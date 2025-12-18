import "dotenv/config";
import express from "express";
import cors from "cors";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import dns from "node:dns/promises";
import ipaddr from "ipaddr.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

/**
 * -------------------------
 * Config
 * -------------------------
 * Auth precedence:
 * 1) If BLOCKED behind RapidAPI proxy => set RAPIDAPI_PROXY_SECRET and require header X-RapidAPI-Proxy-Secret
 * 2) Otherwise, if you want direct auth => set ACCESS_SCANNER_API_KEY and require Authorization: Bearer <key>
 * 3) Otherwise => open (local dev)
 *
 * SSRF/DNS checks:
 * - BLOCK_PRIVATE_NETS=true blocks localhost/private IP targets (recommended)
 * - SKIP_DNS_CHECK=true skips dns.lookup safety check (ONLY for dev environments with weird DNS)
 */
const PRIVATE_NETS_ENABLED = (process.env.BLOCK_PRIVATE_NETS ?? "true").toLowerCase() !== "false";
const SKIP_DNS_CHECK = (process.env.SKIP_DNS_CHECK ?? "false").toLowerCase() === "true";
const HEADLESS = (process.env.PLAYWRIGHT_HEADLESS ?? "true").toLowerCase() !== "false";

/**
 * -------------------------
 * Lightweight request logging
 * -------------------------
 */
app.use((req, res, next) => {
  const started = Date.now();
  const rapidUser = req.header("X-RapidAPI-User") || "direct";
  const rapidKey = req.header("X-RapidAPI-Key");
  const rapidHost = req.header("X-RapidAPI-Host");
  const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.socket.remoteAddress;

  res.on("finish", () => {
    const ms = Date.now() - started;
    const keyTail = rapidKey ? rapidKey.slice(-6) : "none";

    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        ms,
        user: rapidUser,
        key_tail: keyTail,
        host: rapidHost || "none",
        ip,
      })
    );
  });

  next();
});

/**
 * -------------------------
 * Auth middleware
 * -------------------------
 */
app.use((req, res, next) => {
  const rapidExpected = process.env.RAPIDAPI_PROXY_SECRET;

  if (rapidExpected) {
    const got = req.header("X-RapidAPI-Proxy-Secret");
    if (got !== rapidExpected) return res.status(401).json({ ok: false, error: "Unauthorized" });
    return next();
  }

  const directKey = process.env.ACCESS_SCANNER_API_KEY;
  if (directKey) {
    const auth = req.header("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (token !== directKey) return res.status(401).json({ ok: false, error: "Unauthorized" });
    return next();
  }

  return next();
});

/**
 * -------------------------
 * In-memory report store (MVP)
 * -------------------------
 * Swap to Redis/DB later.
 */
const reports = new Map(); // id -> { status, input, startedAt, finishedAt, result, error }

/**
 * -------------------------
 * SSRF guard helpers
 * -------------------------
 */
function isPrivateIp(ip) {
  try {
    const addr = ipaddr.parse(ip);
    if (addr.kind() === "ipv4") {
      const r = addr.range();
      return ["private", "loopback", "linkLocal", "carrierGradeNat", "reserved"].includes(r);
    }
    if (addr.kind() === "ipv6") {
      const r = addr.range();
      return ["uniqueLocal", "loopback", "linkLocal", "reserved"].includes(r);
    }
    return false;
  } catch {
    return true; // if unsure, treat as unsafe
  }
}

async function assertSafeUrl(rawUrl) {
  const url = new URL(rawUrl);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only http/https URLs are allowed");
  }

  const host = url.hostname.toLowerCase();

  if (PRIVATE_NETS_ENABLED) {
    if (host === "localhost" || host.endsWith(".localhost")) throw new Error("Blocked host");
    if (host === "0.0.0.0" || host === "::1") throw new Error("Blocked host");
  }

  if (!PRIVATE_NETS_ENABLED || SKIP_DNS_CHECK) return;

  // DNS resolve and block private ranges
  const lookups = await dns.lookup(host, { all: true, verbatim: true });
  for (const { address } of lookups) {
    if (isPrivateIp(address)) throw new Error("Blocked private network target");
  }
}

/**
 * -------------------------
 * Scan input schema
 * -------------------------
 */
const ScanInput = z.object({
  url: z.string().url(),
  maxPages: z.number().int().min(1).max(25).default(5),
  maxDepth: z.number().int().min(0).max(3).default(1),
  waitUntil: z.enum(["load", "domcontentloaded", "networkidle"]).default("domcontentloaded"),
  timeoutMs: z.number().int().min(5000).max(60000).default(30000),
  includeScreenshots: z.boolean().default(false),
  tags: z.array(z.string()).optional(), // override rule tags
});

const ScanSyncInput = ScanInput.extend({
  maxPages: z.number().int().min(1).max(1).default(1),
  maxDepth: z.number().int().min(0).max(0).default(0),
});

function normalizeUrl(u) {
  const url = new URL(u);
  url.hash = "";
  return url.toString();
}

async function extractLinks(page, baseUrl) {
  const hrefs = await page.$$eval("a[href]", (as) => as.map((a) => a.getAttribute("href")).filter(Boolean));
  const out = [];
  for (const h of hrefs) {
    try {
      const abs = new URL(h, baseUrl).toString();
      out.push(abs);
    } catch {
      // ignore invalid
    }
  }
  return out;
}

function summarizeViolations(violations) {
  const impactCounts = { minor: 0, moderate: 0, serious: 0, critical: 0, unknown: 0 };
  for (const v of violations) {
    const impact = v.impact || "unknown";
    if (impactCounts[impact] === undefined) impactCounts.unknown += 1;
    else impactCounts[impact] += 1;
  }
  return {
    total_violations: violations.length,
    by_impact: impactCounts,
  };
}

/**
 * -------------------------
 * Action items + export helpers
 * -------------------------
 */
function impactRank(impact) {
  switch (impact) {
    case "critical": return 4;
    case "serious": return 3;
    case "moderate": return 2;
    case "minor": return 1;
    default: return 0;
  }
}

function impactToPriority(impact) {
  if (impact === "critical") return "P0";
  if (impact === "serious") return "P1";
  if (impact === "moderate") return "P2";
  if (impact === "minor") return "P3";
  return "P4";
}

function buildActionItems(pages) {
  const map = new Map();

  for (const p of pages) {
    for (const v of (p.violations || [])) {
      const key = v.id;
      const existing = map.get(key);

      const nodeCount = (v.nodes || []).length;
      const bestImpact = existing
        ? (impactRank(v.impact) > impactRank(existing.impact) ? v.impact : existing.impact)
        : v.impact;

      map.set(key, {
        id: key,
        impact: bestImpact,
        priority: impactToPriority(bestImpact),
        help: v.help,
        helpUrl: v.helpUrl,
        description: v.description,
        tags: v.tags || [],
        affected_nodes: (existing?.affected_nodes || 0) + nodeCount,
        affected_pages: new Set([...(existing?.affected_pages || []), p.url]),
      });
    }
  }

  const items = [...map.values()].map((x) => ({
    ...x,
    affected_pages: [...x.affected_pages],
  }));

  items.sort((a, b) => {
    const d = impactRank(b.impact) - impactRank(a.impact);
    if (d !== 0) return d;
    return (b.affected_nodes || 0) - (a.affected_nodes || 0);
  });

  return items;
}

function csvEscape(val) {
  const s = String(val ?? "");
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function reportToCSV(report) {
  const pages = report?.result?.pages || [];
  const header = [
    "page_url",
    "final_url",
    "page_title",
    "violation_id",
    "impact",
    "help",
    "help_url",
    "target",
    "failure_summary",
    "html_snippet",
  ].join(",");

  const rows = [header];

  for (const p of pages) {
    for (const v of (p.violations || [])) {
      for (const n of (v.nodes || [])) {
        rows.push([
          csvEscape(p.url),
          csvEscape(p.finalUrl || p.url),
          csvEscape(p.title || ""),
          csvEscape(v.id),
          csvEscape(v.impact),
          csvEscape(v.help),
          csvEscape(v.helpUrl),
          csvEscape((n.target || []).join(" | ")),
          csvEscape(n.failureSummary || ""),
          csvEscape(n.html || ""),
        ].join(","));
      }
    }
  }

  return rows.join("\n");
}

function reportToHTML(report) {
  const status = report?.status;
  const input = report?.input || {};
  const res = report?.result || null;

  const summary = res?.summary || { total_violations: 0, by_impact: {} };
  const pages = res?.pages || [];
  const actions = res?.action_items || [];

  const esc = (s) => String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const badge = (t) => `<span class="badge">${esc(t)}</span>`;

  const actionsHtml = actions.length
    ? actions.map((a) => `
      <tr>
        <td>${badge(a.priority)}</td>
        <td>${badge(a.impact)}</td>
        <td><code>${esc(a.id)}</code></td>
        <td>${esc(a.help || a.description || "")}</td>
        <td>${esc(a.affected_nodes)}</td>
        <td>${(a.affected_pages || []).map((u) => `<div><a href="${esc(u)}">${esc(u)}</a></div>`).join("")}</td>
        <td>${a.helpUrl ? `<a href="${esc(a.helpUrl)}">${esc(a.helpUrl)}</a>` : ""}</td>
      </tr>
    `).join("")
    : `<tr><td colspan="7">No action items 🎉</td></tr>`;

  const pagesHtml = pages.map((p) => {
    const vio = p.violations || [];
    const shot = p.screenshotBase64
      ? `<details><summary>Screenshot</summary><img class="shot" src="data:image/png;base64,${p.screenshotBase64}" /></details>`
      : "";

    const vioHtml = vio.length
      ? vio.map((v) => `
        <div class="card">
          <div class="card-h">
            ${badge(v.impact)} <code>${esc(v.id)}</code> — ${esc(v.help || "")}
          </div>
          <div class="muted">${esc(v.description || "")}</div>
          ${v.helpUrl ? `<div class="muted"><a href="${esc(v.helpUrl)}">${esc(v.helpUrl)}</a></div>` : ""}
          <div class="nodes">
            ${(v.nodes || []).slice(0, 25).map((n) => `
              <div class="node">
                <div class="muted"><b>Target:</b> ${(n.target || []).map((t) => `<code>${esc(t)}</code>`).join(" ")}</div>
                ${n.failureSummary ? `<div class="muted"><b>Why:</b> ${esc(n.failureSummary)}</div>` : ""}
                <pre>${esc(n.html || "")}</pre>
              </div>
            `).join("")}
          </div>
        </div>
      `).join("")
      : `<div class="muted">No violations found on this page.</div>`;

    return `
      <section class="page">
        <h3>${esc(p.title || "(no title)")} ${badge("html " + (p.htmlSize ?? "?"))}</h3>
        <div class="muted"><b>Requested:</b> <a href="${esc(p.url)}">${esc(p.url)}</a></div>
        <div class="muted"><b>Final:</b> <a href="${esc(p.finalUrl || p.url)}">${esc(p.finalUrl || p.url)}</a></div>
        ${shot}
        ${vioHtml}
      </section>
    `;
  }).join("");

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Accessibility Report</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; color: #111; }
    h1,h2,h3 { margin: 0 0 10px 0; }
    .muted { color: #555; margin: 6px 0; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; margin: 12px 0 18px; }
    .box { border: 1px solid #ddd; border-radius: 12px; padding: 12px 14px; min-width: 220px; }
    .badge { display: inline-block; border: 1px solid #ddd; border-radius: 999px; padding: 2px 10px; font-size: 12px; margin-right: 6px; }
    .card { border: 1px solid #e5e5e5; border-radius: 14px; padding: 12px 14px; margin: 10px 0; }
    .card-h { font-weight: 650; margin-bottom: 6px; }
    .node { border-top: 1px dashed #ddd; padding-top: 10px; margin-top: 10px; }
    pre { background: #f7f7f7; border-radius: 10px; padding: 10px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th,td { border-bottom: 1px solid #eee; text-align: left; padding: 10px 8px; vertical-align: top; }
    .page { margin: 22px 0; }
    .shot { max-width: 100%; border: 1px solid #ddd; border-radius: 12px; margin-top: 10px; }
    a { color: #0b57d0; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>Accessibility Report</h1>
  <div class="muted"><b>Status:</b> ${esc(status)}</div>
  <div class="muted"><b>Target:</b> <a href="${esc(input.url || "")}">${esc(input.url || "")}</a></div>

  <div class="row">
    <div class="box"><div class="muted">Total violations</div><div style="font-size:28px;font-weight:700">${esc(summary.total_violations)}</div></div>
    <div class="box"><div class="muted">Critical</div><div style="font-size:22px;font-weight:650">${esc(summary.by_impact?.critical ?? 0)}</div></div>
    <div class="box"><div class="muted">Serious</div><div style="font-size:22px;font-weight:650">${esc(summary.by_impact?.serious ?? 0)}</div></div>
    <div class="box"><div class="muted">Moderate</div><div style="font-size:22px;font-weight:650">${esc(summary.by_impact?.moderate ?? 0)}</div></div>
    <div class="box"><div class="muted">Minor</div><div style="font-size:22px;font-weight:650">${esc(summary.by_impact?.minor ?? 0)}</div></div>
  </div>

  <h2>Action Items</h2>
  <div class="muted">This is the “what to fix first” list agencies actually want.</div>
  <table>
    <thead>
      <tr>
        <th>Priority</th>
        <th>Impact</th>
        <th>Rule</th>
        <th>Issue</th>
        <th>Affected</th>
        <th>Pages</th>
        <th>Reference</th>
      </tr>
    </thead>
    <tbody>${actionsHtml}</tbody>
  </table>

  <h2>Pages</h2>
  ${pagesHtml}
</body>
</html>`;
}

/**
 * -------------------------
 * Core scan logic
 * -------------------------
 */
async function scanOnePage({ page, url, waitUntil, timeoutMs, tags, includeScreenshots }) {
  const startedAt = new Date().toISOString();
  await page.goto(url, { waitUntil, timeout: timeoutMs });

  const finalUrl = page.url();
  const title = await page.title().catch(() => "");
  const htmlSize = (await page.content()).length;

  const axe = new AxeBuilder({ page });

  // Default rule coverage (good MVP + “best-practice” makes results more valuable)
  const defaultTags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"];
  const wcagTags = tags?.length ? tags : defaultTags;

  const results = await axe.withTags(wcagTags).analyze();

  let screenshotBase64 = null;
  if (includeScreenshots) {
    const buf = await page.screenshot({ fullPage: true, type: "png" });
    screenshotBase64 = buf.toString("base64");
  }

  const finishedAt = new Date().toISOString();

  return {
    url,
    finalUrl,
    title,
    htmlSize,
    startedAt,
    finishedAt,
    passes: results.passes?.length ?? 0,
    inapplicable: results.inapplicable?.length ?? 0,
    incomplete: results.incomplete?.length ?? 0,
    violations: (results.violations || []).map((v) => ({
      id: v.id,
      impact: v.impact || "unknown",
      description: v.description,
      help: v.help,
      helpUrl: v.helpUrl,
      tags: v.tags,
      nodes: (v.nodes || []).slice(0, 25).map((n) => ({
        target: n.target,
        html: n.html,
        failureSummary: n.failureSummary,
      })),
    })),
    screenshotBase64,
  };
}

function friendlyErrorMessage(msg) {
  if (!msg) return "Unknown error";
  if (msg.includes("ENOTFOUND")) return "DNS lookup failed for the target host (check your DNS/network settings).";
  if (msg.includes("timeout")) return "Timed out while loading the page. Try increasing timeoutMs.";
  if (msg.includes("Blocked")) return msg;
  return msg;
}

async function runScan(reportId, input) {
  const startedAt = new Date().toISOString();
  reports.set(reportId, { status: "running", input, startedAt, finishedAt: null, result: null, error: null });

  try {
    await assertSafeUrl(input.url);

    const browser = await chromium.launch({ headless: HEADLESS });
    const context = await browser.newContext({
      userAgent: "AccessibilityScannerBot/1.0",
      viewport: { width: 1280, height: 720 },
    });

    const base = normalizeUrl(input.url);
    const origin = new URL(base).origin;

    const queue = [{ url: base, depth: 0 }];
    const visited = new Set([base]);
    const pages = [];

    while (queue.length && pages.length < input.maxPages) {
      const { url, depth } = queue.shift();

      // Scan the page
      const page = await context.newPage();
      page.setDefaultTimeout(input.timeoutMs);

      let pageResult;
      try {
        pageResult = await scanOnePage({
          page,
          url,
          waitUntil: input.waitUntil,
          timeoutMs: input.timeoutMs,
          tags: input.tags,
          includeScreenshots: input.includeScreenshots,
        });
      } finally {
        await page.close().catch(() => {});
      }

      pages.push(pageResult);

      // Crawl links if needed (same-origin only)
      if (depth < input.maxDepth) {
        const linkPage = await context.newPage();
        linkPage.setDefaultTimeout(input.timeoutMs);

        try {
          await linkPage.goto(url, { waitUntil: "domcontentloaded", timeout: input.timeoutMs });
          const links = await extractLinks(linkPage, url);

          for (const l of links) {
            const norm = normalizeUrl(l);
            if (!norm.startsWith(origin)) continue;
            if (visited.has(norm)) continue;

            visited.add(norm);
            queue.push({ url: norm, depth: depth + 1 });
          }
        } catch {
          // ignore link extraction failures
        } finally {
          await linkPage.close().catch(() => {});
        }
      }
    }

    await context.close().catch(() => {});
    await browser.close().catch(() => {});

    const allViolations = pages.flatMap((p) => p.violations || []);
    const summary = summarizeViolations(allViolations);
    const action_items = buildActionItems(pages);

    const finishedAt = new Date().toISOString();
    reports.set(reportId, {
      status: "complete",
      input,
      startedAt,
      finishedAt,
      error: null,
      result: {
        origin,
        pages_scanned: pages.length,
        summary,
        action_items,
        pages,
      },
    });
  } catch (err) {
    const finishedAt = new Date().toISOString();
    const msg = friendlyErrorMessage(err?.message || "Unknown error");

    reports.set(reportId, {
      status: "failed",
      input,
      startedAt,
      finishedAt,
      result: null,
      error: msg,
    });
  }
}

/**
 * -------------------------
 * Routes
 * -------------------------
 */
app.get("/health", (req, res) => res.json({ ok: true }));

// Async scan (returns 202 + report id)
app.post("/scan", async (req, res) => {
  const parsed = ScanInput.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: "Invalid input", details: parsed.error.flatten() });
  }

  const reportId = uuidv4();
  reports.set(reportId, {
    status: "queued",
    input: parsed.data,
    startedAt: null,
    finishedAt: null,
    result: null,
    error: null,
  });

  // fire-and-forget (safe)
  runScan(reportId, parsed.data).catch(() => {});

  return res.status(202).json({
    ok: true,
    report_id: reportId,
    status: "queued",
    status_url: `/report/${reportId}`,
  });
});

// Sync scan (hard-capped: 1 page, depth 0)
app.post("/scan/sync", async (req, res) => {
  const parsed = ScanSyncInput.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ ok: false, error: "Invalid input", details: parsed.error.flatten() });
  }

  const reportId = uuidv4();
  await runScan(reportId, parsed.data);

  const report = reports.get(reportId);
  return res.json({ ok: true, report_id: reportId, ...report });
});

// Get report status/results
app.get("/report/:id", (req, res) => {
  const id = req.params.id;
  const report = reports.get(id);
  if (!report) return res.status(404).json({ ok: false, error: "Report not found" });
  return res.json({ ok: true, report_id: id, ...report });
});

// Export completed report: html | csv | json
app.get("/export/:id", (req, res) => {
  const id = req.params.id;
  const format = String(req.query.format || "html").toLowerCase();

  const report = reports.get(id);
  if (!report) return res.status(404).json({ ok: false, error: "Report not found" });
  if (report.status !== "complete") {
    return res.status(409).json({ ok: false, error: "Report not complete", status: report.status });
  }

  if (format === "json") {
    return res.json({ ok: true, report_id: id, ...report });
  }

  if (format === "csv") {
    const csv = reportToCSV({ status: report.status, input: report.input, result: report.result });
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="a11y-report-${id}.csv"`);
    return res.send(csv);
  }

  // default html
  const html = reportToHTML({ status: report.status, input: report.input, result: report.result });
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Disposition", `inline; filename="a11y-report-${id}.html"`);
  return res.send(html);
});

/**
 * -------------------------
 * Boot
 * -------------------------
 */
const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Accessibility Scanner API listening on :${port}`);
});
