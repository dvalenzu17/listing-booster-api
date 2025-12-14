import "dotenv/config";
import express from "express";
import OpenAI from "openai";
import { z } from "zod";
import { zodTextFormat } from "openai/helpers/zod";

const app = express();
app.use(express.json({ limit: "1mb" }));


app.use((req, res, next) => {
    // If you’re testing locally, leave RAPIDAPI_PROXY_SECRET empty.
    const expected = process.env.RAPIDAPI_PROXY_SECRET;
    if (!expected) return next();
  
    const got = req.header("X-RapidAPI-Proxy-Secret");
    if (got !== expected) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }
    return next();
  });
  

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---- Input validation (your API contract)
const ListingInput = z.object({
  platform: z.enum(["amazon", "etsy", "shopify", "ebay"]).default("shopify"),
  product_name: z.string().min(3).max(120),
  features: z.array(z.string().min(2).max(200)).min(2).max(12),
  audience: z.string().max(120).optional(),
  tone: z.enum(["premium", "playful", "minimal", "bold", "luxury"]).default("premium"),
  price_point: z.enum(["budget", "mid", "premium"]).optional(),
  language: z.string().default("en"),
});

// ---- Output schema (what the model MUST return)
const ListingOutput = z.object({
  platform: z.string(),
  title: z.string().min(10).max(200),
  bullets: z.array(z.string().min(10).max(250)).min(5).max(5),
  description: z.string().min(50).max(2000),
  keywords: z.array(z.string().min(2).max(40)).min(8).max(30),
  ad_variations: z.array(
    z.object({
      headline: z.string().min(5).max(80),
      primary_text: z.string().min(20).max(200),
      cta: z.enum(["Shop now", "Learn more", "Buy now", "Get yours", "See details"]),
    })
  ).min(3).max(3),
  compliance_notes: z.array(z.string().min(5).max(200)).max(8).default([]),
});

// Health check (marketplace listings love this)
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/generate-listing", async (req, res) => {
  try {
    const input = ListingInput.parse(req.body);

    const system = [
      "You are an elite ecommerce conversion copywriter.",
      "Write high-converting copy that is clear, specific, and skimmable.",
      "No unverifiable claims (e.g., 'best', 'guaranteed', medical claims).",
      "Avoid prohibited/unsafe claims. If info is missing, stay generic rather than inventing details.",
      "Match the platform style and the requested tone.",
      "Return ONLY the structured JSON output matching the provided schema."
    ].join(" ");

    const userPayload = {
      ...input,
      // small nudge: enforce bullets count expectations per common marketplace patterns
      requirements: {
        bullets_count: 5,
        ad_variations_count: 3
      }
    };

    // Using the SDK's structured output parsing with Zod :contentReference[oaicite:3]{index=3}
    const response = await client.responses.parse({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini-2024-07-18",
      input: [
        { role: "system", content: system },
        { role: "user", content: JSON.stringify(userPayload) }
      ],
      text: { format: zodTextFormat(ListingOutput, "listing_output") },
      // Keep it tight so you don’t torch margin
      max_output_tokens: 700,
    });

    return res.json({
      ok: true,
      data: response.output_parsed,
      // If you want cost tracking later, inspect response for usage fields in your logs.
    });
  } catch (err) {
    // Zod validation errors + OpenAI errors, all in one place
    const message = err?.message || "Unknown error";
    return res.status(400).json({ ok: false, error: message });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`✅ Listing Booster API running on :${port}`));
