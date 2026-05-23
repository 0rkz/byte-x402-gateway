/**
 * OpenAPI 3.1 document for the Byte Protocol x402 gateway.
 *
 * Served at GET /openapi.json — this is the canonical machine-readable
 * discovery contract that x402scan (and other agent discovery layers) read.
 * Discovery precedence: this document first, runtime 402 behavior second.
 *
 * Lists only the four *payable* resources. Free operational endpoints
 * (/feeds catalog, /health) are deliberately omitted — x402scan treats
 * every path here as a payable resource, so a free one fails its 402
 * probe and registers as an error.
 *
 * Every paid operation declares both halves of the contract x402scan checks:
 *   - x-payment-info  — price (fixed $/request) + protocols ([{ x402 }])
 *   - responses.402   — the runtime payment challenge
 *   - input + output schemas — so an agent knows what to send and what it
 *     gets back.
 *
 * buildOpenApiDoc() reads `config` so price/network stay in sync with the
 * running gateway — never hard-code the amount here.
 */
import { config, feedRegistry } from "./config.js";

/** Shared x-payment-info block — fixed price, x402 protocol. */
function paymentInfo() {
  return {
    price: {
      mode: "fixed",
      currency: "USD",
      // requestAmountAtomic is 6-decimal USDC base units ("1000" = $0.001).
      amount: (Number(config.requestAmountAtomic) / 1_000_000).toFixed(6),
    },
    protocols: [{ x402: {} }],
  };
}

/** Standard responses block for a paid operation, given its 200 schema. */
function paidResponses(okSchema: object) {
  return {
    "200": {
      description: "Successful response",
      content: { "application/json": { schema: okSchema } },
    },
    "402": {
      description:
        "Payment Required — pay the x402 challenge in the payment-required " +
        "header (x402 v2) and retry. $0.001 USDC on Arbitrum Sepolia.",
    },
    "502": { description: "Upstream data source unavailable" },
  };
}

// ─── Output schemas ──────────────────────────────────────────────────────────

const cryptoTop100Schema = {
  type: "object",
  properties: {
    feed: { type: "string" },
    timestamp: { type: "string", format: "date-time" },
    count: { type: "integer" },
    data: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          symbol: { type: "string" },
          name: { type: "string" },
          current_price: { type: "number" },
          market_cap: { type: "number" },
          market_cap_rank: { type: "integer" },
          total_volume: { type: "number" },
          price_change_percentage_24h: { type: "number" },
          last_updated: { type: "string", format: "date-time" },
        },
        required: ["id", "symbol", "name", "current_price"],
      },
    },
  },
  required: ["feed", "timestamp", "count", "data"],
};

const defiYieldsSchema = {
  type: "object",
  properties: {
    feed: { type: "string" },
    timestamp: { type: "string", format: "date-time" },
    count: { type: "integer" },
    data: {
      type: "array",
      items: {
        type: "object",
        properties: {
          chain: { type: "string" },
          project: { type: "string" },
          symbol: { type: "string" },
          apy: { type: "number", description: "Annual percentage yield" },
          tvlUsd: { type: "number", description: "Total value locked, USD" },
        },
        required: ["chain", "project", "symbol", "apy"],
      },
    },
  },
  required: ["feed", "timestamp", "data"],
};

const byteStatusSchema = {
  type: "object",
  properties: {
    feed: { type: "string" },
    timestamp: { type: "string", format: "date-time" },
    publishers: { type: "integer" },
    validators: { type: "integer" },
    messages: { type: "integer" },
    totalStakedPpb: { type: "string" },
  },
  required: ["feed", "timestamp"],
};

const factQueryRequestSchema = {
  type: "object",
  properties: {
    question: {
      type: "string",
      minLength: 1,
      description: "The factual question to answer.",
    },
    subscriber_address: {
      type: "string",
      pattern: "^0x[0-9a-fA-F]{40}$",
      description:
        "The Arbitrum address the on-chain answer is broadcast to. Must be " +
        "subscribed to the fact-oracle publisher and hold USDC escrow.",
    },
    max_byte_cost: {
      type: "integer",
      description: "Optional cap on answer payload size in bytes (default 2000).",
    },
  },
  required: ["question", "subscriber_address"],
};

const factQueryResponseSchema = {
  type: "object",
  properties: {
    request_id: { type: "string", description: "Tracking id for this query." },
    est_eta_ms: {
      type: "integer",
      description: "Estimated ms until the on-chain answer broadcast lands.",
    },
    publisher: {
      type: "string",
      description: "Address of the fact-oracle publisher answering the query.",
    },
  },
  required: ["request_id", "publisher"],
};

// Generic response shape for BYTE Library publisher-backed feeds — the
// `data` field varies per publisher, so it's typed as a free-form object/array.
const byteLibraryFeedSchema = {
  type: "object",
  properties: {
    feed: { type: "string" },
    publisher: { type: "string", description: "Publisher's on-chain address" },
    timestamp: { type: "string", format: "date-time" },
    source: { const: "byte-library-broadcast" },
    txHash: { type: "string", description: "DataStream broadcast tx hash" },
    payloadHash: { type: "string", description: "keccak256 of the broadcast payload" },
    payloadBytes: { type: "integer" },
    data: {
      description: "Publisher-defined payload. Shape varies; see byte-data-feeds repo for per-feed schemas.",
    },
  },
  required: ["feed", "publisher", "timestamp", "source", "data"],
};

// ─── Document ────────────────────────────────────────────────────────────────

/** PascalCase a kebab-case slug for OpenAPI operationIds. e.g. "code-pulse" → "CodePulse". */
function pascal(slug: string): string {
  return slug
    .split("-")
    .map((s) => (s[0] ? s[0].toUpperCase() + s.slice(1) : s))
    .join("");
}

/** Build OpenAPI path entries for every BYTE Library publisher-backed feed. */
function indexerFeedPaths(): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const feed of feedRegistry) {
    if (!feed.publisher) continue;
    paths[feed.endpoint] = {
      get: {
        operationId: `get${pascal(feed.id)}`,
        summary: `${feed.name} — latest BYTE Library broadcast`,
        description: feed.description,
        tags: ["Feeds"],
        parameters: [],
        "x-payment-info": paymentInfo(),
        responses: paidResponses(byteLibraryFeedSchema),
      },
    };
  }
  return paths;
}

export function buildOpenApiDoc() {
  const usdAmount = (Number(config.requestAmountAtomic) / 1_000_000).toFixed(6);

  return {
    openapi: "3.1.0",
    info: {
      title: "Byte Protocol x402 Gateway",
      version: "0.2.0",
      description:
        "Per-byte data feeds for AI agents — crypto markets, DeFi yields, " +
        "Byte Protocol status, and a slashable fact-oracle. Paid per request " +
        "in USDC via x402, no API keys.",
      "x-guidance":
        "Paid endpoints return HTTP 402 with x402 v2 payment requirements in " +
        "the `payment-required` header — pay $" +
        usdAmount +
        " USDC on Arbitrum Sepolia (network eip155:421614) and retry. " +
        "GET feed endpoints (/feeds/crypto-top100, /feeds/defi-yields, " +
        "/feeds/byte-status) take no input. POST /feeds/fact-oracle needs a " +
        "JSON body: `question` (string) and `subscriber_address` (0x… address " +
        "subscribed to the fact-oracle with USDC escrow). The fact-oracle " +
        "answer is delivered on-chain via a DataStream broadcast to that " +
        "address. Free, no payment: GET /feeds (catalog) and GET /health.",
    },
    servers: [{ url: "https://x402.payperbyte.io" }],
    paths: {
      "/feeds/crypto-top100": {
        get: {
          operationId: "getCryptoTop100",
          summary: "Top 25 cryptocurrencies — price, market cap, 24h change",
          tags: ["Feeds"],
          // No-input GET — explicit empty parameter list so discovery
          // tooling reads "nothing to send" rather than "schema forgotten".
          parameters: [],
          "x-payment-info": paymentInfo(),
          responses: paidResponses(cryptoTop100Schema),
        },
      },
      "/feeds/defi-yields": {
        get: {
          operationId: "getDefiYields",
          summary: "Top DeFi yield pools across major chains",
          tags: ["Feeds"],
          parameters: [],
          "x-payment-info": paymentInfo(),
          responses: paidResponses(defiYieldsSchema),
        },
      },
      "/feeds/byte-status": {
        get: {
          operationId: "getByteStatus",
          summary: "Byte Protocol live on-chain status and metrics",
          tags: ["Feeds"],
          parameters: [],
          "x-payment-info": paymentInfo(),
          responses: paidResponses(byteStatusSchema),
        },
      },
      "/feeds/fact-oracle": {
        post: {
          operationId: "postFactOracle",
          summary:
            "Slashable factual Q&A — answer delivered on-chain by a " +
            "reputation-staked fact-oracle publisher",
          tags: ["Feeds"],
          "x-payment-info": paymentInfo(),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: factQueryRequestSchema },
            },
          },
          responses: paidResponses(factQueryResponseSchema),
        },
      },
      ...indexerFeedPaths(),
      // NOTE: the free operational endpoints (GET /feeds catalog, GET /health)
      // are intentionally NOT listed here. This document is consumed by
      // x402scan as a catalog of *payable* resources — a free endpoint fails
      // its 402 probe and registers as an error. The free endpoints still
      // exist on the server; agents learn about them from info.x-guidance.
    },
  };
}
