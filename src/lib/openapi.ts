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

/**
 * Feeds that are exposed as synchronous POST request-response oracles (carry a
 * JSON request body), not GET broadcast pulls. Must stay in sync with
 * POST_ORACLES in index.ts — drift here causes method/param mismatch between
 * the OpenAPI contract and the live routes. usc-statute is dual-pattern: it is
 * a publisher-backed feed AND a POST oracle, so it gets BOTH a GET (latest
 * broadcast) and a POST (synchronous query) operation below.
 */
const POST_ORACLE_IDS = new Set(["fact-oracle", "evidence-pack", "usc-statute"]);

/** Per-oracle request-body schema, keyed by feed id. Each oracle takes a
 *  different question/claim/citation field plus optional on-chain delivery
 *  binding. Used to emit a correct requestBody for every POST operation. */
const ORACLE_REQUEST_SCHEMAS: Record<string, object> = {
  "fact-oracle": {
    type: "object",
    properties: {
      question: {
        type: "string",
        minLength: 1,
        description: "The factual question to answer in plain language, e.g. \"Who won the 2024 Super Bowl?\".",
      },
      subscriber_address: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description:
          "The Arbitrum (eip155:421614) address the on-chain answer is broadcast to. Must be subscribed to the fact-oracle publisher and hold USDC escrow to receive the signed answer broadcast.",
      },
      max_byte_cost: {
        type: "integer",
        minimum: 1,
        description: "Optional cap on the answer payload size in bytes (default 2000). Caps the per-byte settlement cost of the on-chain answer.",
      },
    },
    required: ["question", "subscriber_address"],
  },
  "evidence-pack": {
    type: "object",
    properties: {
      claim: {
        type: "string",
        minLength: 1,
        description: "The claim to fact-check and ground against cited sources, e.g. \"USDC is fully reserved 1:1\".",
      },
      domains: {
        type: "array",
        items: { type: "string" },
        description: "Optional allowlist of source domains to retrieve evidence from (e.g. [\"sec.gov\", \"circle.com\"]). Omit to search all indexed BYTE Library factual feeds.",
      },
      max_sources: {
        type: "integer",
        minimum: 1,
        description: "Optional cap on the number of cited sources in the returned evidence pack. Price is $0.05 base + $0.005 per source, so this also caps cost.",
      },
      subscriber_address: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "Optional. The Arbitrum address bound to the signed EIP-712 request, so a leaked query cannot burn another wallet's escrow.",
      },
    },
    required: ["claim"],
  },
  "usc-statute": {
    type: "object",
    properties: {
      citation: {
        type: "string",
        minLength: 1,
        description: "The US Code citation to resolve, e.g. \"17 USC 107\" or \"26 U.S.C. § 501(c)(3)\". Returns the current public-domain statute text with a content hash and source URLs.",
      },
      subscriber_address: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "Optional. The Arbitrum address bound to the signed EIP-712 request so a leaked query cannot burn another wallet's escrow.",
      },
    },
    required: ["citation"],
  },
};

/** Per-feed x-payment-info block — price varies by expected payload size. */
function paymentInfo(priceAtomic: string) {
  return {
    price: {
      mode: "fixed",
      currency: "USD",
      amount: (Number(priceAtomic) / 1_000_000).toFixed(6),
    },
    protocols: [{ x402: {} }],
  };
}

/** Responses block for a paid operation. The 402 description embeds the price. */
function paidResponses(okSchema: object, priceAtomic: string) {
  const usd = (Number(priceAtomic) / 1_000_000).toFixed(6);
  return {
    "200": {
      description: "Successful response",
      content: { "application/json": { schema: okSchema } },
    },
    "402": {
      description:
        `Payment Required — pay the x402 challenge in the payment-required ` +
        `header (x402 v2) and retry. $${usd} USDC on Arbitrum Sepolia.`,
    },
    "502": { description: "Upstream data source unavailable" },
  };
}

/** Lookup a feed by id, throwing if missing — keeps the bespoke paths honest. */
function feed(id: string) {
  const f = feedRegistry.find((x) => x.id === id);
  if (!f) throw new Error(`feedRegistry missing entry for ${id}`);
  return f;
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

/** Generic signed-verdict response schema for the oracle POST operations. The
 *  gateway returns a request ACK; the answer/verdict is broadcast on-chain to
 *  the subscriber address. Mirrors fact-oracle's ack shape across all oracles. */
const oracleAckSchema = {
  type: "object",
  properties: {
    request_id: { type: "string", description: "Tracking id for this query." },
    est_eta_ms: {
      type: "integer",
      description: "Estimated milliseconds until the on-chain answer broadcast lands.",
    },
    publisher: {
      type: "string",
      description: "On-chain address of the publisher answering the query.",
    },
  },
  required: ["request_id", "publisher"],
};

/** Build the POST operation for a request-response oracle feed. */
function oraclePostOperation(f: { id: string; name: string; price: string; description: string; priceAtomic: string }) {
  const reqSchema = ORACLE_REQUEST_SCHEMAS[f.id];
  return {
    operationId: `post${pascal(f.id)}`,
    summary: `${f.name} — synchronous query, answer delivered on-chain (${f.price} per query ACK)`,
    description: f.description,
    tags: ["Feeds"],
    security: [{ x402Payment: [] }],
    "x-payment-info": paymentInfo(f.priceAtomic),
    requestBody: {
      required: true,
      content: { "application/json": { schema: reqSchema } },
    },
    responses: paidResponses(oracleAckSchema, f.priceAtomic),
  };
}

/**
 * Build OpenAPI path entries for every BYTE Library publisher-backed feed.
 *
 * Publisher feeds serve their latest broadcast via GET. A feed that is ALSO a
 * POST oracle (usc-statute) is dual-pattern: it gets the GET broadcast path AND
 * a POST synchronous-query path on the same endpoint — matching the live
 * routes in index.ts. Without the POST half, the OpenAPI contract drifts from
 * the manifest/agent.json (which advertise these as POST).
 */
function indexerFeedPaths(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const f of feedRegistry) {
    if (!f.publisher) continue;
    paths[f.endpoint] = {
      get: {
        operationId: `get${pascal(f.id)}`,
        summary: `${f.name} — latest BYTE Library broadcast (${f.price} / call, ~${f.expectedSizeBytes}B)`,
        description: f.description,
        tags: ["Feeds"],
        security: [{ x402Payment: [] }],
        parameters: [],
        "x-payment-info": paymentInfo(f.priceAtomic),
        responses: paidResponses(byteLibraryFeedSchema, f.priceAtomic),
      },
    };
    // Dual-pattern feeds (usc-statute): add the synchronous POST oracle path.
    if (POST_ORACLE_IDS.has(f.id)) {
      paths[f.endpoint].post = oraclePostOperation(f);
    }
  }
  return paths;
}

/** Build OpenAPI path entries for POST oracles that are NOT publisher-backed
 *  (evidence-pack — bespoke, custom-priced, no GET broadcast). Without this
 *  these endpoints were missing from the contract entirely. */
function bespokeOraclePaths(): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const f of feedRegistry) {
    if (f.publisher) continue;            // publisher oracles handled above
    if (!POST_ORACLE_IDS.has(f.id)) continue;
    if (f.id === "fact-oracle") continue; // fact-oracle is declared explicitly below
    paths[f.endpoint] = { post: oraclePostOperation(f) };
  }
  return paths;
}

export function buildOpenApiDoc() {
  const crypto = feed("crypto-top100");
  const defi = feed("defi-yields");
  const oracle = feed("fact-oracle");

  return {
    openapi: "3.1.0",
    info: {
      title: "BYTE Library x402 Gateway",
      version: "0.3.0",
      description:
        "Verified, provenance-first data feeds for AI agents. Every payload " +
        "is cryptographically signed and EIP-712 PayloadAttestation " +
        "provenance-stamped — covering crypto markets, DeFi yields, weather, " +
        "earthquakes, news, code-pulse, threat-intel, and a slashable " +
        "fact-oracle. Pay per call in USDC over x402 with no API keys — a " +
        "wallet, not a secret on the box. Settlement is on Arbitrum Sepolia " +
        "testnet (eip155:421614). Price is per-feed, derived from expected " +
        "payload size at " +
        `$${(Number(config.pricePerKBAtomic) / 1_000_000).toFixed(6)}/KB ` +
        `(floor $${(Number(config.priceFloorAtomic) / 1_000_000).toFixed(6)}).`,
      "x-guidance":
        "Paid endpoints return HTTP 402 with x402 v2 payment requirements " +
        "in the `payment-required` header — pay the quoted USDC on Arbitrum " +
        "Sepolia (network eip155:421614) and retry. Each feed has its own " +
        "price (see x-payment-info per operation); the catalog at GET /feeds " +
        "(free, ungated) lists every feed with its computed price and " +
        "expected payload size. POST /feeds/fact-oracle needs a JSON body: " +
        "`question` (string) and `subscriber_address` (0x… address " +
        "subscribed to the fact-oracle with USDC escrow). The answer is " +
        "broadcast on-chain via DataStream to that address. Free, no " +
        "payment: GET /feeds and GET /health.",
    },
    servers: [{ url: "https://x402.payperbyte.io" }],
    // x402 payment is the auth scheme for every paid operation. Declared as an
    // OpenAPI http "bearer" scheme whose bearer is the x402 settlement receipt:
    // an unpaid request returns 402 with the payment challenge in the
    // `payment-required` header (x402 v2), the client pays the quoted USDC over
    // x402, and retries with the receipt. `x-payment-info` per operation carries
    // the machine-readable price; this securityScheme documents the flow as a
    // first-class auth mechanism so agent toolchains that key off
    // components.securitySchemes (rather than the custom x-payment-info) can
    // still recognize the endpoints as authenticated-by-payment.
    security: [{ x402Payment: [] }],
    paths: {
      "/feeds/crypto-top100": {
        get: {
          operationId: "getCryptoTop100",
          summary: `Top 25 cryptocurrencies — price, market cap, 24h change (${crypto.price})`,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          parameters: [],
          "x-payment-info": paymentInfo(crypto.priceAtomic),
          responses: paidResponses(cryptoTop100Schema, crypto.priceAtomic),
        },
      },
      "/feeds/defi-yields": {
        get: {
          operationId: "getDefiYields",
          summary: `Top DeFi yield pools across major chains (${defi.price})`,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          parameters: [],
          "x-payment-info": paymentInfo(defi.priceAtomic),
          responses: paidResponses(defiYieldsSchema, defi.priceAtomic),
        },
      },
      "/feeds/fact-oracle": {
        post: {
          operationId: "postFactOracle",
          summary: `Slashable factual Q&A — answer delivered on-chain (${oracle.price} per query ACK)`,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(oracle.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: factQueryRequestSchema },
            },
          },
          responses: paidResponses(factQueryResponseSchema, oracle.priceAtomic),
        },
      },
      ...bespokeOraclePaths(),
      ...indexerFeedPaths(),
      // NOTE: the free operational endpoints (GET /feeds catalog, GET /health)
      // are intentionally NOT listed here. This document is consumed by
      // x402scan as a catalog of *payable* resources — a free endpoint fails
      // its 402 probe and registers as an error. The free endpoints still
      // exist on the server; agents learn about them from info.x-guidance.
    },
    components: {
      securitySchemes: {
        x402Payment: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "x402-settlement-receipt",
          description:
            "x402 pay-per-call. An unpaid request returns HTTP 402 with the " +
            "payment challenge in the `payment-required` header (x402 v2). Pay " +
            "the quoted USDC on Arbitrum Sepolia (network eip155:421614) via an " +
            "x402 client, then retry with the settlement receipt. No API key — " +
            "a wallet signs an EIP-3009 `transferWithAuthorization` and the " +
            "facilitator settles on-chain. See the per-operation `x-payment-info` " +
            "for the exact price.",
        },
      },
      schemas: {
        CryptoTop100Response: cryptoTop100Schema,
        DefiYieldsResponse: defiYieldsSchema,
        FactQueryRequest: factQueryRequestSchema,
        FactQueryResponse: factQueryResponseSchema,
        ByteLibraryFeedResponse: byteLibraryFeedSchema,
        OracleAck: oracleAckSchema,
      },
    },
  };
}
