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
import { config, feedRegistry, networkInfo } from "./config.js";

/**
 * Feeds that are exposed as synchronous POST request-response oracles (carry a
 * JSON request body), not GET broadcast pulls. Must stay in sync with
 * POST_ORACLES in index.ts — drift here causes method/param mismatch between
 * the OpenAPI contract and the live routes. usc-statute is dual-pattern: it is
 * a publisher-backed feed AND a POST oracle, so it gets BOTH a GET (latest
 * broadcast) and a POST (synchronous query) operation below.
 */
// token-safety removed 2026-06-15: delisted, not in feedRegistry, so it never
// appeared in the doc anyway — dropped here to stay in sync with POST_ORACLES
// (index.ts) and avoid advertising a delisted resource if it is ever re-added
// to the registry before its gate.
const POST_ORACLE_IDS = new Set(["evidence-pack", "usc-statute", "address-reputation", "pkg-verdict", "sanctions-screen", "liquidation-stream", "positioning-snapshot", "reasoning-verdict", "runtime-eol", "threat-intel"]);

/** Per-oracle request-body schema, keyed by feed id. Each oracle takes a
 *  different question/claim/citation field plus optional on-chain delivery
 *  binding. Used to emit a correct requestBody for every POST operation. */
export const ORACLE_REQUEST_SCHEMAS: Record<string, Record<string, unknown>> = {
  "reasoning-verdict": {
    type: "object",
    properties: {
      subject: {
        type: "string",
        minLength: 1,
        description:
          "The action/text to judge — the message, payload, proposal, payee, or tool-call the agent is about to act on. Returns a signed ALLOW/WARN/BLOCK/ABSTAIN verdict + a 0-100 safe-to-proceed score + reasons from a LOCAL model (no data egress).",
      },
    },
    required: ["subject"],
  },
  "runtime-eol": {
    type: "object",
    properties: {
      product: {
        type: "string",
        minLength: 1,
        description: 'Runtime/product name (endoflife.date identifier), e.g. "nodejs", "python", "ubuntu".',
      },
      version: {
        type: "string",
        minLength: 1,
        description: 'The version/cycle to judge, e.g. "18" or "3.9". Returns a signed supported-vs-EOL verdict as of now.',
      },
    },
    required: ["product", "version"],
  },
  "threat-intel": {
    type: "object",
    properties: {
      components: {
        type: "array",
        items: { type: "string", minLength: 1 },
        minItems: 1,
        description: 'Product/vendor/package names or CVE ids to screen against the CISA KEV catalog, e.g. ["log4j", "CVE-2021-44228"].',
      },
    },
    required: ["components"],
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
        description: "Optional allowlist of source domains to retrieve evidence from (e.g. [\"sec.gov\", \"circle.com\"]). Omit to search all indexed PayPerByte factual feeds.",
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
  "address-reputation": {
    type: "object",
    properties: {
      domain: {
        type: "string",
        minLength: 1,
        description: "The payee's web domain, e.g. \"github.com\". BLOCK if it doesn't resolve or hits the blocklist.",
      },
      address: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "The receiving address about to be paid. On-chain history + blocklist are checked on the selected chain.",
      },
      amount: {
        type: "integer",
        minimum: 0,
        description: "Optional. The payment amount in atomic units — logged with the query and bound into the verdict context.",
      },
      chain: {
        type: "string",
        enum: ["base", "arbitrum"],
        description: "Chain for the on-chain receiving-address signals (default \"base\" = Base mainnet; \"arbitrum\" = Arbitrum Sepolia testnet).",
      },
    },
    required: ["domain", "address"],
  },
  "pkg-verdict": {
    type: "object",
    properties: {
      ecosystem: {
        type: "string",
        enum: ["npm", "pypi"],
        description: "Package ecosystem.",
      },
      package: {
        type: "string",
        maxLength: 214,
        description: "Package name (npm scoped names like @scope/name allowed; PyPI names are PEP-503-normalized for matching).",
      },
      version: {
        type: "string",
        maxLength: 64,
        description: "Exact version to judge. Omitted => the registry's latest is resolved and pinned into answer.query.version.",
      },
    },
    required: ["ecosystem", "package"],
  },
  "sanctions-screen": {
    type: "object",
    description: "At least one of `address` or `name` is required.",
    properties: {
      address: {
        type: "string",
        description: "Counterparty address: 0x+40-hex (EVM) or a digital-currency address. Checked against the OFAC SDN digital-currency annex.",
      },
      name: {
        type: "string",
        minLength: 2,
        maxLength: 256,
        description: "Counterparty name (individual or entity). Screened exact + conservative fuzzy against primary and a.k.a. names in the SDN + Consolidated lists.",
      },
      chain: {
        type: "string",
        description: "Optional, informational only — the SDN annex pins addresses to currency symbols; chain never gates a hit.",
      },
    },
  },
  "liquidation-stream": {
    type: "object",
    properties: {
      asset: {
        type: "string",
        pattern: "^[A-Za-z0-9]{1,10}$",
        description: "Asset symbol (OKX USDT-SWAP underlying), e.g. BTC.",
      },
      window_h: {
        type: "number",
        minimum: 1,
        maximum: 72,
        description: "Lookback window in hours (default 6). Committed into the answer as window_start_ms/window_end_ms for /verify reproducibility.",
      },
    },
    required: ["asset"],
  },
  "positioning-snapshot": {
    type: "object",
    properties: {
      assets: {
        type: "array",
        items: { type: "string", pattern: "^[A-Za-z0-9]{1,10}$" },
        maxItems: 10,
        description: "Subset of the configured asset set to snapshot (default: all configured — BTC, ETH, SOL, ARB, AVAX).",
      },
    },
  },
  "token-safety": {
    type: "object",
    properties: {
      token: {
        type: "string",
        pattern: "^0x[0-9a-fA-F]{40}$",
        description: "The token contract address to screen (honeypot/rug/mint/blacklist signals). BLOCK if no contract code is deployed at the address.",
      },
      chain: {
        type: "string",
        enum: ["base", "ethereum", "arbitrum"],
        description: "Chain the token lives on (default \"base\"). Selects the GoPlus chain_id + the public RPC for the on-chain code check.",
      },
    },
    required: ["token"],
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
/** Structured error body the gateway returns (matches the runtime error handler):
 *  { error: <machine code>, detail?: <human> }. No stack/path is ever included. */
const ERROR_SCHEMA = {
  type: "object",
  properties: {
    error: {
      type: "string",
      description: "Machine-readable code, e.g. invalid_json, payload_too_large, method_not_allowed.",
    },
    detail: { type: "string", description: "Human-readable explanation (no stack trace / path)." },
  },
  required: ["error"],
};

function paidResponses(okSchema: object, priceAtomic: string) {
  const usd = (Number(priceAtomic) / 1_000_000).toFixed(6);
  return {
    "200": {
      description: "Successful response",
      content: { "application/json": { schema: okSchema } },
    },
    "400": {
      description: "Bad Request — malformed JSON body (POST oracles).",
      content: { "application/json": { schema: ERROR_SCHEMA } },
    },
    "402": {
      description:
        `Payment Required — pay the x402 challenge in the payment-required ` +
        `header (x402 v2) and retry. $${usd} USDC on ${networkInfo().label}.`,
    },
    "413": {
      description: "Payload Too Large — request body exceeds the 32 KB limit.",
      content: { "application/json": { schema: ERROR_SCHEMA } },
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

// address-reputation returns its verdict SYNCHRONOUSLY (not the on-chain ack
// shape) — { answer, attestation, broadcast }. Two independent receipts ride
// the paid 200: the embedded `attestation` (the publisher's verdict-level
// EIP-712 sig over the canonical answer bytes) and the gateway's
// X-BYTE-Attestation header (byte-integrity receipt over the whole body).
const addressReputationResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "address-reputation/v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        query: {
          type: "object",
          properties: {
            domain: { type: "string" },
            address: { type: "string" },
            amount: { type: "integer" },
            chain: { type: "string" },
          },
        },
        verdict: {
          type: "string",
          enum: ["ALLOW", "WARN", "BLOCK"],
          description: "Go/no-go: ALLOW = clear to pay; WARN = hold for a human / extra check; BLOCK = do not pay.",
        },
        score: { type: "integer", minimum: 0, maximum: 100 },
        reasons: { type: "array", items: { type: "string" } },
        signals: {
          type: "object",
          description: "The full signal set judged: domain (RDAP/TLS/DNS/Wayback), onchain (tx_count, balance, is_contract, is_delegated_eoa), blocklist hits.",
        },
        methodology: { type: "string", description: "Pinned ruleset id, e.g. \"ar-v1\" — frozen; verdicts are reproducible." },
        input_hashes: { type: "object" },
      },
      required: ["v", "verdict", "score", "reasons", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: {
          type: "object",
          description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}. The consensus domain is anchored on Arbitrum (mainnet pending audit); the signature + byte-integrity is real regardless of which rail you paid on.",
        },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed verdict is the product.",
    },
  },
  required: ["answer"],
};

// pkg-verdict returns its verdict SYNCHRONOUSLY — { answer, attestation, broadcast }.
// Two independent receipts ride the paid 200: the embedded `attestation` (the publisher's
// EIP-712 sig over the canonical answer bytes) and the gateway's X-BYTE-Attestation header.
const pkgVerdictResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "pkg-verdict/v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        query: {
          type: "object",
          properties: {
            ecosystem: { type: "string", enum: ["npm", "pypi"] },
            package: { type: "string" },
            version: { type: ["string", "null"], description: "The resolved version actually judged (pinned)." },
            version_requested: { type: ["string", "null"] },
          },
        },
        verdict: {
          type: "string",
          enum: ["ALLOW", "WARN", "BLOCK"],
          description: "Install gate: ALLOW = clear; WARN = hold for review; BLOCK = do not install.",
        },
        score: { type: "integer", minimum: 0, maximum: 100 },
        reasons: { type: "array", items: { type: "string" } },
        signals: {
          type: "object",
          description: "Four gathered signal groups: malicious (OSV.dev), registry, typosquat (corpus), knownbad (curated seed).",
        },
        retrieved_at: { type: "string", format: "date-time" },
        methodology: { type: "string", description: "Frozen ruleset id, e.g. \"pv-v1\"." },
        input_hashes: { type: "object" },
        error: { type: ["string", "null"], description: "Set iff the registry was unreachable (a 404 is a BLOCK verdict, not an error)." },
      },
      required: ["v", "verdict", "score", "reasons", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: {
          type: "object",
          description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}.",
        },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed verdict is the product.",
    },
  },
  required: ["answer"],
};

// sanctions-screen returns its verdict SYNCHRONOUSLY — { answer, attestation, broadcast }.
// The answer embeds `list_state` pinning the exact OFAC list version (date + sha256) used.
const sanctionsScreenResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "sanctions-screen/v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        query: {
          type: "object",
          properties: {
            address: { type: ["string", "null"] },
            name: { type: ["string", "null"] },
            chain: { type: ["string", "null"] },
          },
        },
        verdict: {
          type: "string",
          enum: ["ALLOW", "WARN", "BLOCK"],
          description: "BLOCK = direct OFAC SDN hit; WARN = non-SDN hit, fuzzy-name screen, or inconclusive; ALLOW = no match against the pinned list-state.",
        },
        score: { type: "integer", minimum: 0, maximum: 100 },
        reasons: {
          type: "array",
          items: { type: "string" },
          description: "Each hit cites the OFAC entry (#uid, name, programs) AND the list version. Staleness and outage notes also appear here.",
        },
        signals: {
          type: "object",
          description: "sdn + consolidated signal blocks: address_hit, name_exact_hit, name_fuzzy_hit, list_state, error.",
        },
        list_state: {
          type: "object",
          description: "VERSION-PINNING: the exact OFAC list version judged against (source, published_date, fetched_at, content_sha256, entry_count, stale).",
          properties: {
            sdn: { type: "object" },
            consolidated: { type: "object" },
          },
        },
        retrieved_at: { type: "string", format: "date-time" },
        methodology: { type: "string", description: "Frozen ruleset id, e.g. \"ss-v1\"." },
        input_hashes: { type: "object" },
        error: { type: ["string", "null"], description: "Set iff no SDN list-state was available at all." },
      },
      required: ["v", "verdict", "score", "reasons", "list_state", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: {
          type: "object",
          description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}.",
        },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed verdict is the product.",
    },
  },
  required: ["answer"],
};

// token-safety returns its verdict SYNCHRONOUSLY — { answer, attestation, broadcast }.
const tokenSafetyResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "token-safety/v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        query: {
          type: "object",
          properties: {
            token: { type: "string" },
            chain: { type: "string" },
          },
        },
        verdict: {
          type: "string",
          enum: ["ALLOW", "WARN", "BLOCK"],
          description: "BLOCK = honeypot / cannot-sell / no contract code / known-bad corpus hit; WARN = rug/control flag (mintable, owner-can-change-balance, pausable, blacklist) or unverified; ALLOW = clean.",
        },
        score: { type: "integer", minimum: 0, maximum: 100 },
        reasons: { type: "array", items: { type: "string" } },
        signals: {
          type: "object",
          description: "goplus (honeypot, buy/sell tax, is_mintable, owner_change_balance, can_take_back_ownership, hidden_owner, blacklist, is_open_source, LP) + onchain (is_contract via eth_getCode) + corpus (known-bad hit). GoPlus is the cited data source; BYTE adds the signed reproducible verdict.",
        },
        methodology: { type: "string", description: "Frozen ruleset id, e.g. \"ts-v1\"." },
        input_hashes: { type: "object" },
        error: { type: ["string", "null"] },
      },
      required: ["v", "verdict", "score", "reasons", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: { type: "object", description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}." },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed verdict is the product.",
    },
  },
  required: ["answer"],
};

// liquidation-stream returns its verdict SYNCHRONOUSLY — { answer, attestation, broadcast }.
// The committed window (window_start_ms/window_end_ms) in the answer makes the verdict
// reproducible via POST /verify against the append-only archive.
const liquidationStreamResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "liquidation-stream/v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        query: {
          type: "object",
          properties: {
            asset: { type: "string" },
            window_h: { type: "number" },
            window_start_ms: { type: "integer", description: "Committed window start (Unix milliseconds)." },
            window_end_ms: { type: "integer", description: "Committed window end (Unix milliseconds)." },
          },
        },
        verdict: {
          type: "string",
          enum: ["SUBCRITICAL", "NEAR_CRITICAL", "SUPERCRITICAL", "INSUFFICIENT_DATA"],
          description: "Hawkes branching-ratio regime. INSUFFICIENT_DATA abstain when fewer than 30 in-window events.",
        },
        score: { type: ["integer", "null"], minimum: 0, maximum: 100, description: "min(100, round(n̂*100)); null when abstaining." },
        reasons: { type: "array", items: { type: "string" } },
        signals: {
          type: "object",
          description: "archive (events, venues), hawkes (n_hat, mu, alpha, beta), collector signal blocks.",
        },
        retrieved_at: { type: "string", format: "date-time" },
        methodology: { type: "string", description: "Frozen ruleset id, e.g. \"ls-v1\"." },
        input_hashes: { type: "object" },
        error: { type: ["string", "null"] },
      },
      required: ["v", "verdict", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: {
          type: "object",
          description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}.",
        },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed verdict is the product.",
    },
  },
  required: ["answer"],
};

// positioning-snapshot returns its measurement SYNCHRONOUSLY — { answer, attestation, broadcast }.
// Every derived field (funding_apr, open_interest_usd, agg) recomputes exactly from the raw
// fields committed alongside it; POST /verify re-derives them with no network access.
const positioningSnapshotResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "positioning-snapshot/v1" },
        ts: { type: "integer", description: "Unix seconds the snapshot was taken." },
        query: {
          type: "object",
          properties: {
            assets: { type: "array", items: { type: "string" } },
          },
        },
        verdict: {
          type: "string",
          enum: ["COMPLETE", "PARTIAL", "UNAVAILABLE"],
          description: "Coverage verdict: % of expected live (venue, asset) legs present.",
        },
        score: { type: "integer", minimum: 0, maximum: 100, description: "% of expected live venue-asset legs present." },
        reasons: { type: "array", items: { type: "string" } },
        signals: {
          type: "object",
          description: "venues (per-venue status), assets (per-asset legs with raw funding + OI fields + derived agg), archive signal blocks.",
          properties: {
            venues: { type: "object" },
            assets: {
              type: "array",
              description: "Per-asset positioning: legs[] with raw funding_rate_native/funding_interval_s/funding_apr/open_interest_base/open_interest_usd/price_ref, plus OI-weighted agg.",
            },
            archive: { type: "object" },
          },
        },
        retrieved_at: { type: "string", format: "date-time" },
        methodology: { type: "string", description: "Frozen ruleset id, e.g. \"ps-v1\"." },
        input_hashes: { type: "object" },
        error: { type: ["string", "null"] },
      },
      required: ["v", "verdict", "score", "methodology"],
    },
    attestation: {
      type: "object",
      description:
        "Publisher's EIP-712 PayloadAttestation over keccak256 of the canonical " +
        "(insertion-order, minified) answer bytes. Recompute the hash over `answer` " +
        "AS RECEIVED and recover the signer before acting on the verdict.",
      properties: {
        payloadHash: { type: "string" },
        payloadLength: { type: "integer" },
        deadline: { type: "integer" },
        signer: { type: "string" },
        signature: { type: "string" },
        domain: {
          type: "object",
          description: "EIP-712 domain {name:\"BYTE Library\", version:\"1\", chainId:421614, verifyingContract}.",
        },
      },
    },
    broadcast: {
      type: "object",
      description: "On-chain broadcast status — disabled on this rail; the synchronous signed measurement is the product.",
    },
  },
  required: ["answer"],
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
 *  the subscriber address. */
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
        summary: `${f.name} — latest PayPerByte broadcast (${f.price} / call, ~${f.expectedSizeBytes}B)`,
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
  // IDs declared explicitly in buildOpenApiDoc() with bespoke response schemas.
  const EXPLICIT_IDS = new Set([
    "address-reputation",
    "pkg-verdict",
    "sanctions-screen",
    "liquidation-stream",
    "positioning-snapshot",
  ]);
  const paths: Record<string, unknown> = {};
  for (const f of feedRegistry) {
    if (f.publisher) continue;            // publisher oracles handled above
    if (!POST_ORACLE_IDS.has(f.id)) continue;
    if (EXPLICIT_IDS.has(f.id)) continue; // declared explicitly below — own response schema
    paths[f.endpoint] = { post: oraclePostOperation(f) };
  }
  return paths;
}

export function buildOpenApiDoc() {
  const defi = feed("defi-yields");
  const addressRep = feed("address-reputation");
  const pkgVerdict = feed("pkg-verdict");
  const sanctionsScreen = feed("sanctions-screen");
  const liquidationStream = feed("liquidation-stream");
  const positioningSnapshot = feed("positioning-snapshot");

  return {
    openapi: "3.1.0",
    info: {
      title: "PayPerByte x402 Gateway",
      version: "0.3.0",
      description:
        "Verified, provenance-first data feeds for AI agents. Every payload " +
        "is cryptographically signed and EIP-712 PayloadAttestation " +
        "provenance-stamped — covering crypto markets, DeFi yields, weather, " +
        "earthquakes, news, code-pulse, threat-intel, address reputation, " +
        "sanctions screening, and supply-chain verdicts. " +
        "Pay per call in USDC over x402 with no API keys — a " +
        "wallet, not a secret on the box. Settlement is on " +
        `${networkInfo().label} (${config.network}). Price is per-feed, derived from expected ` +
        "payload size at " +
        `$${(Number(config.pricePerKBAtomic) / 1_000_000).toFixed(6)}/KB ` +
        `(floor $${(Number(config.priceFloorAtomic) / 1_000_000).toFixed(6)}).`,
      "x-guidance":
        "Paid endpoints return HTTP 402 with x402 v2 payment requirements " +
        "in the `payment-required` header — pay the quoted USDC on " +
        `${networkInfo().label} (network ${config.network}) and retry. Each feed has its own ` +
        "price (see x-payment-info per operation); the catalog at GET /feeds " +
        "(free, ungated) lists every feed with its computed price and " +
        "expected payload size. POST oracle endpoints (address-reputation, " +
        "sanctions-screen, pkg-verdict, evidence-pack, usc-statute, " +
        "liquidation-stream, positioning-snapshot) require a JSON body — " +
        "see the requestBody schema per operation. Free, no " +
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
      "/feeds/address-reputation": {
        post: {
          operationId: "postAddressReputation",
          summary: `Address Reputation — synchronous signed ALLOW/WARN/BLOCK verdict before you pay (${addressRep.price} per verdict)`,
          description: addressRep.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(addressRep.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["address-reputation"] },
            },
          },
          responses: paidResponses(addressReputationResponseSchema, addressRep.priceAtomic),
        },
      },
      "/feeds/pkg-verdict": {
        post: {
          operationId: "postPkgVerdict",
          summary: `Package Verdict — synchronous signed ALLOW/WARN/BLOCK install gate (${pkgVerdict.price} per verdict)`,
          description: pkgVerdict.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(pkgVerdict.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["pkg-verdict"] },
            },
          },
          responses: paidResponses(pkgVerdictResponseSchema, pkgVerdict.priceAtomic),
        },
      },
      "/feeds/sanctions-screen": {
        post: {
          operationId: "postSanctionsScreen",
          summary: `Sanctions Screen — synchronous signed ALLOW/WARN/BLOCK OFAC verdict (${sanctionsScreen.price} per verdict)`,
          description: sanctionsScreen.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(sanctionsScreen.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["sanctions-screen"] },
            },
          },
          responses: paidResponses(sanctionsScreenResponseSchema, sanctionsScreen.priceAtomic),
        },
      },
      "/feeds/liquidation-stream": {
        post: {
          operationId: "postLiquidationStream",
          summary: `Liquidation Stream — signed cascade-risk regime (${liquidationStream.price} per verdict)`,
          description: liquidationStream.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(liquidationStream.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["liquidation-stream"] },
            },
          },
          responses: paidResponses(liquidationStreamResponseSchema, liquidationStream.priceAtomic),
        },
      },
      "/feeds/positioning-snapshot": {
        post: {
          operationId: "postPositioningSnapshot",
          summary: `Positioning Snapshot — signed cross-venue perp positioning measurement (${positioningSnapshot.price} per snapshot)`,
          description: positioningSnapshot.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(positioningSnapshot.priceAtomic),
          requestBody: {
            required: false,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["positioning-snapshot"] },
            },
          },
          responses: paidResponses(positioningSnapshotResponseSchema, positioningSnapshot.priceAtomic),
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
            `the quoted USDC on ${networkInfo().label} (network ${config.network}) via an ` +
            "x402 client, then retry with the settlement receipt. No API key — " +
            "a wallet signs an EIP-3009 `transferWithAuthorization` and the " +
            "facilitator settles on-chain. See the per-operation `x-payment-info` " +
            "for the exact price.",
        },
      },
      schemas: {
        CryptoTop100Response: cryptoTop100Schema,
        DefiYieldsResponse: defiYieldsSchema,
        ByteLibraryFeedResponse: byteLibraryFeedSchema,
        OracleAck: oracleAckSchema,
        AddressReputationResponse: addressReputationResponseSchema,
        PkgVerdictResponse: pkgVerdictResponseSchema,
        SanctionsScreenResponse: sanctionsScreenResponseSchema,
        TokenSafetyResponse: tokenSafetyResponseSchema,
        LiquidationStreamResponse: liquidationStreamResponseSchema,
        PositioningSnapshotResponse: positioningSnapshotResponseSchema,
      },
    },
  };
}
