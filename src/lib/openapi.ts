/**
 * OpenAPI 3.1 document for the Byte Protocol x402 gateway.
 *
 * Served at GET /openapi.json — this is the canonical machine-readable
 * discovery contract that x402scan (and other agent discovery layers) read.
 * Discovery precedence: this document first, runtime 402 behavior second.
 *
 * Lists the payable resources PLUS the two free discovery endpoints (GET /feeds
 * catalog, GET /health). The free ones are declared with operation-level
 * `security: []` (overriding the doc-level x402Payment) and carry NO
 * x-payment-info and NO 402 response, so a scanner/codegen tool sees them as
 * explicitly non-payable rather than mis-probing them for a 402.
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
// evidence-pack and liquidation-stream removed 2026-07-28 (same reason, same
// pattern — both DELISTED, not in feedRegistry). Without this,
// buildOpenApiDoc()'s explicit `feed("liquidation-stream")` lookup throws
// (feedRegistry has no entry for it), 500ing the free /openapi.json route —
// caught by gate-engagement-check.mjs's free-route-reachable assertion.
const POST_ORACLE_IDS = new Set(["address-reputation", "pkg-verdict", "sanctions-screen", "positioning-snapshot", "reasoning-verdict", "runtime-eol", "threat-intel", "merchant-screen", "cctp-attestation-latency"]);

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
      kind: {
        type: "string",
        enum: ["payee", "transaction", "contract", "message", "proposal", "tool-call", "url", "claim", "general"],
        description: "Optional. The action type, to focus the judgment (default \"general\"). Echoed back in answer.kind.",
      },
      context: {
        type: "string",
        description: "Optional. Extra context for the judgment — a string, or a JSON object/array (it is stringified). Length-capped server-side.",
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
        description: "The statement to research and ground against cited sources — returns a signed citation bundle (retrieved sources + excerpts), e.g. \"USDC is fully reserved 1:1\". The receipt proves provenance/integrity of the returned bundle, NOT that the statement is true; no correctness or fact-check verdict is asserted.",
      },
      domains: {
        type: "array",
        items: { type: "string" },
        description: "Optional allowlist of source domains to retrieve evidence from (e.g. [\"sec.gov\", \"circle.com\"]). Omit to search all indexed PayPerByte factual feeds.",
      },
      max_sources: {
        type: "integer",
        minimum: 1,
        description: "Optional cap on the number of cited sources in the returned evidence pack — bounds the response size. The price is a flat $0.02 per call regardless of how many sources are returned (it is not metered per source).",
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
        description: "The payee's web domain, e.g. \"github.com\". BLOCK if it doesn't resolve or hits the blocklist. Provide either `domain` or its alias `url`.",
      },
      url: {
        type: "string",
        minLength: 1,
        description: "Alias for `domain` — the payee's web domain/URL. Accepted interchangeably with `domain` (provide at least one).",
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
        enum: ["base", "arbitrum-one"],
        description: "Mainnet for the on-chain receiving-address signals (default \"base\" = Base mainnet; \"arbitrum-one\" = Arbitrum One mainnet). Mainnets only — a testnet returns meaningless zeros for a real payee. (The Arbitrum Sepolia testnet is opt-in dev-only via ADDRESS_REP_ENABLE_TESTNET as chain \"arbitrum-sepolia\", and is intentionally not advertised here.)",
      },
    },
    // `address` always required; the domain may be given as `domain` OR `url`
    // (the upstream accepts either: `body.get("domain") or body.get("url")`).
    required: ["address"],
    anyOf: [{ required: ["domain"] }, { required: ["url"] }],
  },
  "merchant-screen": {
    type: "object",
    required: ["domain"],
    properties: {
      domain: { type: "string", description: "The merchant host the agent is about to pay." },
      address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$", description: "Optional — the payTo the agent observed." },
      observed_price_atomic: { type: "string", pattern: "^[0-9]+$", description: "Optional — atomic USDC price quoted to the agent. STRING (may exceed 2^53; a JSON number is rejected upstream)." },
      chain: { type: "string", enum: ["base"], default: "base" },
    },
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
    // At least one screenable subject is required — an empty {} body would screen
    // NOTHING. The gateway enforces this BEFORE settlement (a 400 cancels the
    // x402 payment), so an agent is never charged $0.05 for an unscreenable query.
    anyOf: [{ required: ["address"] }, { required: ["name"] }],
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
  "cctp-attestation-latency": {
    type: "object",
    properties: {
      chain: {
        type: "string",
        description: "Optional. Narrow to one source chain (e.g. \"base\", \"arbitrum\", \"optimism\"). Omit for every configured chain.",
      },
      path: {
        type: "string",
        enum: ["fast", "standard"],
        description: "Optional. CCTP v2 settlement path. Fast and Standard are never blended — omitting this returns both as separate distributions; an unrecognized value is a 400, not a silent fallback.",
      },
    },
  },
};

/** Per-oracle EXAMPLE request body — a concrete, schema-valid payload an agent can
 *  copy. This is distinct from ORACLE_REQUEST_SCHEMAS (the JSON Schema): the Bazaar
 *  extension puts the EXAMPLE in `info.input.body` (human/sample) and the SCHEMA in
 *  `schema.input.body` (machine). Reusing the schema object as the example makes the
 *  example fail its own schema, so a strict Bazaar/CDP validator drops the oracle —
 *  hence a real example per oracle. Each satisfies its schema's required/anyOf. */
export const ORACLE_REQUEST_EXAMPLES: Record<string, Record<string, unknown>> = {
  "reasoning-verdict": { subject: "Release 5,000 USDC to 0x1111111111111111111111111111111111111111 for invoice #42?", kind: "transaction" },
  "runtime-eol": { product: "nodejs", version: "18" },
  "threat-intel": { components: ["log4j", "CVE-2021-44228"] },
  "evidence-pack": { claim: "USDC is fully reserved 1:1" },
  "usc-statute": { citation: "17 USC 107" },
  "address-reputation": { domain: "example.com", address: "0x1111111111111111111111111111111111111111", amount: 50000, chain: "base" },
  "merchant-screen": { domain: "example.com", address: "0x1111111111111111111111111111111111111111", observed_price_atomic: "150000", chain: "base" },
  "pkg-verdict": { ecosystem: "npm", package: "left-pad" },
  // A name that actually hits the SDN list — paired with the BLOCK response
  // excerpt below, it demos the dated list pin end-to-end.
  "sanctions-screen": { name: "Lazarus Group" },
  "liquidation-stream": { asset: "BTC" },
  "positioning-snapshot": { assets: ["BTC", "ETH"] },
  "cctp-attestation-latency": { chain: "base", path: "fast" },
};

/** Per-oracle EXAMPLE response excerpt → the Bazaar declaration's `output.example`
 *  (PROD-15) — a browsing agent sees the verdict envelope + the receipt shape
 *  BEFORE paying, not just `{ feed }`. Kept compact: the declaration rides the
 *  402's PAYMENT-REQUIRED header on every challenge, so these are excerpts, not
 *  full bodies. sanctions-screen is an excerpt of a REAL answer from the live
 *  service (queried 2026-07-01) showcasing the dated OFAC list pin; the other
 *  three are illustrative shapes and say so in `_note`. In every case the
 *  EIP-712 receipt proves WHO SIGNED THE EXACT BYTES (authenticity +
 *  tamper-evidence) — never that the verdict/data is correct. Verdicts are
 *  screening signals, not legal advice. Feeds not listed fall back to the
 *  minimal `{ feed }` example in getExtensions(). */
export const ORACLE_RESPONSE_EXAMPLES: Record<string, Record<string, unknown>> = {
  "sanctions-screen": {
    _note:
      "Excerpt of a real answer (live service, 2026-07-01); hash/signature elided, signals/consolidated " +
      "trimmed. Every answer pins the exact OFAC list version (published date + sha256 + entry count) it " +
      "was judged against. Screening signal, not legal advice. The EIP-712 receipt — domain chainId " +
      "421614 = Arbitrum Sepolia, a frozen signing namespace, not a settlement rail — proves who signed " +
      "these exact bytes (authenticity + tamper-evidence), not that the screening result is correct. " +
      "Recompute keccak256(canonical answer bytes) and recover the signer before acting.",
    answer: {
      v: "sanctions-screen/v1",
      query: { address: null, name: "Lazarus Group", chain: null },
      verdict: "BLOCK",
      score: 0,
      reasons: [
        'name exactly matches OFAC SDN primary name "LAZARUS GROUP": entry #27307 "LAZARUS GROUP" [DPRK3] — list published 2026-06-30',
      ],
      list_state: {
        sdn: {
          source: "OFAC SDN (Specially Designated Nationals and Blocked Persons)",
          published_date: "2026-06-30",
          content_sha256: "a04efa5d60104ebd35fc08b6891811120d151bf37801fbd3c01e64380198f099",
          entry_count: 19129,
          stale: false,
        },
      },
      methodology: "ss-v1",
    },
    attestation: {
      payloadHash: "0x…",
      signer: "0x344ECaCDe6566294c31397445c98b62a3EEEA456",
      signature: "0x…",
      domain: { name: "BYTE Library", version: "1", chainId: 421614, verifyingContract: "0x44729bB148F46d8Db509E47b0453edc271e06e95" },
    },
  },
  "address-reputation": {
    _note:
      "Illustrative response shape — not a live answer. ALLOW/WARN/BLOCK is a screening signal. The " +
      "embedded EIP-712 receipt (domain chainId 421614 = Arbitrum Sepolia, a frozen signing namespace, " +
      "not a settlement rail) proves who signed the exact answer bytes — not that the verdict is correct.",
    answer: {
      v: "address-reputation/v1",
      query: { domain: "example.com", address: "0x1111111111111111111111111111111111111111", amount: 50000, chain: "base" },
      verdict: "WARN",
      score: 55,
      reasons: ["illustrative — real answers cite the ar-v1 domain (RDAP/TLS/DNS/Wayback), on-chain, and blocklist signals judged"],
      methodology: "ar-v1",
    },
    attestation: {
      payloadHash: "0x…",
      signer: "0x…",
      signature: "0x…",
      domain: { name: "BYTE Library", version: "1", chainId: 421614 },
    },
  },
  "pkg-verdict": {
    _note:
      "Illustrative response shape — not a live answer. ALLOW/WARN/BLOCK is a screening signal. The " +
      "embedded EIP-712 receipt (domain chainId 421614 = Arbitrum Sepolia, a frozen signing namespace, " +
      "not a settlement rail) proves who signed the exact answer bytes — not that the verdict is correct.",
    answer: {
      v: "pkg-verdict/v1",
      query: { ecosystem: "npm", package: "left-pad", version: null, version_requested: null },
      verdict: "ALLOW",
      score: 96,
      reasons: ["illustrative — real answers cite the pv-v1 OSV.dev / typosquat / registry / known-bad signals judged"],
      methodology: "pv-v1",
    },
    attestation: {
      payloadHash: "0x…",
      signer: "0x…",
      signature: "0x…",
      domain: { name: "BYTE Library", version: "1", chainId: 421614 },
    },
  },
  "reasoning-verdict": {
    _note:
      "Illustrative response shape — not a live answer. The verdict is advisory. The embedded EIP-712 " +
      "receipt (domain chainId 421614 = Arbitrum Sepolia, a frozen signing namespace, not a settlement " +
      "rail) proves who signed the exact answer bytes — not that the verdict is correct.",
    answer: {
      v: "reasoning-verdict/v1",
      kind: "transaction",
      subject: "Release 5,000 USDC to 0x1111111111111111111111111111111111111111 for invoice #42?",
      verdict: "WARN",
      score: 40,
      summary: "illustrative — a one-sentence rationale from the LOCAL model",
      reasons: ["illustrative — real answers list the model's risk reasons"],
      confidence: "medium",
      ruleset: "rv-v1",
      disclaimer:
        "The receipt proves these exact bytes came from this publisher; it does NOT guarantee the " +
        "verdict is correct. AI-generated advisory analysis — verify independently before acting.",
    },
    attestation: {
      payloadHash: "0x…",
      signer: "0x…",
      signature: "0x…",
      domain: { name: "BYTE Library", version: "1", chainId: 421614 },
    },
  },
  "cctp-attestation-latency": {
    _note:
      "Excerpt of a real answer (live service, 2026-08-25); hash/signature elided, other buckets " +
      "trimmed. Every figure is a BOUNDED observation (burn -> first poll seeing complete), never " +
      "an exact measurement; percentiles are withheld below an 8-measured-sample floor. Fast and " +
      "Standard are separate settlement paths and are never blended into one percentile. The " +
      "embedded EIP-712 receipt (domain chainId 421614 = Arbitrum Sepolia, a frozen signing " +
      "namespace, not a settlement rail) proves who signed these exact bytes — not that the " +
      "measured latency will hold for your own transfer.",
    answer: {
      query: { chain: "base", path: "fast" },
      distributions: {
        "base/fast": {
          samples: 27715,
          measured_samples: 37,
          min_s: -1,
          max_s: 7999,
          p50_s: 1753,
          p95_s: 7265,
          p99_s: 7583,
          percentiles_reported: true,
          percentiles_withheld_because: null,
        },
      },
      observation_count: 27715,
      coverage: { status: "observed" },
      ruleset: "cctp-lat-v1",
    },
    attestation: {
      payloadHash: "0x…",
      signer: "0x…",
      signature: "0x…",
      domain: { name: "BYTE Library", version: "1", chainId: 421614 },
    },
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
// the paid 200: the embedded `attestation` (this feed's OWN per-feed EIP-712 sig
// over the canonical answer bytes — a distinct signer) and the gateway's
// X-BYTE-Attestation header (delivery-integrity receipt over the whole body,
// signed by the gateway key).
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
// Two independent receipts ride the paid 200: the embedded `attestation` (this feed's OWN
// per-feed EIP-712 sig over the canonical answer bytes) and the gateway's X-BYTE-Attestation
// header (delivery-integrity, gateway key).
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
        "EIP-712 PayloadAttestation signed by this feed's own per-feed attestation key (recover `attestation.signer` and compare to the feed's published signer — distinct from the gateway X-BYTE-Attestation key; first-party PayPerByte, not an independent third-party publisher, not a correctness guarantee), over keccak256 of the canonical " +
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
    // "byte-library-broadcast" = served from the on-chain-anchored discovery-api
    // archive (has txHash). "live" = P1 fix 2026-07-28 — served directly from the
    // feed's live-query companion when the broadcast archive is stale/empty (no
    // txHash this cycle; see feeds/generic.ts fetchFeedPayload + the `live` case
    // in attestationReceiptBlock().embedded.verify). Widened from a single-value
    // const so a buyer validating a live response against this schema doesn't
    // reject a valid delivery.
    source: { type: "string", enum: ["byte-library-broadcast", "live"] },
    txHash: { type: "string", description: "DataStream broadcast tx hash. Absent on a `live`-sourced response — there is no on-chain event that cycle." },
    payloadHash: { type: "string", description: "keccak256 of the payload. On `byte-library-broadcast`, the on-chain-committed hash; on `live`, the live-query companion's own EIP-712 PayloadAttestation payloadHash." },
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

/** The embedded EIP-712 PayloadAttestation block, shared by the synchronous oracle
 *  responses. This is the FEED's OWN per-feed signature (a distinct signer, separate
 *  from the gateway's X-BYTE-Attestation header key): recompute keccak256 over the
 *  canonical `answer` bytes AS RECEIVED, recover `attestation.signer`, and compare it
 *  to the feed's published signer before acting. First-party PayPerByte, NOT correctness. */
const payloadAttestationSchema = {
  type: "object",
  description:
    "EIP-712 PayloadAttestation signed by THIS feed's own per-feed attestation key " +
    "(a distinct signer — recover `attestation.signer` and compare it to the feed's " +
    "published signer address; SEPARATE from the gateway's X-BYTE-Attestation header " +
    "key). Computed over keccak256 of the canonical (insertion-order, minified) answer " +
    "bytes — recompute the hash over `answer` AS RECEIVED and recover the signer before " +
    "acting. First-party PayPerByte (not an independent third-party publisher), and NOT " +
    "a correctness guarantee.",
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
};

/** On-chain broadcast status block — disabled on this rail; the synchronous
 *  signed answer IS the product. */
const broadcastDisabledSchema = {
  type: "object",
  description: "On-chain broadcast status — disabled on this rail; the synchronous signed answer is the product (ok:false).",
};

/**
 * Generic SYNCHRONOUS response schema for the oracle POST operations that don't
 * have a bespoke schema (evidence-pack, runtime-eol, threat-intel, usc-statute).
 *
 * These return the answer SYNCHRONOUSLY in the paid 200 body — there is NO async
 * on-chain ACK and no `request_id`/`est_eta_ms`. The decision oracles
 * (runtime-eol, threat-intel) put a signed ALLOW/WARN/BLOCK/ABSTAIN verdict in
 * `answer`; the data oracles (usc-statute statute text, evidence-pack citation
 * bundle) put their feed-shaped payload there. `attestation` is this feed's OWN
 * per-feed EIP-712 receipt over the canonical answer bytes — a distinct signer,
 * recover `attestation.signer` (present when the upstream signs; usc-statute carries
 * no embedded receipt and relies on the gateway's X-BYTE-Attestation response header
 * instead). First-party PayPerByte, NOT correctness.
 */
const syncOracleResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      description:
        "The synchronous answer. Decision oracles return {verdict: ALLOW|WARN|BLOCK|ABSTAIN, score, reasons, methodology/ruleset, ...}; data oracles return their feed-shaped payload (e.g. statute text + content hash + source URLs, or a citation bundle of retrieved sources). Shape varies per feed — see the operation description.",
    },
    attestation: payloadAttestationSchema,
    broadcast: broadcastDisabledSchema,
    note: {
      type: "string",
      // Corrected 2026-08-01 (hardening plan §0.2), re-checked later the same
      // day. The old text — "Present ONLY when the answer is returned unsigned
      // (no publisher key configured)" — documented a fail-OPEN behavior the
      // oracles behind this schema no longer have: address-reputation,
      // pkg-verdict and sanctions-screen refuse with 503 rather than serve an
      // unsigned answer, and the second hardening wave extended that to
      // positioning-snapshot, liquidation-stream, evidence-pack, token-safety,
      // reasoning-verdict, runtime-eol and threat-intel. No feed still emits an
      // unsigned-answer note on a paid 200. The wording below stays true either
      // way, and keeps `note` from being read as the signal for "is this
      // signed?".
      description: "Optional diagnostic string — NOT part of the signed bytes, and NOT emitted by every feed. Oracles that fail closed on an unusable publisher key refuse with 503 instead of returning an unsigned answer, so they never set it; where it does appear the `attestation` is absent and the gateway X-BYTE-Attestation response header is the only receipt. Decide whether an answer is signed by checking for `attestation` — never infer it from the absence of `note`.",
    },
  },
  required: ["answer"],
};

/**
 * reasoning-verdict — explicit SYNCHRONOUS response schema (the flagship
 * local-LLM verify-before-act oracle). The live service (data-feeds/
 * reasoning-verdict/server.py, POST /query) returns { answer, attestation,
 * broadcast } in the paid 200 — NOT an async ACK. The embedded attestation signs
 * the canonical `answer` bytes; recompute and recover the signer before acting.
 * The verdict is ADVISORY — the receipt proves provenance + integrity, NOT that
 * the verdict is correct (the honesty notice is baked into answer.disclaimer).
 */
const reasoningVerdictResponseSchema = {
  type: "object",
  properties: {
    answer: {
      type: "object",
      properties: {
        v: { const: "reasoning-verdict/v1" },
        kind: {
          type: "string",
          enum: ["payee", "transaction", "contract", "message", "proposal", "tool-call", "url", "claim", "general"],
          description: "The classified action type the subject was judged as.",
        },
        subject: { type: "string", description: "The action/text that was judged (normalized, ASCII, length-capped)." },
        verdict: {
          type: "string",
          enum: ["ALLOW", "WARN", "BLOCK", "ABSTAIN"],
          description: "Go/no-go: ALLOW = no material risk seen; WARN = proceed only with caution / human review; BLOCK = do not proceed; ABSTAIN = insufficient information to judge.",
        },
        score: { type: "integer", minimum: 0, maximum: 100, description: "Safe-to-proceed score (100 = clearly safe, 0 = clearly unsafe)." },
        summary: { type: "string", description: "One-sentence rationale." },
        reasons: { type: "array", items: { type: "string" } },
        confidence: { type: "string", enum: ["low", "medium", "high"] },
        model: { type: "string", description: "The LOCAL model that produced the verdict (no third-party API; no data egress)." },
        ruleset: { const: "rv-v1" },
        ts: { type: "integer", description: "Unix seconds the verdict was produced." },
        disclaimer: {
          type: "string",
          description: "Honesty notice signed into the bytes: the receipt proves these exact bytes came from this publisher; it does NOT guarantee the verdict is correct. AI-generated advisory analysis — verify independently before acting.",
        },
      },
      required: ["v", "kind", "subject", "verdict", "score", "summary", "reasons", "confidence", "model", "ruleset", "ts", "disclaimer"],
    },
    attestation: payloadAttestationSchema,
    broadcast: broadcastDisabledSchema,
    // `note` REMOVED 2026-08-01 (second hardening wave). It documented the
    // unsigned-verdict fallback that data-feeds/reasoning-verdict/server.py no
    // longer has: with no usable REASONING_VERDICT_PUB_KEY, /query now refuses
    // with 503 "signing unavailable" before running inference instead of
    // returning a 200 carrying the verdict unsigned plus a note. Its paid 200
    // body is {answer, attestation, broadcast} and never carries a top-level
    // `note`, so documenting one here promised a response shape the service
    // cannot produce. Verified against the source, not the docs.
  },
  required: ["answer"],
};

/** Wrap a typed `answer` schema in the standard synchronous oracle envelope
 *  { answer, attestation?, broadcast, note? }. `embeddedAttestation:false` for a
 *  feed that carries no in-body receipt (usc-statute — its provenance receipt is
 *  the gateway X-BYTE-Attestation response header). `note:false` for a feed that
 *  FAILS CLOSED on a missing publisher key (503) and therefore never returns an
 *  unsigned-answer note on a paid 200.
 *
 *  UPDATE 2026-08-01 (second hardening wave): every remaining caller now passes
 *  `note:false`. The earlier version of this comment recorded that the default
 *  note text was still accurate for runtime-eol
 *  (data-feeds/runtime-eol/gate.py) and threat-intel
 *  (data-feeds/threat-intel/gate.py) because both still set
 *  `note: "no publisher key configured — answer returned UNSIGNED"`, and told
 *  the next reader not to "correct" it without re-reading them. Both were
 *  re-read at the source and then changed in the same wave: each now refuses
 *  with 503 before doing any work rather than serving an unsigned answer, so
 *  neither can emit that note. evidence-pack (data-feeds/evidence-pack/
 *  server.py) was hardened in the same wave and is the same case. The
 *  `noteDesc` path survives for usc-statute, whose `note` is a
 *  degraded/upstream-error string unrelated to signing. */
function syncResponseWith(
  answerSchema: object,
  opts: { embeddedAttestation?: boolean; noteDesc?: string; note?: boolean } = {},
) {
  const properties: Record<string, unknown> = { answer: answerSchema };
  if (opts.embeddedAttestation !== false) properties.attestation = payloadAttestationSchema;
  properties.broadcast = broadcastDisabledSchema;
  // `note` is OPT-IN and requires an explicit `noteDesc` (VETO wave-2 F2). The
  // old default text — "Present ONLY when the answer is returned unsigned (no
  // publisher key configured)" — described a fail-OPEN behavior no feed behind
  // this helper still has, and it was reachable by simply omitting `opts`. That
  // made the UNSAFE state the default: a future caller adding a feed here would
  // silently republish the removed promise. Deleted, and emission now requires
  // the caller to say what the note actually means. `note: false` is still
  // accepted (and passed explicitly by every current caller that has no note) so
  // the intent stays readable at the call site.
  if (opts.note !== false && opts.noteDesc) {
    properties.note = { type: "string", description: opts.noteDesc };
  }
  return { type: "object", properties, required: ["answer"] };
}

// ── Typed answer schemas for the generic POST oracles (was: one untyped shared
//    `answer` object). Each matches its live service's response dict. ───────────

// runtime-eol gate — data-feeds/runtime-eol/gate.py assess() answer dict.
const runtimeEolAnswerSchema = {
  type: "object",
  properties: {
    schema: { const: "runtime-eol/v1" },
    product: { type: "string", description: "endoflife.date product id, e.g. \"nodejs\"." },
    version: { type: "string", description: "The version/cycle queried." },
    cycle: { type: ["string", "null"], description: "The release cycle matched on endoflife.date." },
    status: { type: "string", enum: ["SUPPORTED", "EOL-SOON", "EOL", "UNKNOWN"], description: "Raw support status mapped into the verdict." },
    verdict: { type: "string", enum: ["ALLOW", "WARN", "BLOCK", "ABSTAIN"], description: "ALLOW = supported; WARN = EOL soon; BLOCK = end-of-life; ABSTAIN = unknown/unreachable." },
    score: { type: "integer", minimum: 0, maximum: 100 },
    eol: { type: ["string", "null"], description: "EOL marker from endoflife.date: an EOL date string (YYYY-MM-DD), or the literal string \"false\"/\"true\", or null when unknown." },
    days_until_eol: { type: ["integer", "null"] },
    latest: { type: ["string", "null"], description: "Latest release in the cycle." },
    is_latest: { type: ["boolean", "null"] },
    reasons: { type: "array", items: { type: "string" } },
    source: { const: "endoflife.date" },
    source_url: { type: "string" },
    ts: { type: "integer", description: "Unix seconds the verdict was produced." },
    disclaimer: { type: "string", description: "Advisory notice: the receipt proves provenance/integrity, not correctness." },
  },
  required: ["schema", "product", "version", "status", "verdict", "score", "source", "ts", "disclaimer"],
};

// threat-intel gate — data-feeds/threat-intel/gate.py assess() answer dict.
const threatIntelAnswerSchema = {
  type: "object",
  properties: {
    schema: { const: "threat-intel-gate/v1" },
    verdict: { type: "string", enum: ["ALLOW", "WARN", "BLOCK", "ABSTAIN"], description: "BLOCK = a queried component is in the CISA KEV (actively exploited); WARN = partial/heuristic match; ALLOW = none in KEV; ABSTAIN = catalog unavailable." },
    score: { type: "integer", minimum: 0, maximum: 100 },
    summary: { type: "string" },
    checked: { type: "integer", description: "Number of components screened." },
    match_count: { type: "integer", description: "Number of components matched in the KEV catalog." },
    matches: { type: "array", description: "Per-match detail (component → KEV/CVE entry).", items: { type: "object" } },
    kev_catalog: {
      type: "object",
      description: "VERSION-PINNING: the exact CISA KEV catalog judged against.",
      properties: {
        version: { type: "string" },
        dateReleased: { type: "string" },
        count: { type: "integer" },
        sha256: { type: "string" },
      },
    },
    source: { const: "CISA Known Exploited Vulnerabilities" },
    source_url: { type: "string" },
    ts: { type: "integer" },
    disclaimer: { type: "string", description: "Advisory notice: the receipt proves provenance/integrity, not correctness." },
  },
  required: ["schema", "verdict", "score", "checked", "match_count", "matches", "kev_catalog", "source", "ts", "disclaimer"],
};

// usc-statute — data-feeds/usc-statute/server.py /query answer dict. NOTE: uses
// `type` (not `schema`) + `answered_at` (not `ts`); carries NO embedded attestation.
const uscStatuteAnswerSchema = {
  type: "object",
  properties: {
    type: { const: "usc-statute/v1" },
    query: { type: "object", properties: { citation: { type: "string" } } },
    result: {
      type: "object",
      description: "The resolved statute: current public-domain text, a content hash, and source URLs (shape follows the usc-statute resolver). `error` is set here instead on an upstream failure.",
    },
    disclaimer_category: { const: "legal" },
    disclaimer: { type: "string" },
    request_id: { type: "string" },
    answered_at: { type: "string", format: "date-time" },
  },
  required: ["type", "query", "result", "disclaimer", "answered_at"],
};

// evidence-pack — data-feeds/evidence-pack/server.py answer dict. The `verdict`/
// `confidence` are ADVISORY grounding signals, NOT a certified correctness verdict.
const evidencePackAnswerSchema = {
  type: "object",
  properties: {
    type: { const: "evidence-pack/v1" },
    query: {
      type: "object",
      properties: {
        claim: { type: "string" },
        domains: { type: "array", items: { type: "string" } },
        max_sources: { type: ["integer", "null"] },
      },
    },
    verdict: { type: "string", description: "ADVISORY grounding signal from the NLI backend (one of \"supported\", \"contradicted\", \"unverifiable\") — NOT a certified correctness verdict. The signed receipt proves the bundle's provenance, not that the claim is true; judge the cited sources yourself." },
    confidence: { type: "number", minimum: 0, maximum: 1, description: "Advisory backend confidence (0-1) for the grounding signal — not a calibrated truth probability." },
    reasoning: { type: "string" },
    sources: { type: "array", description: "Retrieved + cited sources (url, excerpt, entailment/contradiction scores).", items: { type: "object" } },
    grounding_backend: { type: ["string", "null"] },
    grounding_model: { type: ["string", "null"] },
    retrieval: {
      type: "object",
      properties: {
        top_k: { type: "integer" },
        chunks_evaluated: { type: "integer" },
        sources_collected: { type: "integer" },
      },
    },
    disclaimer_category: { const: "general" },
    disclaimer: { type: "string" },
    request_id: { type: "string" },
    answered_at: { type: "string", format: "date-time" },
  },
  required: ["type", "query", "sources", "disclaimer", "answered_at"],
};

// merchant-screen — data-feeds/merchant-screen/resolvers.py resolve() answer dict
// (verified live 2026-07-28 against the real return shape, not the doc sketch).
// Pre-settlement screen: signals are MEASURED live at query time (RDAP age, TLS
// handshake, redirect probe, brand-clone distance vs a committed corpus), not a
// static reputation lookup.
const merchantScreenAnswerSchema = {
  type: "object",
  properties: {
    v: { const: "merchant-screen/v1" },
    ts: { type: "integer", description: "Unix seconds the verdict was produced." },
    query: {
      type: "object",
      properties: {
        domain: { type: "string" },
        address: { type: ["string", "null"] },
        observed_price_atomic: { type: ["string", "null"] },
        chain: { type: "string" },
      },
    },
    verdict: {
      type: "string",
      enum: ["ALLOW", "WARN", "BLOCK"],
      description:
        "Pre-settlement go/no-go: BLOCK = fresh-clone shape (near-clone of a known brand AND domain age <180d/unknown), no reachable HTTPS, or a hard price/payTo mismatch — do not settle. WARN = an unverified core signal (RDAP or TLS) caps confidence, or a soft price/payTo mismatch. ALLOW = no fresh-clone/fabricated-price shape found — evidence-toward, NEVER a certification of legitimacy.",
    },
    score: { type: "integer", minimum: 0, maximum: 100 },
    reasons: { type: "array", items: { type: "string" } },
    signals: {
      type: "object",
      description:
        "Signal blocks measured live at query time. price_sanity is present ONLY when observed_price_atomic and/or address was supplied in the request — never a fabricated null block when absent.",
      properties: {
        domain_age_days: { type: "object", description: "RDAP domain-age lookup." },
        tls: { type: "object", description: "Live TLS handshake: cert age, issuer, SAN match, has_https." },
        redirect: { type: "object", description: "Off-domain redirect probe." },
        clone_brand: { type: "object", description: "Brand-similarity distance vs a committed known-brand corpus (nearest_known_brand, distance, skeleton_hit)." },
        price_sanity: { type: "object", description: "Merchant's own advertised x402 manifest price + payTo match, when a price and/or address was supplied." },
        independence: { type: "object", description: "Static identity statement (not measured evidence — excluded from input_hashes)." },
      },
    },
    retrieved_at: { type: "string", format: "date-time" },
    methodology: { type: "string", description: "Frozen ruleset id, e.g. \"ms-v1\"." },
    input_hashes: { type: "object", description: "Hashes of the MEASURED evidence blocks (independence excluded)." },
    source: { type: "string" },
    error: { type: ["string", "null"], description: "Set ONLY when BOTH core signal sources (RDAP and TLS) were unreachable — a single unverified signal instead degrades the ruleset to a WARN cap." },
  },
  required: ["v", "verdict", "score", "reasons", "signals", "methodology"],
};

// runtime-eol, threat-intel and evidence-pack all lost their unsigned-answer
// variant in the 2026-08-01 hardening waves: each now refuses with 503 "signing
// unavailable" before doing any work rather than returning a 200 carrying an
// unsigned answer plus a soft note (data-feeds/runtime-eol/gate.py,
// data-feeds/threat-intel/gate.py, data-feeds/evidence-pack/server.py — the
// fail-closed check at the top of each /query). Their paid 200 body never
// carries a top-level `note`, so documenting one here promised a response shape
// the services cannot produce. Verified against the source.
const runtimeEolResponseSchema = syncResponseWith(runtimeEolAnswerSchema, { note: false });
const threatIntelResponseSchema = syncResponseWith(threatIntelAnswerSchema, { note: false });
const evidencePackResponseSchema = syncResponseWith(evidencePackAnswerSchema, { note: false });
// merchant-screen has NO unsigned-answer variant: when signing is requested and
// the publisher key is unusable it refuses the query with 503 rather than return
// a 200 carrying an unsigned verdict plus a soft note
// (data-feeds/merchant-screen/server.py — the fail-closed check at the top of
// /query). Its paid 200 body is {answer, broadcast, attestation?} and never
// carries a top-level `note`, so documenting one here promised a response shape
// the service cannot produce (hardening plan §0.2). Verified 2026-08-01.
const merchantScreenResponseSchema = syncResponseWith(merchantScreenAnswerSchema, { note: false });
const uscStatuteResponseSchema = syncResponseWith(uscStatuteAnswerSchema, {
  embeddedAttestation: false,
  noteDesc:
    "usc-statute carries NO embedded attestation — its provenance receipt is the gateway X-BYTE-Attestation response header. `note` appears on degraded/upstream-error paths.",
});

// cctp-attestation-latency — data-feeds/cctp-attestation-latency/resolvers.py
// resolve() answer dict, wrapped by http_api.py's POST /query. Distinct from
// every other oracle here: it has NO subscriber/broadcast model at all (not
// publisher-indexer-backed, unlike positioning-snapshot; no on-chain escrow
// path to stub, unlike merchant-screen/pkg-verdict/sanctions-screen). Its
// paid 200 body is {answer, attestation?} — never a `broadcast` field — so
// this does NOT go through syncResponseWith (which always adds one).
const cctpAttestationLatencyAnswerSchema = {
  type: "object",
  properties: {
    query: {
      type: "object",
      properties: {
        chain: { type: ["string", "null"] },
        path: { type: ["string", "null"] },
      },
    },
    distributions: {
      type: "object",
      description:
        "Keyed \"<chain>/<path>\" (e.g. \"base/fast\"), never merged — Fast and Standard are " +
        "separate settlement paths and are never blended into one percentile. Each bucket: " +
        "samples (total), measured_samples (caught in flight — the only population percentiles " +
        "are computed over), min_s/max_s (bounds over ALL samples), p50_s/p95_s/p99_s (null " +
        "below the measured-sample floor), percentiles_reported, percentiles_withheld_because, " +
        "max_bound_width_s, first_poll_already_complete, detail.",
    },
    observation_count: { type: "integer", description: "Rows in scope after chain/path filtering." },
    unclassified_excluded: { type: "integer", description: "Samples whose settlement path could not be classified — excluded, never bucketed." },
    unclassified_excluded_scope: { type: "string" },
    coverage: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["observed", "no_data"], description: "no_data means unknown, NEVER a claim of zero or fast latency." },
        detail: { type: "string" },
      },
    },
    ruleset: { const: "cctp-lat-v1" },
    readiness: {
      type: "object",
      description: "Registration-readiness metadata (feed_ready/coverage_claim/scope_claim) — not a data field.",
    },
  },
  required: ["query", "distributions", "observation_count", "coverage", "ruleset"],
};

const cctpAttestationLatencyResponseSchema = {
  type: "object",
  properties: {
    answer: cctpAttestationLatencyAnswerSchema,
    attestation: payloadAttestationSchema,
  },
  required: ["answer"],
};

/** Per-feed typed response schema for the generic POST oracles — fills the
 *  previously-untyped shared `answer`. Feeds not listed fall back to the generic
 *  syncOracleResponseSchema. */
const ORACLE_RESPONSE_SCHEMAS: Record<string, object> = {
  "runtime-eol": runtimeEolResponseSchema,
  "threat-intel": threatIntelResponseSchema,
  "evidence-pack": evidencePackResponseSchema,
  "usc-statute": uscStatuteResponseSchema,
  "merchant-screen": merchantScreenResponseSchema,
  "cctp-attestation-latency": cctpAttestationLatencyResponseSchema,
};

/** Build the POST operation for a request-response oracle feed. */
function oraclePostOperation(f: { id: string; name: string; price: string; description: string; priceAtomic: string }) {
  const reqSchema = ORACLE_REQUEST_SCHEMAS[f.id];
  return {
    operationId: `post${pascal(f.id)}`,
    summary: `${f.name} — synchronous signed query/response (${f.price} per call)`,
    description: f.description,
    tags: ["Feeds"],
    security: [{ x402Payment: [] }],
    "x-payment-info": paymentInfo(f.priceAtomic),
    requestBody: {
      required: true,
      content: { "application/json": { schema: reqSchema } },
    },
    responses: paidResponses(ORACLE_RESPONSE_SCHEMAS[f.id] ?? syncOracleResponseSchema, f.priceAtomic),
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
  // liquidation-stream removed 2026-07-28 (delisted — see POST_ORACLE_IDS above).
  const EXPLICIT_IDS = new Set([
    "address-reputation",
    "pkg-verdict",
    "sanctions-screen",
    "positioning-snapshot",
    "reasoning-verdict",
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

/** GET /feeds — the free, ungated catalog response. */
const feedsCatalogSchema = {
  type: "object",
  properties: {
    protocol: { type: "string" },
    version: { type: "string" },
    networks: { type: "array", items: { type: "string" } },
    facilitator: { type: "string" },
    asset: { type: "string" },
    pricing: { type: "object", description: "Per-byte pricing model + floor." },
    disclaimers: { type: "object", description: "Disclaimer header name + per-category text." },
    feeds: {
      type: "array",
      description: "Every feed with its price, expected size, provenance, and accepted method(s).",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          method: {
            type: "array",
            items: { type: "string", enum: ["GET", "POST"] },
            description: "Accepted HTTP verb(s) — dual-pattern feeds list both [\"GET\",\"POST\"].",
          },
          price: { type: "string" },
          expectedSizeBytes: { type: "integer" },
          provenance: { type: "string" },
          disclaimerCategory: { type: "string" },
        },
      },
    },
  },
  required: ["protocol", "feeds"],
};

/** GET /health — the free liveness response. */
const healthSchema = {
  type: "object",
  properties: {
    status: { type: "string", description: "\"ok\" when serving." },
    network: { type: "string" },
    attester: { type: "string" },
  },
  required: ["status"],
};

export function buildOpenApiDoc() {
  const addressRep = feed("address-reputation");
  const pkgVerdict = feed("pkg-verdict");
  const sanctionsScreen = feed("sanctions-screen");
  // liquidation-stream lookup removed 2026-07-28 — delisted, no longer in
  // feedRegistry; `feed()` throws on a missing id (see its own comment), and
  // it was 500ing the free /openapi.json route (see POST_ORACLE_IDS above).
  const positioningSnapshot = feed("positioning-snapshot");
  const reasoningVerdict = feed("reasoning-verdict");
  // Feeds whose payload itself carries a LIVE per-feed EIP-712 attestation (a
  // distinct per-feed signer) — drives the honest "live per-feed provenance" claim.
  const attestedCount = feedRegistry.filter((f) => f.provenance === "eip712-attested").length;

  return {
    openapi: "3.1.0",
    info: {
      title: "PayPerByte x402 Gateway",
      version: "0.3.0",
      description:
        "Cryptographically attested, first-party data feeds for AI agents — " +
        "covering crypto markets, DeFi yields, weather, earthquakes, news, " +
        "code-pulse, threat-intel, address reputation, sanctions screening, and " +
        "supply-chain verdicts. Every paid response carries EIP-712 receipts you " +
        "verify before acting: (1) a GATEWAY delivery-integrity receipt " +
        "(X-BYTE-Attestation header, signed by the PayPerByte gateway key) proving " +
        "these are exactly the bytes we served; and (2) on the " +
        `${attestedCount} attested feeds (provenance:eip712-attested in GET /feeds), a ` +
        "LIVE per-feed PayloadAttestation by that feed's OWN distinct publisher key, " +
        "anchored ON-CHAIN — recover it from the broadcast the response references via " +
        "txHash. (Separately, the POST verdict oracles embed their own per-feed " +
        "`attestation` directly in the response body — recover attestation.signer.) " +
        "Both attest authenticity + tamper-evidence " +
        "under the BYTE Library domain. NEITHER asserts the correctness of the " +
        "underlying data or any verdict, and NEITHER claims an independent " +
        "third-party data source signed it — all keys are first-party PayPerByte. " +
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
        "sanctions-screen, pkg-verdict, reasoning-verdict, merchant-screen, " +
        "usc-statute, runtime-eol, threat-intel, " +
        "positioning-snapshot) require a JSON body and return their signed " +
        "answer SYNCHRONOUSLY in the 200 — see the requestBody/response schema " +
        "per operation. usc-statute, runtime-eol, and threat-intel ALSO serve a " +
        "latest-broadcast GET on the same path. Free, no payment: GET /feeds and " +
        "GET /health.",
      "x-post-oracle-quickstart":
        "Raw-HTTP buy of a POST oracle (address-reputation) — two requests:\n\n" +
        "# 1) Unpaid POST -> 402 with the challenge in the `payment-required` response header\n" +
        "curl -sD - -X POST https://x402.payperbyte.io/feeds/address-reputation \\\n" +
        "  -H 'content-type: application/json' \\\n" +
        "  -d '{\"domain\":\"example.com\",\"address\":\"0x1234...abcd\"}'\n\n" +
        "# 2) Pay the challenge with an x402 client (it signs an EIP-3009 USDC\n" +
        "#    transferWithAuthorization), then replay the SAME POST with the signed\n" +
        "#    payload in the `X-PAYMENT` request header:\n" +
        "curl -s -X POST https://x402.payperbyte.io/feeds/address-reputation \\\n" +
        "  -H 'content-type: application/json' \\\n" +
        "  -H 'X-PAYMENT: <base64 payment payload from the x402 client>' \\\n" +
        "  -d '{\"domain\":\"example.com\",\"address\":\"0x1234...abcd\"}'\n\n" +
        "The paid 200 returns {answer, attestation, broadcast} plus an X-BYTE-Attestation " +
        "response header; the settlement tx is in X-PAYMENT-RESPONSE. There are TWO independent " +
        "receipts — verify before acting:\n" +
        "  (1) GATEWAY header (delivery-integrity, on every paid 200): parse X-BYTE-Attestation, " +
        "recompute keccak256(responseBody) === header.payloadHash, AND recover the header signer == " +
        "the attester from GET /.well-known/agent.json .receipt.attester.\n" +
        "  (2) EMBEDDED body `attestation` (per-feed provenance, on the verdict oracles): recompute " +
        "keccak256(canonical(answer)) === attestation.payloadHash, AND recover attestation.signer == " +
        "the feed's OWN published signer (a distinct per-feed key — NOT the gateway attester).\n" +
        "The x402 client does the payment signing — see @payperbyte/sdk@>=0.1.6 " +
        "verifyFromGatewayResponse / GatewayClient, or any x402 v2 client.",
    },
    servers: [{ url: "https://x402.payperbyte.io" }],
    // x402 payment is the auth scheme for every paid operation. Declared as an
    // OpenAPI apiKey-in-header scheme (the x402 v2 `X-PAYMENT` request header) —
    // NOT http/bearer, which would make codegen emit a broken Authorization stub:
    // an unpaid request returns 402 with the payment challenge in the
    // `payment-required` header (x402 v2), the client pays the quoted USDC over
    // x402, and retries with the receipt. `x-payment-info` per operation carries
    // the machine-readable price; this securityScheme documents the flow as a
    // first-class auth mechanism so agent toolchains that key off
    // components.securitySchemes (rather than the custom x-payment-info) can
    // still recognize the endpoints as authenticated-by-payment.
    security: [{ x402Payment: [] }],
    paths: {
      // Free, ungated discovery endpoints. `security: []` overrides the doc-level
      // x402Payment requirement so codegen + scanners see them as NON-payable (no
      // 402, no x-payment-info) — a complete contract without a broken auth stub.
      "/feeds": {
        get: {
          operationId: "getFeedsCatalog",
          summary: "Feed catalog (free) — every feed with price, accepted method(s), and expected size",
          description:
            "The free, ungated catalog. Lists all feeds with computed price, expected payload " +
            "size, provenance, disclaimer category, and accepted HTTP method(s). No x402 payment.",
          tags: ["Discovery"],
          security: [],
          responses: {
            "200": {
              description: "The feed catalog.",
              content: { "application/json": { schema: feedsCatalogSchema } },
            },
          },
        },
      },
      "/health": {
        get: {
          operationId: "getHealth",
          summary: "Liveness check (free)",
          description: "Free liveness/health probe. No x402 payment.",
          tags: ["Discovery"],
          security: [],
          responses: {
            "200": {
              description: "Service health.",
              content: { "application/json": { schema: healthSchema } },
            },
          },
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
      // /feeds/liquidation-stream removed 2026-07-28 — delisted (see
      // POST_ORACLE_IDS above); the route is now a 410-Gone stub (index.ts),
      // so it no longer belongs in the payable contract.
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
      "/feeds/reasoning-verdict": {
        post: {
          operationId: "postReasoningVerdict",
          summary: `Reasoning Verdict — synchronous signed ALLOW/WARN/BLOCK/ABSTAIN verify-before-act verdict from a local LLM (${reasoningVerdict.price} per call)`,
          description: reasoningVerdict.description,
          tags: ["Feeds"],
          security: [{ x402Payment: [] }],
          "x-payment-info": paymentInfo(reasoningVerdict.priceAtomic),
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ORACLE_REQUEST_SCHEMAS["reasoning-verdict"] },
            },
          },
          responses: paidResponses(reasoningVerdictResponseSchema, reasoningVerdict.priceAtomic),
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
        // x402 is NOT a static credential. Declared as apiKey-in-header (the
        // x402 v2 `X-PAYMENT` request header) rather than http/bearer — an
        // http/bearer scheme makes OpenAPI codegen emit a non-functional
        // `Authorization: Bearer <token>` stub that never satisfies the gateway.
        // apiKey-in-header makes codegen emit a settable `X-PAYMENT` header param,
        // which is the actual on-the-wire shape the agent populates per request.
        x402Payment: {
          type: "apiKey",
          in: "header",
          name: "X-PAYMENT",
          description:
            "x402 pay-per-call — NOT a static API key. An unpaid request returns " +
            "HTTP 402 with the payment challenge in the `payment-required` response " +
            "header (x402 v2). An x402 client pays the quoted USDC on " +
            `${networkInfo().label} (network ${config.network}) — a wallet signs an ` +
            "EIP-3009 `transferWithAuthorization` and the facilitator settles " +
            "on-chain — then encodes the signed payment payload and retries with it " +
            "in the `X-PAYMENT` request header. The settlement result returns in the " +
            "`X-PAYMENT-RESPONSE` header. See the per-operation `x-payment-info` for " +
            "the exact price.",
        },
      },
      schemas: {
        CryptoTop100Response: cryptoTop100Schema,
        DefiYieldsResponse: defiYieldsSchema,
        ByteLibraryFeedResponse: byteLibraryFeedSchema,
        SyncOracleResponse: syncOracleResponseSchema,
        RuntimeEolResponse: runtimeEolResponseSchema,
        ThreatIntelResponse: threatIntelResponseSchema,
        EvidencePackResponse: evidencePackResponseSchema,
        UscStatuteResponse: uscStatuteResponseSchema,
        AddressReputationResponse: addressReputationResponseSchema,
        MerchantScreenResponse: merchantScreenResponseSchema,
        PkgVerdictResponse: pkgVerdictResponseSchema,
        SanctionsScreenResponse: sanctionsScreenResponseSchema,
        TokenSafetyResponse: tokenSafetyResponseSchema,
        LiquidationStreamResponse: liquidationStreamResponseSchema,
        PositioningSnapshotResponse: positioningSnapshotResponseSchema,
        ReasoningVerdictResponse: reasoningVerdictResponseSchema,
      },
    },
  };
}
