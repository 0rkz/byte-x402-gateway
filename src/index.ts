/**
 * Byte x402 Gateway
 *
 * HTTP payment gateway that exposes Byte Protocol data feeds using the x402
 * standard. Agents discover feeds via GET /feeds, receive HTTP 402 with payment
 * terms, pay in USDC through the x402 facilitator, and receive data on success.
 *
 * @see https://www.x402.org
 */

import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient, type FacilitatorConfig } from "@x402/core/server";
import type { ResourceServerExtension } from "@x402/core/types";
import { config, feedRegistry, DISCLAIMER_TEXT, networkInfo, FEED_LIVE_URL, FEED_STALE_AFTER_S } from "./lib/config.js";
import { buildOpenApiDoc, ORACLE_REQUEST_SCHEMAS, ORACLE_REQUEST_EXAMPLES, ORACLE_RESPONSE_EXAMPLES } from "./lib/openapi.js";
import { fetchDefiYields } from "./feeds/defi.js";
import { fetchFeedPayload } from "./feeds/generic.js";
import {
  sendAttested,
  sendAttestedRaw,
  attestationEnabled,
  attesterAddress,
  attestationDomain,
} from "./lib/attestation.js";
import { logDelivery } from "./lib/delivery-log.js";

// Solana support — conditionally loaded at startup
let ExactSvmScheme: any = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const svm = require("@x402/svm/exact/server");
  ExactSvmScheme = svm.ExactSvmScheme;
} catch {
  // @x402/svm not installed or import failed — Solana disabled
}

const app = express();

// Trust the cloudflared tunnel as a single upstream proxy. Without this,
// req.protocol returns "http" because the tunnel terminates TLS and forwards
// to localhost over plain HTTP — the x402 payment-required payload's
// `resource.url` then advertises `http://x402.payperbyte.io/...` even though
// the real public scheme is HTTPS. Strict x402 v2 clients reject the scheme
// mismatch ("you said http but my request was https"). Setting trust proxy
// makes Express honor the X-Forwarded-Proto header cloudflared injects, so
// req.protocol returns "https" and the payload URL matches reality.
// Value "1" = trust exactly one hop (the local tunnel) — narrower than
// `true` (trust all) and correct for our single-cloudflared topology.
app.set("trust proxy", 1);

// Don't advertise the framework (no `X-Powered-By: Express` header).
app.disable("x-powered-by");

// ── CORS (browser preflight + x402 header exposure) ────────────────────────
// This is a PUBLIC, credential-less read/pay API: any web origin (a dApp, an
// agent dashboard, a Bazaar/402index browser) may call it, and responses carry
// NO cookies or session state. So we return Access-Control-Allow-Origin: "*" —
// a wildcard, DELIBERATELY not a reflected Origin and WITHOUT
// Access-Control-Allow-Credentials: "*"+credentials is both a spec violation
// and a CSRF footgun, and there is nothing credentialed here to protect.
//
// The entire x402 handshake lives in HTTP headers a cross-origin browser
// fetch() cannot read unless we name them in Access-Control-Expose-Headers.
// Verified against @x402/core (chunk-4CEZVZ3P.mjs): the 402 challenge rides the
// PAYMENT-REQUIRED response header (createHTTPPaymentRequiredResponse), the paid
// settlement receipt rides PAYMENT-RESPONSE (createSettlementHeaders), and the
// client also reads X-PAYMENT-RESPONSE as the v1 fallback (getPaymentSettleResponse).
// We add our own provenance headers X-BYTE-Attestation + X-BYTE-Disclaimer-Category
// and Content-Length so a browser client can size and verify the exact bytes it
// paid for before acting.
//
// Inbound, the x402 client sends its payment signature as X-PAYMENT (v1) or
// PAYMENT-SIGNATURE (v2) — the express adapter reads payment-signature||x-payment
// — so Access-Control-Allow-Headers admits both plus Content-Type and Authorization.
// Preflight (OPTIONS) is answered HERE with 204 BEFORE the trailing-slash
// canonicalizer, the payment gate, the HEAD guard, and the 405/400 layers, so a
// browser's preflight never trips those and the real GET/POST proceeds normally.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Expose-Headers",
    "X-BYTE-Attestation, X-BYTE-Disclaimer-Category, PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, Content-Length",
  );
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-PAYMENT, PAYMENT-SIGNATURE, Authorization",
    );
    res.setHeader("Access-Control-Max-Age", "86400");
    return res.sendStatus(204);
  }
  return next();
});

// Canonicalize a trailing slash on /feeds/<slug>/ → /feeds/<slug>. @x402 builds
// the 402 challenge's `resource.url` from `req.originalUrl`, so a trailing-slash
// request would advertise a NON-canonical resource.url (…/feeds/slug/) that
// differs from the path in openapi.json / agent.json — a strict x402 client's
// resource-binding check then rejects the challenge. Rewrite req.url +
// req.originalUrl so routing AND the challenge are canonical. (A rewrite, NOT a
// 301 — a redirect would break the POST-with-payment replay.) Must precede the
// payment gate. The bare catalog `/feeds/` is left alone (no slug to canonicalize).
app.use((req, _res, next) => {
  // Case-INSENSITIVE on the `/feeds/` prefix: the x402 route layer matches paths
  // case-insensitively, so `/FEEDS/slug/` also reaches a feed handler — emit a
  // canonical lowercase `/feeds/` prefix, else that request would still advertise
  // a non-canonical `resource.url` (…/FEEDS/slug) and a strict client rejects it.
  // The slug (m[1]) and query (m[2]) are preserved as-is; bare `/feeds/` is untouched.
  const m = /^\/feeds\/([^/?#]+)\/+(\?.*)?$/i.exec(req.url);
  if (m) {
    const canonical = "/feeds/" + m[1] + (m[2] ?? "");
    req.url = canonical;
    (req as unknown as { originalUrl: string }).originalUrl = canonical;
  }
  next();
});

// JSON body parsing for the POST oracle proxies. @x402/express documents that
// it requires express.json(); without it req.body is undefined and every
// oracle proxy silently forwarded `{}` upstream regardless of what the agent
// sent. 32 KB cap — honest oracle queries are <1 KB; this stops the
// "POST 100 MB" memory-pressure class (mirrors the feeds' own 16 KB caps).
app.use(express.json({ limit: "32kb" }));

// Per-paid-delivery logging. Attach a finish hook to every request; the logger
// records ONLY paid deliveries — a 200 on a /feeds/<slug> route whose x402
// payment SETTLED (PAYMENT-RESPONSE header present; free broadcasts carry only
// X-BYTE-Attestation and are skipped) — emitting the attribution tuple
// {ts, feed, status, payer, amountUSDC, txHash, nonce} the revenue watcher joins
// on. The finish hook fires after the settle headers are set, so it captures
// them. Throw-free; never blocks a delivery.
app.use((req, res, next) => {
  res.on("finish", () => logDelivery(req, res));
  next();
});

// ---------------------------------------------------------------------------
// x402 Payment Middleware
// ---------------------------------------------------------------------------

/**
 * Route-level payment requirements. Each paid endpoint declares its price,
 * payment scheme, network, and receiving address. The x402 middleware
 * intercepts requests and returns HTTP 402 with these terms when no valid
 * payment receipt is present.
 */
/**
 * Build the accepts array — EVM always, Solana if configured.
 *
 * Uses explicit AssetAmount object for `price` instead of the "$0.001"
 * dollar-string syntax. The dollar-string path requires the SDK's
 * default-asset registry to know "what stablecoin is USD on chain X" — and
 * Arbitrum Sepolia isn't upstreamed into that registry, so a string price
 * would throw at startup. The AssetAmount form bypasses the registry by
 * naming the token contract + atomic amount explicitly; works on any EVM
 * chain regardless of upstream registry coverage.
 *
 * `extra.name` / `extra.version` give the facilitator the EIP-712 domain
 * fields it needs to verify the EIP-3009 signature (Centre USDC uses
 * `"USD Coin"` / `"2"`).
 */
function buildAccepts(priceAtomic: string) {
  const accepts: any[] = [
    {
      scheme: "exact",
      network: config.network,
      payTo: config.payTo,
      price: {
        asset: config.usdcAddress,
        amount: priceAtomic,
        extra: {
          name: config.usdcDomainName,
          version: config.usdcDomainVersion,
        },
      },
    },
  ];

  // Add Solana payment option if wallet is configured
  if (config.solanaPayTo && ExactSvmScheme) {
    accepts.push({
      scheme: "exact",
      price: `$${Number(priceAtomic) / 1_000_000}`,
      network: config.solanaNetwork,
      payTo: config.solanaPayTo,
    });
  }

  return accepts;
}

// Every feed in feedRegistry is wired into the payment middleware with its
// per-feed price (computed from expectedSizeBytes). POST oracles carry a
// request body; broadcast/scheduled feeds are GET. Some publisher-backed
// oracles offer both (subscribe-then-listen via GET indexer proxy AND
// synchronous request-response via POST proxy) — see usc-statute.
// evidence-pack and liquidation-stream DELISTED 2026-07-28 (founder-approved,
// in-session — see the delist comments in lib/config.ts feedRegistry and the
// 410-Gone stubs below) — removed from POST_ORACLES so neither the payment
// gate nor the body-validation middleware treats them as live.
const POST_ORACLES = new Set(["address-reputation", "pkg-verdict", "sanctions-screen", "positioning-snapshot", "reasoning-verdict", "runtime-eol", "threat-intel", "merchant-screen"]);

// ── Bazaar service metadata (PROD-15) ───────────────────────────────────────
// CDP Bazaar catalogs `resource.serviceName` / `resource.tags` from the
// paymentPayload's `resource` object, which the x402 client copies verbatim
// from the 402 challenge's `resource` (ResourceInfo — see @x402/core client
// `resource: paymentRequired.resource`). @x402 2.13.0's RouteConfig has no
// serviceName/tags fields and the HTTP server builds ResourceInfo from
// url/description/mimeType only, so every Bazaar row showed serviceName:null /
// tags:null — browsing agents skip null-named entries and brand search returns
// zero. Fix: each route declares a service-metadata extension (below, merged in
// getExtensions) and the registered serviceMetadataExtension copies it onto the
// challenge's resource object at 402-build time. Limits enforced downstream by
// @x402/core's ResourceInfoSchema + the facilitator's
// sanitizeResourceServiceMetadata (soft-drop): serviceName ≤32 printable-ASCII
// chars; tags ≤5 entries × ≤32 printable-ASCII chars.
const SERVICE_METADATA_KEY = "payperbyte-service-metadata";
const SERVICE_NAME = "PayPerByte";

// Per-feed Bazaar search tags. Curated for the decision oracles; every other
// feed derives [brand, id, disclaimerCategory, provenance] so each row is still
// individually searchable. Self-referential only — no competitor names; no
// correctness claims ("signed-verdict" = the answer is signed, not correct).
const FEED_TAGS: Record<string, string[]> = {
  "sanctions-screen": ["payperbyte", "sanctions-screen", "ofac", "compliance", "signed-verdict"],
  "address-reputation": ["payperbyte", "address-reputation", "payments-risk", "go-no-go", "signed-verdict"],
  "pkg-verdict": ["payperbyte", "pkg-verdict", "supply-chain", "install-gate", "signed-verdict"],
  "reasoning-verdict": ["payperbyte", "reasoning-verdict", "verify-before-act", "local-llm", "signed-verdict"],
  "merchant-screen": ["payperbyte", "merchant-screen", "storefront-risk", "clone-detect", "signed-verdict"],
};

/** Tags for a feed's Bazaar row — curated when listed above, else derived from
 *  the registry entry (all values are ≤32-char printable ASCII by construction). */
function feedTags(feedId: string): string[] {
  const curated = FEED_TAGS[feedId];
  if (curated) return curated;
  const f = feedRegistry.find((x) => x.id === feedId);
  return f ? ["payperbyte", f.id, f.disclaimerCategory, f.provenance] : ["payperbyte", feedId];
}

/**
 * Server extension that copies each route's declared service metadata onto the
 * 402 challenge's `resource` object (ResourceInfo declares both fields). Core
 * only guards `accepts` after extension enrichment
 * (assertAcceptsAllowlistedAfterExtensionEnrich) — `resource` is the documented
 * carrier for bazaar service metadata (see sanitizeResourceServiceMetadata in
 * @x402/extensions, "Service Metadata on `resource`"). Returns undefined so
 * nothing extra merges into extensions[key]; the declaration itself already
 * rides the 402 as visible (honest) metadata. Registered in
 * setupPaymentMiddleware, before the middleware is built.
 */
const serviceMetadataExtension: ResourceServerExtension = {
  key: SERVICE_METADATA_KEY,
  enrichPaymentRequiredResponse: async (declaration, context) => {
    const meta = declaration as { serviceName?: string; tags?: string[] } | undefined;
    const resource = context.paymentRequiredResponse?.resource;
    if (resource && meta) {
      if (meta.serviceName) resource.serviceName = meta.serviceName;
      if (Array.isArray(meta.tags) && meta.tags.length > 0) resource.tags = meta.tags;
    }
    return undefined;
  },
};

// Bazaar discovery extension per route. Output examples per feed shape — enough
// for checkIfBazaarNeeded() in @x402/express to detect the extension and
// auto-register bazaarResourceServerExtension on the server; the decision
// oracles additionally carry a response EXCERPT (ORACLE_RESPONSE_EXAMPLES) so a
// browsing agent sees the verdict envelope + receipt shape before paying.
// See @x402/extensions/bazaar for the full schema.
//
// Note: the input config OMITS `method` — it's inferred from the route key
// (`GET /...` vs `POST /...`) and filled in later by
// bazaarResourceServerExtension.enrichDeclaration. The `bodyType` field is
// the discriminant between Query (GET/HEAD/DELETE) and Body (POST/PUT/PATCH)
// variants of the union.
function getExtensions(feedId: string, isPost: boolean): Record<string, unknown> {
  // Service metadata (PROD-15) rides every route's declared extensions; the
  // registered serviceMetadataExtension copies it onto the 402's resource.
  const serviceMetadata = { serviceName: SERVICE_NAME, tags: feedTags(feedId) };
  if (isPost) {
    return {
      ...declareDiscoveryExtension({
        bodyType: "json",
        // Advertise the real request body in the 402 Bazaar challenge so an agent
        // knows what to POST (was hardcoded {} → agents paid then 400'd blind).
        // `input` → bazaar.info.input.body must be a concrete EXAMPLE (it is
        // validated AGAINST the schema; a schema-object-as-example fails its own
        // schema and strict Bazaar/CDP validators then DROP the oracle). `inputSchema`
        // → bazaar.schema.input.body is the MACHINE-READABLE JSON Schema. Both must
        // be populated and mutually consistent.
        input: ORACLE_REQUEST_EXAMPLES[feedId] ?? {},
        inputSchema: ORACLE_REQUEST_SCHEMAS[feedId] ?? { properties: {} },
        output: { example: ORACLE_RESPONSE_EXAMPLES[feedId] ?? { feed: feedId } },
      }),
      [SERVICE_METADATA_KEY]: serviceMetadata,
    };
  }
  return {
    ...declareDiscoveryExtension({
      output: { example: { feed: feedId } },
    }),
    [SERVICE_METADATA_KEY]: serviceMetadata,
  };
}

// 402-CHALLENGE description overrides (2026-07-29 root cause): clients echo the
// challenge's `resource` back inside their payment envelope, and CDP's verify
// schema 400s the whole payload when that echo is too large — merchant-screen's
// 924-char catalog description made every paid replay fail verify SILENTLY
// ("'paymentPayload' is invalid"). The full description INCLUDING the founder-
// approved retention/egress disclosure stays on /feeds, /openapi.json,
// /.well-known/x402.json and agent.json unchanged; the challenge carries a
// compact form that POINTS to it. Keep any entry here well under ~300 chars.
const PAYMENT_CHALLENGE_DESCRIPTION: Record<string, string> = {
  // Wording: FD-drafted, founder-approved verbatim 2026-07-29 — both material
  // disclosures inline at the pay decision, pointer for the full text.
  "merchant-screen":
    "Pre-settlement merchant screen: signed ALLOW/WARN/BLOCK on (domain, payTo, price) before you settle. Queries are logged (domain, payTo, price); screening is not covert — the merchant sees the probe. Full disclosure: https://x402.payperbyte.io/feeds",
  // 2026-08-13: the KYA repositioning (config.ts, founder GO 08-12) pushed the
  // catalog descriptions past the ~300-char challenge budget (555/503 chars),
  // and reasoning-verdict (422) predated the rule. Compact forms below keep the
  // scope/advisory clauses inline at the pay decision; the full copy stays on
  // /feeds, /openapi.json and agent.json unchanged.
  "address-reputation":
    "Know-Your-Agent counterparty screening — reputation pillar. Signed ALLOW/WARN/BLOCK verdict on (domain, receiving address, amount, chain) before you release USDC. Screens the counterparty tuple you supply — not the calling agent's identity. Full method + scope: https://x402.payperbyte.io/feeds",
  "sanctions-screen":
    "Know-Your-Agent counterparty screening — sanctions pillar. Signed OFAC SDN + Consolidated screen on an address or name, pinned to the exact list-state (date + sha256). Screens the counterparty you supply — not the calling agent's identity. Full scope: https://x402.payperbyte.io/feeds",
  "reasoning-verdict":
    "Verify-before-act risk oracle: POST an action context and get a signed ALLOW/WARN/BLOCK/ABSTAIN verdict + 0-100 score + reasons from a LOCAL model (no data egress). Advisory: the receipt proves provenance/integrity, not correctness. Full method: https://x402.payperbyte.io/feeds",
};

const paymentRoutes: Record<string, any> = {};
for (const feed of feedRegistry) {
  const accepts = buildAccepts(feed.priceAtomic);
  if (POST_ORACLES.has(feed.id)) {
    paymentRoutes[`POST ${feed.endpoint}`] = {
      accepts,
      description: PAYMENT_CHALLENGE_DESCRIPTION[feed.id] ?? feed.description,
      // Paid 200 is JSON — declare it so the 402 challenge's mimeType isn't "".
      mimeType: "application/json",
      extensions: getExtensions(feed.id, true),
    };
  }
  if (feed.publisher) {
    // Publisher-backed feeds also serve the latest broadcast via GET — gate it.
    paymentRoutes[`GET ${feed.endpoint}`] = {
      accepts,
      description: feed.description,
      // Paid 200 is JSON — declare it so the 402 challenge's mimeType isn't "".
      mimeType: "application/json",
      extensions: getExtensions(feed.id, false),
    };
  } else if (!POST_ORACLES.has(feed.id)) {
    // Bespoke non-oracle feeds (crypto-top100, defi-yields) are GET.
    paymentRoutes[`GET ${feed.endpoint}`] = {
      accepts,
      description: feed.description,
      // Paid 200 is JSON — declare it so the 402 challenge's mimeType isn't "".
      mimeType: "application/json",
      extensions: getExtensions(feed.id, false),
    };
  }
}

// Challenge-size ratchet (the 2026-07-29 class): clients echo the challenge's
// resource back inside their payment envelope, and CDP's verify schema 400s an
// oversized payload SILENTLY — an over-budget description here loses the sale,
// not just the listing (Bazaar's own quality cap is 500). Warn, don't throw: a
// copy edit must never down the gateway, but it must never ship quietly either.
for (const [route, routeCfg] of Object.entries(paymentRoutes)) {
  const descLen = (routeCfg.description ?? "").length;
  if (descLen > 300) {
    console.warn(
      `[challenge-desc] ${route}: description is ${descLen} chars (>300 budget) — ` +
        `add a PAYMENT_CHALLENGE_DESCRIPTION override (2026-07-29 verify-400 class)`,
    );
  }
}

/**
 * Build the x402 resource server that verifies payment receipts.
 * Uses the HTTPFacilitatorClient for remote verification and the
 * ExactEvmScheme for EVM-compatible payment settlement.
 */
// Payment middleware setup is deferred — facilitator may not be reachable.
// Gateway runs in discovery mode (free feeds) until facilitator DNS resolves.
//
// It is built asynchronously (must await the facilitator supported-kinds
// fetch), but Express runs handlers in registration order — app.use()'ing it
// after the route handlers would never gate them. Fix: a synchronous
// pass-through wrapper is mounted before all routes (see below) and delegates
// here once the real middleware is ready.
let activePaymentMiddleware: ((req: any, res: any, next: any) => void) | null = null;

/**
 * Normalize a request path the SAME way the real x402 matcher does
 * (@x402/core normalizePath + case-insensitive route regex). Express runs with
 * loose routing (no strict/case-sensitive routing set), so `/feeds/defi-yields/`,
 * `/Feeds/defi-yields`, `/FEEDS/DEFI-YIELDS` and `%2F`-encoded forms all route to
 * the canonical paid handler. Without this normalization the fail-closed stub's
 * raw exact lookup misses those variants → the handler serves data FREE during
 * the facilitator-down window. Decode %2F, collapse duplicate slashes, strip the
 * trailing slash, lowercase.
 */
function normalizeGatePath(p: string): string {
  let s = p;
  try {
    s = decodeURIComponent(s);
  } catch {
    /* keep raw on a malformed escape */
  }
  s = s.replace(/\/{2,}/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s.toLowerCase();
}

/** True iff this method+path (normalized) is one of the payment-gated routes. */
function isPaidRoute(req: any): boolean {
  return Boolean(
    paymentRoutes[`${String(req.method).toUpperCase()} ${normalizeGatePath(req.path)}`],
  );
}

/** `/feeds/<slug>` (normalized) → slug, else null. */
function oracleSlug(p: string): string | null {
  const m = /^\/feeds\/([^/]+)$/.exec(normalizeGatePath(p));
  return m ? m[1] : null;
}

/** Keys in `required` that are absent/empty in `body`. Treats undefined, null,
 *  blank strings, and empty arrays as missing — matching the schemas' own
 *  minLength/minItems intent (an empty string/array screens/judges NOTHING). */
function missingRequired(required: string[], body: Record<string, unknown>): string[] {
  return required.filter((k) => {
    const v = body[k];
    if (v === undefined || v === null) return true;
    if (typeof v === "string" && v.trim() === "") return true;
    if (Array.isArray(v) && v.length === 0) return true;
    return false;
  });
}

/**
 * Enforce ONLY a schema's declared contract (`required` / `anyOf`). Returns null
 * when valid, else a human detail string. Feeds with neither constraint (e.g.
 * positioning-snapshot) accept {} unchanged — defaults are intentional there.
 * Deliberately minimal (no full JSON-Schema validator): it closes the "pay to
 * query nothing" gap without risking false rejects of advertised shapes.
 */
function validateOracleBody(
  schema: Record<string, unknown> | undefined,
  body: unknown,
): string | null {
  if (!schema) return null;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return "request body must be a JSON object";
  }
  const b = body as Record<string, unknown>;
  // Unconditionally-required fields first (clearest error), then anyOf groups.
  const required = schema.required as string[] | undefined;
  if (Array.isArray(required) && required.length > 0) {
    const missing = missingRequired(required, b);
    if (missing.length > 0) {
      return `missing required field(s): ${missing.join(", ")}`;
    }
  }
  const anyOf = schema.anyOf as Array<{ required?: string[] }> | undefined;
  if (Array.isArray(anyOf) && anyOf.length > 0) {
    const ok = anyOf.some(
      (branch) =>
        missingRequired(Array.isArray(branch.required) ? branch.required : [], b).length === 0,
    );
    if (!ok) {
      const opts = anyOf.map((br) => `(${(br.required ?? []).join(" + ")})`).join(" or ");
      return `at least one of these field set(s) is required: ${opts}`;
    }
  }
  return null;
}

/** The HTTP verb(s) a feed accepts, as a display string ("GET", "POST", or
 *  "POST, GET" for dual-pattern feeds) — mirrors the live paymentRoutes logic
 *  (POST iff a POST oracle; GET iff publisher-backed broadcast OR bespoke
 *  non-oracle) so the /feeds catalog tells a dev which method to use without
 *  guessing. Self-contained (POST_ORACLES + publisher) — no external deps. */
function feedMethods(feed: { id: string; publisher?: string }): ("GET" | "POST")[] {
  const ms: ("GET" | "POST")[] = [];
  const isOracle = POST_ORACLES.has(feed.id);
  // GET first to match the 405 `Allow` header ordering (GET, POST). Returns a
  // machine-readable array: dual-pattern feeds → ["GET","POST"], single → ["GET"]
  // or ["POST"] (a comma-string forced clients to parse it).
  if (feed.publisher || !isOracle) ms.push("GET");
  if (isOracle) ms.push("POST");
  return ms;
}

// ── x402 forensics tiering (2026-07-29) ────────────────────────────────────
// Two tiers, deliberately not one switch:
//   HOT (always on)  — payment verify rejections, plus any outbound re-challenge
//                      .error that is NOT boilerplate. A rejection nobody can
//                      see is a rejection nobody can fix; these are the lines
//                      that turn a silent 402 loop into a five-minute answer.
//   VERBOSE (opt-in) — inbound payment-header presence + envelope structure.
//                      One or two lines on EVERY gated POST, so they are pure
//                      journal weight once an investigation closes.
// Neither tier logs a header value, a signature, or key material.
/**
 * Verbose tier, read PER REQUEST rather than once at module load: turning it on
 * must not require restarting the very gateway you are trying to observe. A
 * restart destroys the in-flight incident and re-races the facilitator startup,
 * so a module-load-once read makes the flag useless exactly when it is needed.
 */
function forensicVerbose(): boolean {
  return ["1", "true", "yes", "on"].includes(
    (process.env.X402_FORENSIC_VERBOSE || "").trim().toLowerCase(),
  );
}

// True only once the findMatchingRequirements probe has actually installed.
// The static suppression of core's "No matching payment requirements" echo is
// valid ONLY while that probe is live: if a core rename drops it, the HOT
// NO-MATCH line is guarded off AND an unconditional static suppression would
// keep the sniffer quiet about core's echo too — leaving a no-match rejection
// invisible on BOTH paths, the exact silence these forensics exist to prevent.
// Gating on this flag makes the static path degrade the same way the dynamic
// (per-request stamped) path already does.
let matchProbeInstalled = false;

// ALWAYS boilerplate, independent of probe state: core emits "Payment required"
// whenever the payment header is absent or undecodable, and warns about the
// undecodable case itself — there is nothing for us to add either way.
const ALWAYS_BOILERPLATE_ERRORS = new Set(["Payment required"]);

// Boilerplate ONLY while the match probe is installed — core echoes this string
// into .error on precisely the path our NO-MATCH line already reports in full.
const MATCH_PROBE_ECHO = "No matching payment requirements";

// Per-request record of the invalidReasons the HOT verify logger already
// printed. `invalidReason` is a free-form string in core, not an enum, so it
// cannot be listed statically — it is stamped on the Express req (which core
// hands back through transportContext.request.adapter.req) and read again by
// the outbound sniffer on that same request. Request-scoped, so concurrent
// payers never read each other's reasons.
const HOT_LOGGED_REASONS = Symbol.for("byte.x402.hotLoggedReasons");

/** Record an invalidReason the HOT tier printed, so the sniffer skips its echo. */
function markHotLogged(ctx: any, reason: unknown): void {
  if (typeof reason !== "string" || reason === "") return;
  const req = ctx?.request?.adapter?.req;
  if (!req || typeof req !== "object") return;
  const seen: unknown = req[HOT_LOGGED_REASONS];
  if (seen instanceof Set) seen.add(reason);
  else req[HOT_LOGGED_REASONS] = new Set([reason]);
}

/** True when an outbound challenge .error carries nothing the HOT tier missed. */
function isBoilerplateChallengeError(err: unknown, req: any): boolean {
  if (err === null || err === undefined) return true; // no .error field at all
  if (typeof err !== "string") return false; // an unexpected shape IS a finding
  const s = err.trim();
  if (s === "") return true;
  if (ALWAYS_BOILERPLATE_ERRORS.has(s)) return true;
  // Suppress core's echo of our own NO-MATCH line only while we are actually
  // emitting that line. If the probe is gone, let the echo through: a duplicated
  // line costs nothing, a silently dropped rejection costs an investigation.
  if (s === MATCH_PROBE_ECHO) return matchProbeInstalled;
  const seen: unknown = req?.[HOT_LOGGED_REASONS];
  return seen instanceof Set && seen.has(s);
}

/**
 * Build the x402 payment middleware. Returns true on success, false (rather
 * than throwing) if the facilitator is unreachable — so the caller can retry.
 */
async function setupPaymentMiddleware(): Promise<boolean> {
  // Reset per ATTEMPT, not per process. Every call builds a fresh resource
  // server, and the retry loop calls this until one succeeds — so an attempt
  // that installed the probe and then failed further down (or before a later
  // attempt whose core no longer exposes the seam) must not leave the flag
  // asserting a probe the live server does not have. Stale-true is the fail-open
  // direction: it would suppress core's echo with no HOT line behind it.
  matchProbeInstalled = false;
  try {
    // Facilitator auth is OFF by default (xpay self-hosted needs none), so this
    // is byte-for-byte the previous `new HTTPFacilitatorClient({ url })`. Setting
    // FACILITATOR_AUTH=cdp attaches Coinbase CDP request-auth — flip it together
    // with FACILITATOR_URL to the CDP facilitator to unblock §3 (Bazaar/CDP).
    const facilitatorConfig: FacilitatorConfig = { url: config.facilitatorUrl };
    if (config.facilitatorAuth === "cdp") {
      // Lazy, variable-specifier import: keeps `tsc --noEmit` green while
      // @coinbase/x402 is not yet installed (the gate is off in every shipped
      // config). Before flipping the gate: `npm i @coinbase/x402` and confirm the
      // CDP key env-var names + the export against the installed version
      // (current shape: `facilitator.createAuthHeaders`).
      const pkg: string = "@coinbase/x402";
      const cdp: any = await import(pkg);
      const createAuthHeaders = cdp?.facilitator?.createAuthHeaders ?? cdp?.createAuthHeaders;
      if (typeof createAuthHeaders !== "function") {
        throw new Error(
          "FACILITATOR_AUTH=cdp but @coinbase/x402 exposed no createAuthHeaders — " +
            "run `npm i @coinbase/x402` and verify the export (expected facilitator.createAuthHeaders).",
        );
      }
      facilitatorConfig.createAuthHeaders = createAuthHeaders;
      console.log("[x402-gateway] CDP facilitator auth ENABLED (createAuthHeaders attached)");
    }
    const facilitator = new HTTPFacilitatorClient(facilitatorConfig);
    const server = new x402ResourceServer(facilitator)
      .register(config.network, new ExactEvmScheme());

    // PROD-15: copy each route's declared serviceName/tags onto the 402's
    // resource object (must be registered before the middleware is built; the
    // "bazaar" key is still auto-registered separately by @x402/express).
    server.registerExtension(serviceMetadataExtension);

    if (ExactSvmScheme && config.solanaPayTo) {
      server.register(config.solanaNetwork, new ExactSvmScheme());
      console.log(`[x402-gateway] Solana payments enabled: ${config.solanaNetwork}`);
    }

    // Fetch supported payment kinds from the facilitator. Without this the
    // resource server has no supported-kinds cache, so buildPaymentRequirements
    // throws "Facilitator does not support exact on eip155:421614" on every
    // payable request. If the facilitator is unreachable at startup this
    // throws — caught below, reported as false, and retried.
    await server.initialize();

    // FORENSICS — HOT tier (FD spec 2026-07-29): the middleware re-402s payment
    // rejections SILENTLY — core carries VerifyError.invalidReason/invalidMessage/
    // payer and none of it ever reached the journal, which twice on 07-29 turned
    // five-minute questions into investigations. Wrap the two route-specific
    // rejection points (requirement matching + verify) and log UNCONDITIONALLY on
    // the failure branch — an empty reason is itself a finding, so no truthiness
    // guard, and never behind X402_FORENSIC_VERBOSE.
    // Nothing sensitive is logged: payer/amounts are public on-chain data;
    // signatures and key material never appear.
    //
    // Existence-guarded because these are @x402/core INTERNALS, not public API.
    // Unguarded, a core rename makes `.bind` throw right here — inside a try
    // whose catch reports "middleware not ready", so every paid route would
    // fail closed (503) on the strength of a purely diagnostic wrapper.
    // Forensics never takes the revenue path down: if the seam moves we log
    // that the probe was lost and leave payment handling untouched.
    //
    // GAP CLOSED (2026-08-01, board #8 — founder-gated, because it changes
    // revenue-path error handling): the `typeof` guards below prove each seam
    // EXISTS; they cannot prove it is WRITABLE. Against a read-only property the
    // ASSIGNMENT ITSELF throws under "use strict" (tsc emits it under `strict:
    // true`), and before this change that throw fell through to the outer catch
    // and failed EVERY paid route closed (503) on the strength of a purely
    // diagnostic wrapper — precisely what the paragraph above says must never
    // happen. Each probe now installs inside its OWN try/catch and degrades to a
    // warn, so a seam that moves or hardens costs forensics and nothing else.
    //
    // Deliberately NOT one try/catch around both: a throw while installing the
    // first would skip the second, turning one lost probe into two lost probes.
    // The catches swallow by design — that is the whole point — and each is
    // paired with the pre-existing "probe NOT installed" line so a degraded
    // build still says so out loud rather than going quiet.
    {
      const srv = server as any;

      try {
        if (typeof srv.findMatchingRequirements === "function") {
          const origMatch = srv.findMatchingRequirements.bind(server);
          const matchProbe = (avail: any[], payload: any) => {
            const m = origMatch(avail, payload);
            if (!m) {
              const auth = payload?.payload?.authorization ?? {};
              console.warn(
                `[x402-verify] NO-MATCH payer=${auth.from ?? "?"} sent={scheme:${payload?.scheme},network:${payload?.network},v:${payload?.x402Version}} ` +
                  `available=${JSON.stringify((avail ?? []).map((a: any) => ({ scheme: a?.scheme, network: a?.network, amount: a?.amount, asset: a?.asset, payTo: a?.payTo })))}`,
              );
            }
            return m;
          };
          srv.findMatchingRequirements = matchProbe;
          // Claim the probe only once the assignment has demonstrably TAKEN, by
          // reading the property back. `typeof === "function"` proves the seam
          // EXISTS, not that it is WRITABLE, and the two failure modes differ: a
          // read-only property throws under "use strict" (which tsc emits today
          // under `strict: true`) but would silently no-op without it. Setting the
          // flag before the assignment caught neither; setting it after catches
          // only the throw. Reading it back catches both, so the flag can never
          // assert a probe that is not installed — the fail-open it exists to close.
          matchProbeInstalled = srv.findMatchingRequirements === matchProbe;
        }
      } catch (e) {
        // Class only, never the message: an assignment TypeError can quote the
        // property and surrounding source, and this file's logging discipline is
        // class-only everywhere (see upstreamErrorClass).
        matchProbeInstalled = false;
        console.warn(
          `[x402-verify] match probe install FAILED: class=${upstreamErrorClass(e)} — ` +
            "payment matching is UNAFFECTED (core's own method is left in place).",
        );
      }
      if (!matchProbeInstalled) {
        console.warn(
          "[x402-verify] probe NOT installed: x402ResourceServer.findMatchingRequirements is " +
            "missing or not writable — payment matching is UNAFFECTED, but NO-MATCH " +
            "rejections are silent again (core's own echo is no longer suppressed).",
        );
      }

      // Read back like the match probe, and for the same reason. Previously this
      // side only had an `else` on the `typeof` check, so a present-but-unwritable
      // verifyPayment reported nothing at all: the else never ran, and under a
      // non-strict build the assignment would no-op silently. Verify has no
      // static-suppression flag to corrupt, so the cost there is a silent probe
      // rather than a fail-open — still the failure this block exists to prevent.
      let verifyProbeInstalled = false;
      try {
        if (typeof srv.verifyPayment === "function") {
          const origVerify = srv.verifyPayment.bind(server);
          const verifyProbe = async (payload: any, req: any, ext?: unknown, ctx?: any) => {
            const r = await origVerify(payload, req, ext, ctx);
            if (!r || r.isValid === false) {
              const auth = payload?.payload?.authorization ?? {};
              // Stamp the reason before the challenge is written, so the outbound
              // sniffer can tell core's echo of THIS line from a new finding.
              markHotLogged(ctx, r?.invalidReason);
              console.warn(
                `[x402-verify] REJECTED route=${ctx?.request?.path ?? "?"} reason=${JSON.stringify(r?.invalidReason ?? null)} ` +
                  `message=${JSON.stringify(r?.invalidMessage ?? null)} payer=${r?.payer ?? auth.from ?? "?"} ` +
                  `matched={scheme:${req?.scheme},network:${req?.network},amount:${req?.amount},asset:${req?.asset},payTo:${req?.payTo}} ` +
                  `sent={to:${auth.to ?? "?"},value:${auth.value ?? "?"},validBefore:${auth.validBefore ?? "?"}}`,
              );
            }
            return r;
          };
          srv.verifyPayment = verifyProbe;
          verifyProbeInstalled = srv.verifyPayment === verifyProbe;
        }
      } catch (e) {
        verifyProbeInstalled = false;
        console.warn(
          `[x402-verify] verify probe install FAILED: class=${upstreamErrorClass(e)} — ` +
            "verification is UNAFFECTED (core's own method is left in place).",
        );
      }
      if (!verifyProbeInstalled) {
        console.warn(
          "[x402-verify] probe NOT installed: x402ResourceServer.verifyPayment is missing or " +
            "not writable — verification is UNAFFECTED, but verify rejections are silent again.",
        );
      }
    }

    activePaymentMiddleware = paymentMiddleware(paymentRoutes, server, undefined, undefined, false);
    return true;
  } catch (e) {
    console.warn(`[x402-gateway] Payment middleware not ready: ${e instanceof Error ? e.message : e}`);
    return false;
  }
}

/**
 * Bring the payment middleware up, retrying until the facilitator is reachable.
 *
 * This is the fix for the 402-flow regression: setup ran exactly once at
 * startup, so if the gateway lost the boot race against the facilitator's HTTP
 * listener it failed once and then served every paid feed FREE forever. It now
 * retries — and, critically, paid routes fail closed (503) until it succeeds
 * (see the gate below), so paid data is never given away.
 */
async function setupPaymentMiddlewareWithRetry(): Promise<void> {
  const RETRY_DELAY_MS = 15_000;
  let attempt = 0;
  while (!activePaymentMiddleware) {
    attempt += 1;
    if (await setupPaymentMiddleware()) {
      console.log(`[x402-gateway] Payment middleware active (attempt ${attempt})`);
      return;
    }
    console.warn(
      `[x402-gateway] paid feeds FAIL CLOSED (503) until the facilitator is reachable — ` +
        `retrying in ${RETRY_DELAY_MS / 1000}s (attempt ${attempt})`,
    );
    await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
  }
}

// Non-blocking — facilitator trouble must not prevent the free discovery
// endpoints from starting.
setupPaymentMiddlewareWithRetry().catch(() => {});

// HEAD payment-bypass guard — MUST precede the payment gate AND the routes.
// Express maps HEAD→GET at the router, but the x402 paymentMiddleware only gates
// the exact GET/POST method keys (paymentRoutes), so a HEAD on a paid feed skips
// payment yet still runs the GET handler — emitting a signed X-BYTE-Attestation
// receipt + content-length for FREE on all GET feeds. 405 HEAD on any paid
// resource so a receipt is NEVER produced without payment. Free routes (catalog,
// health, well-known) are not in paymentRoutes and pass through untouched.
app.use((req, res, next) => {
  if (req.method === "HEAD") {
    const p = normalizeGatePath(req.path);
    const methods = ["GET", "POST"].filter((m) => paymentRoutes[`${m} ${p}`]);
    if (methods.length > 0) {
      res.setHeader("Allow", methods.join(", "));
      return res.status(405).json({
        error: "method_not_allowed",
        detail:
          "HEAD is not supported on paid feed routes — it would leak a signed " +
          "receipt without payment. Use a paid GET/POST.",
      });
    }
  }
  return next();
});

// Payment gate — MUST be registered before any route so Express runs it first.
//   middleware ready       -> delegate to the real x402 payment middleware
//   not ready + paid route -> 503 FAIL CLOSED (never serve paid data free)
//   not ready + free route -> next()
// The previous version next()'d unconditionally when the middleware was not
// ready, which served every paid feed for free if the facilitator was missed
// at startup. That silent revenue hole is the regression this fixes.
app.use((req, res, next) => {
  if (req.method === "POST" && isPaidRoute(req)) {
    const ps = req.headers["payment-signature"];

    // FORENSICS — VERBOSE tier (2026-07-29, merchant-screen 402-loop): what
    // payment header (if any) actually ARRIVES on a gated POST, and how the
    // envelope is shaped, upstream of the middleware. extractPayment reads
    // PAYMENT-SIGNATURE and falls through to the unpaid branch silently when it
    // is absent OR undecodable, which without these lines is indistinguishable
    // from an unpaid probe. They fire on every gated POST though, so once an
    // investigation closes they are noise: opt in with X402_FORENSIC_VERBOSE=1.
    // Lengths and key names only — never a header value, signature, or key.
    if (forensicVerbose()) {
      const xp = req.headers["x-payment"];
      console.log(
        `[x402-inbound] POST ${req.path} payment-signature=${ps ? `present(${String(ps).length}b)` : "ABSENT"} x-payment=${xp ? `present(${String(xp).length}b)` : "absent"}`,
      );
      // Inline decode diagnostic (structure only — never signature/key values):
      // mirrors extractPayment's regex+parse to show exactly where extraction dies.
      if (ps) {
        try {
          const raw = String(ps);
          const b64ok = /^[A-Za-z0-9+/]*={0,2}$/.test(raw);
          const dec: unknown = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
          // Shape-guard before keying it: a bare JSON scalar decodes fine and
          // then throws in Object.keys — which the catch below would report as
          // "decode FAILED" when the decode in fact succeeded. Say what's true.
          if (dec === null || typeof dec !== "object") {
            console.warn(
              `[x402-inbound]   decode: b64regex=${b64ok} NOT-AN-OBJECT (${dec === null ? "null" : typeof dec})`,
            );
          } else {
            const d = dec as Record<string, unknown>;
            const topKeys = Object.keys(d);
            const extraKeys = topKeys.filter((k) => !["x402Version", "scheme", "network", "payload"].includes(k));
            const payload = d.payload;
            console.log(
              `[x402-inbound]   decode: b64regex=${b64ok} keys=${JSON.stringify(topKeys)} v=${d.x402Version} scheme=${d.scheme} network=${d.network} ` +
                `payloadKeys=${JSON.stringify(payload && typeof payload === "object" ? Object.keys(payload) : [])} ` +
                `extraSizes=${JSON.stringify(extraKeys.map((k) => [k, String(JSON.stringify(d[k])).length]))}`,
            );
          }
        } catch (e) {
          console.warn(`[x402-inbound]   decode FAILED: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
    }

    // FORENSICS — HOT tier: the middleware's silent catch puts the real
    // exception message into the re-challenge's .error field and logs NOTHING;
    // that field is what identified the CDP schema rejection on 07-29, so it
    // stays live regardless of X402_FORENSIC_VERBOSE. Sniff it off the response
    // header, but print only what the HOT verify logger did not already print —
    // core echoes its own invalidReason (and two fixed boilerplate strings) into
    // this field on every unpaid retry, which would bury the line that matters.
    // Installed only when a payment header actually arrived: with no header the
    // challenge is unconditional boilerplate. Sniff only, never interfere.
    if (ps) {
      const origSetHeader = res.setHeader.bind(res);
      (res as any).setHeader = (name: string, value: unknown) => {
        if (String(name).toLowerCase() === "payment-required") {
          try {
            const d = JSON.parse(Buffer.from(String(value), "base64").toString("utf8"));
            if (!isBoilerplateChallengeError(d?.error, req)) {
              console.warn(`[x402-inbound]   OUT .error=${String(JSON.stringify(d.error)).slice(0, 2000)}`);
            }
          } catch {
            /* sniff only — never interfere */
          }
        }
        return origSetHeader(name as string, value as never);
      };
    }
  }
  if (activePaymentMiddleware) return activePaymentMiddleware(req, res, next);
  if (isPaidRoute(req)) {
    return res.status(503).json({
      error: "payment_unavailable",
      detail:
        "x402 payment facilitator is not reachable yet — paid feeds are " +
        "temporarily unavailable. Retry shortly.",
    });
  }
  return next();
});

// ── POST-oracle request-body validation ────────────────────────────────────
// Runs AFTER the payment gate, so an unpaid probe still gets its 402 price quote
// — but a PAID request whose body doesn't satisfy the advertised schema (e.g. an
// empty {} to sanctions-screen) returns 400. A >=400 response makes the x402
// middleware CANCEL settlement (see @x402/express:
//   `if (res.statusCode >= 400) await cancellationDispatcher.cancel(...)`),
// so the agent is NEVER charged for an unscreenable/unanswerable request. Only
// each schema's OWN declared contract (required / anyOf) is enforced; feeds with
// no required field (positioning-snapshot) still accept {}.
//
// Scoped to LIVE POST oracles (POST_ORACLES) only — NOT every slug with a schema.
// A delisted slug (e.g. token-safety) keeps a stale ORACLE_REQUEST_SCHEMAS entry
// but is served by a 410-Gone stub and is absent from POST_ORACLES; validating it
// here would shadow that 410 with a 400 and break the deploy-blocking
// gate-engagement check (which requires delisted routes to answer 404/410).
app.use((req, res, next) => {
  if (String(req.method).toUpperCase() !== "POST") return next();
  const slug = oracleSlug(req.path);
  if (!slug || !POST_ORACLES.has(slug)) return next();
  const detail = validateOracleBody(ORACLE_REQUEST_SCHEMAS[slug], req.body);
  if (detail) {
    return res.status(400).json({
      error: "invalid_request_body",
      detail: `${slug}: ${detail}. See the request schema in GET /openapi.json or the 402 payment-required body.`,
    });
  }
  return next();
});

// ── Universal disclaimer header ───────────────────────────────────────────
// Every feed declares a disclaimerCategory in its FeedMetadata. We emit
// X-BYTE-Disclaimer-Category on every feed response so agents/clients can
// render the right legal framing without parsing payload. The category-to-
// text mapping is exposed via DISCLAIMER_TEXT in lib/config.ts and surfaced
// in GET /feeds metadata so buyers can preview before purchase.
const disclaimerByPath = new Map<string, string>();
for (const feed of feedRegistry) {
  disclaimerByPath.set(feed.endpoint, feed.disclaimerCategory);
}
app.use((req, res, next) => {
  // Normalize the same way isPaidRoute does, so path variants still get the
  // correct legal-framing header (and don't silently drop it).
  const cat = disclaimerByPath.get(normalizeGatePath(req.path));
  if (cat) res.setHeader("X-BYTE-Disclaimer-Category", cat);
  next();
});

// ---------------------------------------------------------------------------
// Free Endpoints
// ---------------------------------------------------------------------------

/** Feed discovery endpoint -- returns all available feeds with pricing and PQS scores. */
app.get("/feeds", (_req, res) => {
  const networks = [config.network];
  if (config.solanaPayTo && ExactSvmScheme) networks.push(config.solanaNetwork);

  res.json({
    protocol: "PayPerByte x402 Gateway",
    version: "0.3.0",
    networks,
    facilitator: config.facilitatorUrl,
    asset: config.usdcAddress,
    // Copy fixed 2026-07-28 (TASK A integrity item): this block self-described
    // a per-byte formula, but every feed in feedRegistry today is priced via
    // an explicit PRICE_OVERRIDES / customPricedFeed value-tier price (see
    // config.ts) — none currently fall through to the per-KB computation, so
    // the old text didn't reproduce ANY listed price (e.g. weather: formula
    // ≈$0.0215 vs listed $0.005). Values are UNCHANGED — copy only.
    pricing: {
      model: "fixed-per-call",
      note: "Each feed is priced per call at a fixed rate set by its decision/data value (not payload size) — see each feed entry's `price` below. A per-KB rate (pricePerKB/floor) exists as a fallback formula for any future feed without an explicit price, but no currently-listed feed uses it.",
      pricePerKB: `$${(Number(config.pricePerKBAtomic) / 1_000_000).toFixed(6)}`,
      floor: `$${(Number(config.priceFloorAtomic) / 1_000_000).toFixed(6)}`,
    },
    disclaimers: {
      header: "X-BYTE-Disclaimer-Category",
      note: "Every feed response carries X-BYTE-Disclaimer-Category. Render legal framing accordingly. Disclaimer text is also embedded in the signed payload for new Tier 1 publishers; existing publishers carry it via the header until the post-Ari batch upgrade.",
      text: DISCLAIMER_TEXT,
    },
    // Each entry carries `method` — the HTTP verb(s) the feed accepts ("GET",
    // "POST", or "POST, GET" for dual-pattern feeds) — so a dev knows which verb
    // to use without guessing (a GET to a POST oracle now 405s with the right verb,
    // not a circular 404).
    feeds: feedRegistry.map((f) => ({ ...f, method: feedMethods(f) })),
  });
});

/**
 * OpenAPI 3.1 discovery document — the canonical machine-readable contract.
 * x402scan and other agent discovery layers read this first (precedence over
 * the runtime 402). Free endpoint — must not be payment-gated.
 */
app.get("/openapi.json", (_req, res) => {
  res.json(buildOpenApiDoc());
});

/**
 * The live HTTP method(s) a feed is gated on, mirroring the `paymentRoutes` map
 * built above EXACTLY. A POST oracle that is ALSO publisher-backed (usc-statute,
 * runtime-eol, threat-intel) is dual GET+POST; a pure oracle is POST; everything
 * else is GET. Returned as ONE value per feed — a `["GET","POST"]` array for the
 * dual feeds — so the x402 manifest and agent card emit exactly ONE entry per feed
 * and report the canonical 22-feed count (not 25, which mismatched /discover).
 * The OpenAPI doc still declares the two operations separately (path-based).
 * (Distinct from `feedMethods()` above, which returns the comma-joined STRING for
 * the human-readable /feeds catalog; this returns the JSON value for the manifests.)
 */
function feedMethodValue(feed: { id: string; publisher?: string }): "GET" | "POST" | ["GET", "POST"] {
  const isOracle = POST_ORACLES.has(feed.id);
  const hasGet = Boolean(feed.publisher) || !isOracle;
  if (isOracle && hasGet) return ["GET", "POST"];
  return isOracle ? "POST" : "GET";
}

/**
 * x402 resource discovery manifest (/.well-known/x402.json). Pull-based
 * discovery: x402 indexers (x402scan, x402engine, CDP discovery) crawl a
 * well-known path to enumerate payable resources without manual submission.
 * Complements the per-route Bazaar discovery extension (which feeds
 * Coinbase's CDP crawler specifically) by exposing the same catalog to
 * non-Coinbase indexers and the DNS-TXT discovery draft's manifest fetch.
 * Free, ungated; self-updates from feedRegistry.
 */
/**
 * The verify-before-act receipt descriptor — present on every paid 200-response
 * as the X-BYTE-Attestation header. Shared by BOTH agent.json AND x402.json so a
 * client bootstrapping from EITHER canonical entry point learns how to verify
 * receipts (previously only agent.json carried it). `anchorNote` explains why the
 * domain chainId is a testnet id even though funds settle on mainnet. Returns
 * undefined when no attestation key is configured.
 */
/**
 * POST-oracle signer addresses — the public key each oracle signs its
 * embedded PayloadAttestation with (each oracle derives this at startup from
 * its own configured key, the same way data-feeds/*\/gate.py already does).
 *
 * FD 2026-07-28: without this, the embedded-attestation "verify" recipe for
 * POST oracles (see attestationReceiptBlock().embedded.verify.oracle below)
 * is CIRCULAR — a buyer recomputes keccak256(answer), recovers a signer, then
 * checks it against `attestation.signer`, a field the SAME response supplies.
 * There is nothing independent to compare against. Publishing each oracle's
 * expected signer here (like `signers` already does for the on-chain
 * broadcast feeds, via the independently-configured `publisher` field) closes
 * that gap: a buyer checks the recovered signer against a value pinned in the
 * manifest, not against the response's own self-reported claim.
 *
 * Sourced from env so a key rotation is a config change, not a code change.
 * UNSET (omitted from the manifest) by default for EVERY entry — do NOT
 * hardcode a signer address, even one observed live: a key rotation would
 * make the manifest reject good data until someone remembered to update
 * source (FD 2026-07-28, M1 — this file previously hardcoded a fallback for
 * REASONING_VERDICT_SIGNER; removed). The value observed live 2026-07-28T21:55Z
 * via byte-reasoning-verdict.service's own /healthz was
 * `0xe6447AfD82A5E119B5250220Ab6ac2ae7d7f65ab` — set
 * REASONING_VERDICT_SIGNER to that (after confirming it's still current) to
 * populate this entry; it is NOT a default here.
 * None of these 4 oracles (address-reputation, pkg-verdict, sanctions-screen,
 * positioning-snapshot, reasoning-verdict) currently expose their signer via
 * /healthz except reasoning-verdict (and threat-intel-gate, whose signer
 * belongs to a different route — see the SHIPY report), so most of these
 * addresses were not safely obtainable without either handling raw key
 * material (correctly blocked) or editing live services beyond this diff's
 * scope — recommended follow-up: add a `signer` field to each oracle's own
 * /healthz, mirroring reasoning-verdict/threat-intel-gate.
 */
// evidence-pack and liquidation-stream omitted below — both DELISTED
// 2026-07-28 (see the 410-Gone stubs), no live route to publish a signer for.
const ORACLE_SIGNERS: Record<string, string> = Object.fromEntries(
  (
    [
      ["address-reputation", process.env.ADDRESS_REPUTATION_SIGNER],
      ["pkg-verdict", process.env.PKG_VERDICT_SIGNER],
      ["sanctions-screen", process.env.SANCTIONS_SCREEN_SIGNER],
      ["reasoning-verdict", process.env.REASONING_VERDICT_SIGNER],
      ["positioning-snapshot", process.env.POSITIONING_SNAPSHOT_SIGNER],
      // merchant-screen: unset until the founder-provisioned MERCHANT_SCREEN_PUB_KEY
      // lands and its corresponding address is safely read off byte-merchant-screen's
      // own /healthz (never derived from key material in this session) — same
      // "no hardcoded fallback" discipline as every other entry here.
      ["merchant-screen", process.env.MERCHANT_SCREEN_SIGNER],
    ] as [string, string | undefined][]
  ).filter((entry): entry is [string, string] => Boolean(entry[1])),
);

function attestationReceiptBlock() {
  if (!attestationEnabled()) return undefined;
  return {
    header: "X-BYTE-Attestation",
    scheme: "EIP712-PayloadAttestation",
    domain: attestationDomain(),
    attester: attesterAddress(),
    verify:
      "keccak256(responseBody) === payloadHash AND " +
      "recoverTypedDataAddress(domain, {PayloadAttestation}, message, signature) === attester",
    anchorNote:
      "domain.chainId 421614 = Arbitrum Sepolia, a TESTNET — it is a FROZEN signing " +
      "namespace for EIP-712 signature recovery, NOT a settlement rail. Payments settle " +
      "in USDC on Base mainnet (eip155:8453); no funds move on testnet. The chainId is a " +
      "consensus constant: it stays 421614 regardless of where you pay, so every receipt " +
      "verifies against the same domain. (Mainnet re-anchoring is audit-gated.)",
    // SECOND receipt — LIVE per-feed provenance, machine-discoverable. The
    // eip712-attested feeds each have their OWN distinct per-feed signer key (a
    // SEPARATE signer from the gateway `attester` above). `signers` maps feed id →
    // that feed's signer address (the on-chain-registered publisher key). First-party
    // PayPerByte, not an independent third-party data source, not correctness.
    embedded: {
      scheme: "EIP712-PayloadAttestation",
      domain: attestationDomain(),
      // HOW the per-feed signature is recovered depends on the feed shape:
      verify: {
        // GET publisher feeds (provenance:eip712-attested): the per-feed signature
        // is anchored ON-CHAIN — the HTTP body carries `publisher`+`payloadHash`+`txHash`
        // (no signature field); recover the publisher's PayloadAttestation from the
        // BroadcastStreamed event at responseBody.txHash.
        broadcast:
          "recover the publisher's EIP-712 PayloadAttestation from the on-chain " +
          "BroadcastStreamed event at responseBody.txHash; confirm responseBody.publisher " +
          "=== signers[feed] and responseBody.payloadHash matches the broadcast.",
        // GET publisher feeds where responseBody.source === "live" (P1 fix
        // 2026-07-28, feeds/generic.ts fetchFeedPayload): served directly from
        // the feed's live-query companion, NOT the on-chain archive — there is
        // NO BroadcastStreamed event this cycle (no txHash), so the `broadcast`
        // recipe above does not apply. The signature is instead EMBEDDED in
        // responseBody.data.attestation (same shape as a POST oracle's
        // embedded receipt) — recover it directly, THEN confirm it against the
        // SAME independently-published signers[feed] the broadcast recipe
        // checks: live-query companions sign with the identical registered
        // publisher key by design (see data-feeds/*/live.py), not a separate
        // one, so this closes the same self-referential gap `oracle` below
        // still has for any feed id absent from `signers`.
        // FD 2026-07-28 (final PASS condition): "canonical(x)" was ambiguous —
        // a JS buyer following it literally (JSON.parse then re-serialize)
        // gets a MISMATCH on otherwise-valid data, because a JSON writer that
        // normalizes numbers (e.g. renders 3.0 as 3) does not reproduce the
        // exact bytes the publisher signed. Defined explicitly below for both
        // `live` and `oracle` — FD proved the identical defect breaks the
        // `oracle` recipe for JS buyers TODAY in production (sampled payloads
        // mismatch under JS recompute, match under Python), so both get the
        // same fix in this one edit. Full canonicalization-spec/SDK work is a
        // separate lane; this is the doc-correctness half only.
        live:
          "canonical(x) = the EXACT byte substring of x as delivered in this response — the " +
          "gateway forwards the live-query companion's bytes VERBATIM (never re-serialized), so " +
          "extract responseBody.data.answer directly from the raw response text, NOT by " +
          "JSON.parse-ing then re-serializing it: a JSON writer that normalizes numbers (e.g. " +
          "renders 3.0 as 3) will not reproduce the bytes the publisher signed, and the recompute " +
          "mismatches on otherwise-valid data. keccak256(canonical(responseBody.data.answer)) === " +
          "responseBody.data.attestation.payloadHash AND recoverTypedDataAddress(domain, " +
          "{PayloadAttestation}, message, responseBody.data.attestation.signature) === " +
          "responseBody.data.attestation.signer AND confirm responseBody.data.attestation.signer " +
          "=== signers[feed]. (responseBody.payloadHash mirrors the same value at the top level " +
          "for parity with the broadcast shape. Publisher-side note: avoid trailing-.0 float " +
          "literals where possible — a common source of this exact cross-implementation mismatch.)",
        // POST verdict oracles: the signature is EMBEDDED in the response body's
        // `attestation` object — recover it directly. Where the feed id ALSO
        // appears in `signers` (currently: reasoning-verdict — see
        // ORACLE_SIGNERS), also confirm attestation.signer === signers[feed]
        // for an independent binding, not just a self-check against the
        // response's own claim; feed ids absent from `signers` still lack that
        // binding today (tracked follow-up, not yet closed for every oracle).
        oracle:
          "canonical(x) = the EXACT byte substring of x as delivered — same defect and same fix " +
          "as the `live` recipe above (FD 2026-07-28: this recipe mismatches for a JS buyer that " +
          "re-serializes today): extract `answer` from the raw response bytes, never by " +
          "JSON.parse-ing then re-serializing the parsed object. keccak256(canonical(answer)) === " +
          "attestation.payloadHash AND recoverTypedDataAddress(domain, {PayloadAttestation}, " +
          "message, attestation.signature) === attestation.signer (the feed's own per-feed key — " +
          "NOT the gateway attester); if signers[feed] is present, also confirm attestation.signer " +
          "=== signers[feed].",
      },
      note:
        "A distinct per-feed key, separate from the gateway X-BYTE-Attestation header. " +
        "First-party PayPerByte (not an independent third-party data source), NOT a " +
        "correctness guarantee. `signers` maps feed id -> that feed's expected signer, " +
        "independently of what any single response claims: for eip712-attested broadcast " +
        "feeds it's the on-chain-registered publisher address; for POST oracles (where " +
        "configured — see ORACLE_SIGNERS) it's the oracle's own key, published here so the " +
        "`oracle` verify recipe above isn't just checking a response against itself. A feed " +
        "id absent from `signers` (an oracle whose address isn't configured yet) still embeds " +
        "its own `attestation.signer` in the body — verifiable for tamper-evidence, just not " +
        "yet pinnable against an independent expected value.",
      signers: {
        ...Object.fromEntries(
          feedRegistry
            .filter((f) => f.provenance === "eip712-attested" && f.publisher)
            .map((f) => [f.id, f.publisher]),
        ),
        ...ORACLE_SIGNERS,
      },
    },
  };
}

function buildX402Manifest() {
  const net = networkInfo();
  return {
    x402Version: 2,
    name: "PayPerByte",
    description:
      `Per-byte USDC data feeds + oracles for AI agents. First-party, with a verify-before-act EIP-712 receipt (authenticity + tamper-evidence, not data correctness); no token. Settlement on ${net.label}.`,
    provider: { organization: "PayPerByte", url: "https://www.payperbyte.io" },
    network: config.network,
    status: net.status,
    facilitator: config.facilitatorUrl,
    catalog: "https://x402.payperbyte.io/feeds",
    // The verify-before-act receipt + pointers to the full discovery surfaces, so
    // a client bootstrapping from the canonical /.well-known/x402.json (which used
    // to carry payment info but ZERO receipt-verification info) can verify receipts
    // and reach the agent card (full receipt spec + per-skill routing) + OpenAPI.
    receipt: attestationReceiptBlock(),
    agentCard: "https://x402.payperbyte.io/.well-known/agent.json",
    openapi: "https://x402.payperbyte.io/openapi.json",
    // ONE resource entry per feed (canonical 22). Dual-pattern feeds
    // (usc-statute/runtime-eol/threat-intel) carry method:["GET","POST"]; both are
    // gated (the OpenAPI doc declares the two operations separately, path-based).
    resources: feedRegistry.map((feed) => ({
      resource: `https://x402.payperbyte.io${feed.endpoint}`,
      method: feedMethodValue(feed),
      name: feed.name,
      description: feed.description,
      category: feed.disclaimerCategory,
      provenance: feed.provenance,
      // Per-feed publisher signer — for these eip712-attested GET feeds the
      // signature is anchored ON-CHAIN (recover the publisher's PayloadAttestation
      // from the broadcast at the body's txHash), NOT embedded in the response body.
      ...(feed.provenance === "eip712-attested" && feed.publisher ? { signer: feed.publisher } : {}),
      price: feed.price,
      accepts: buildAccepts(feed.priceAtomic),
      metadata: {
        expectedSizeBytes: feed.expectedSizeBytes,
        updateFrequency: feed.updateFrequency,
      },
    })),
  };
}

app.get("/.well-known/x402.json", (_req, res) => {
  res.json(buildX402Manifest());
});

// Doctrine path aliases. The agent-economy doctrine names the bare paths
// `/.well-known/x402` (no .json) and `/x402-manifest`; some crawlers fetch
// those literals. Bind both to the same canonical manifest so neither 404s.
// `/.well-known/x402.json` remains the canonical URL (advertised in the
// agent card, OpenAPI, and the www pointer).
app.get(["/x402-manifest", "/.well-known/x402"], (_req, res) => {
  res.json(buildX402Manifest());
});

/**
 * Agent card (/.well-known/agent.json) — A2A / agent-discovery convention.
 * Describes BYTE Library as an agent-callable service: the x402 payment
 * surface, per-feed skills, and entrypoints (catalog, OpenAPI, the x402
 * manifest, the hosted MCP server). Free, ungated; self-updates from
 * feedRegistry.
 */
app.get("/.well-known/agent.json", (_req, res) => {
  const net = networkInfo();
  res.json({
    name: "PayPerByte",
    description:
      `Per-byte USDC data feeds + oracles for AI agents — pay-per-call via x402, settled in USDC on ${net.label}. Data responses carry an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation) you verify before acting; the attestation domain is anchored on Arbitrum (chainId 421614) regardless of settlement rail.`,
    url: "https://x402.payperbyte.io",
    version: "0.3.0",
    provider: { organization: "PayPerByte", url: "https://www.payperbyte.io" },
    capabilities: {
      payments: {
        protocol: "x402",
        asset: "USDC",
        network: config.network,
        payTo: config.payTo,
      },
      streaming: false,
    },
    // The verify-before-act receipt: present on every data 200-response as the
    // X-BYTE-Attestation header. Shared with x402.json via attestationReceiptBlock()
    // (carries the testnet-anchor `anchorNote`). Omitted only if no key is set.
    receipt: attestationReceiptBlock(),
    // ONE skill per feed (canonical 22) — dual-pattern feeds carry
    // method:["GET","POST"], matching paymentRoutes + the OpenAPI doc + x402.json.
    skills: feedRegistry.map((feed) => ({
      id: feed.id,
      name: feed.name,
      description: feed.description,
      // Full URL + verb so an agent self-routes correctly — the bare id alone
      // (e.g. "defi-yields") would 404; the paid resource is at /feeds/<slug>.
      url: `https://x402.payperbyte.io${feed.endpoint}`,
      method: feedMethodValue(feed),
      // Per-feed publisher signer (eip712-attested feeds) — anchored ON-CHAIN,
      // recover from the broadcast at the body's txHash; not embedded in the body.
      ...(feed.provenance === "eip712-attested" && feed.publisher ? { signer: feed.publisher } : {}),
      tags: [feed.disclaimerCategory, "x402", "usdc", net.chain],
    })),
    endpoints: {
      catalog: "https://x402.payperbyte.io/feeds",
      openapi: "https://x402.payperbyte.io/openapi.json",
      x402: "https://x402.payperbyte.io/.well-known/x402.json",
      mcp: "https://mcp.payperbyte.io/mcp",
    },
    documentationUrl: "https://www.payperbyte.io/docs/quickstart",
  });
});

/**
 * ERC-8004 agent registration file (/.well-known/agent-registration.json).
 * The Identity Registry's agentURI must resolve to THIS spec shape
 * (eip-8004#registration-v1) — the A2A agent card does NOT satisfy it; it is
 * nested below as a service endpoint instead. ERC8004_AGENT_ID is set in the
 * deploy env after the one-time register(string) mint on Arbitrum Sepolia
 * (registry 0x8004A818BFB912233c491871b3d84c89A494BD9e — the registry's own
 * EIP-712 domain is unrelated to the consensus-critical "BYTE Library" one).
 * No supportedTrust field: absent = discovery-only per spec — no trust-model
 * or traction claims.
 */
app.get("/.well-known/agent-registration.json", (_req, res) => {
  const agentId = process.env.ERC8004_AGENT_ID;
  res.json({
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "PayPerByte",
    description:
      `Per-byte USDC data feeds and oracles for AI agents (display name: PayPerByte). ${feedRegistry.length} paid x402 resources served from https://x402.payperbyte.io, settled in USDC on Base mainnet (eip155:8453); flagship POST /feeds/address-reputation at $0.10. Every data response carries an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation header) that callers verify before acting.`,
    image: "https://raw.githubusercontent.com/0rkz/byte-mcp-server/main/assets/logo-400x400.png",
    services: [
      { name: "web", endpoint: "https://x402.payperbyte.io" },
      { name: "A2A", endpoint: "https://x402.payperbyte.io/.well-known/agent.json", version: "0.3.0" },
      { name: "MCP", endpoint: "https://mcp.payperbyte.io/mcp", version: "2025-06-18" },
      { name: "x402", endpoint: "https://x402.payperbyte.io/.well-known/x402.json" },
      { name: "OpenAPI", endpoint: "https://x402.payperbyte.io/openapi.json" },
    ],
    x402Support: true,
    active: true,
    registrations: agentId
      ? [{ agentId: Number(agentId), agentRegistry: "eip155:421614:0x8004A818BFB912233c491871b3d84c89A494BD9e" }]
      : [],
  });
});

/**
 * 402index.io domain-verification file. 402index fetches this to confirm we own
 * x402.payperbyte.io (the host all our feeds are indexed under) and flip
 * domain_verified=1 on our rows. Set INDEX402_VERIFY_HASH to the
 * verification_hash returned by POST https://402index.io/api/v1/claim. Served
 * bare (no trailing newline), no redirect, <1KB — per the 402index spec.
 */
app.get("/.well-known/402index-verify.txt", (_req, res) => {
  res.type("text/plain").send(process.env.INDEX402_VERIFY_HASH || "");
});

/**
 * Favicon — x402scan (and browsers) fetch /favicon.ico to show the listing
 * icon. Served from the repo root; WorkingDirectory is the gateway dir so
 * process.cwd()-relative resolution holds under systemd. Free, ungated.
 */
app.get("/favicon.ico", (_req, res) => {
  res.sendFile("favicon.ico", { root: process.cwd() }, (err) => {
    if (err && !res.headersSent) res.status(404).end();
  });
});

/**
 * Health check for load balancers and monitoring.
 *
 * `signing_ok` mirrors merchant-screen's /healthz signing gate. Since the
 * 2026-08-01 no-key hardening (lib/attestation.ts §1.4) an unset
 * GATEWAY_ATTESTATION_KEY makes every PAID route refuse with 503 rather than
 * serve an unattested 200 — so a missing key is a full paid-surface outage, and
 * a health endpoint that always answered a hardcoded "ok" would hide it until a
 * buyer hit it. Reported here so monitoring sees it first.
 *
 * The HTTP status stays 200 in both states ON PURPOSE: this endpoint also fronts
 * the FREE discovery surfaces (/feeds, /openapi.json, agent.json, .well-known),
 * which keep working when signing is down, and a non-200 would have a load
 * balancer pull those out of rotation as well. Read the body, not just the code.
 */
app.get("/health", (_req, res) => {
  const signingOk = attestationEnabled();
  res.json({
    status: signingOk ? "ok" : "degraded",
    signing_ok: signingOk,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * Extract a safe, honest detail string from an upstream oracle's error body,
 * for the buyer to see instead of a flat "upstream error" (FD 2026-07-28:
 * upstreams produce precise, brand-correct explanations — e.g. liquidation-
 * stream's INSUFFICIENT_DATA — that were being discarded; address-reputation's
 * opaque 400 on a well-formed CAIP-2 body is the same bug).
 *
 * Every first-party oracle proxied below returns clean structured JSON errors
 * ({"error": "..."} — verified across data-feeds/*\/server.py) with no host,
 * IP, or stack trace. Forward ONLY a short string from a known-safe field;
 * any other shape (non-JSON body, an HTML error page, an overlong or
 * non-string field) falls back to the original opaque detail — preserving
 * the R4 leak-class defense this file already documents for the genuinely-
 * unexpected-failure case (a crashed, misconfigured, or non-first-party
 * upstream).
 */
const MAX_SAFE_UPSTREAM_DETAIL_LEN = 300;
function safeUpstreamDetail(rawBody: string): string {
  try {
    const body = JSON.parse(rawBody) as Record<string, unknown>;
    const candidate = body.error ?? body.detail ?? body.reason;
    if (
      typeof candidate === "string" &&
      candidate.length > 0 &&
      candidate.length <= MAX_SAFE_UPSTREAM_DETAIL_LEN
    ) {
      return candidate;
    }
  } catch {
    /* not JSON — fall through to the generic detail */
  }
  return "upstream error";
}

/**
 * Error classes that mean the upstream was genuinely NOT REACHABLE — a DNS, TCP
 * or deadline failure at the transport layer. Node surfaces connection faults as
 * TypeError("fetch failed") carrying the real code on `.cause` (a POSIX code, or
 * one of undici's own UND_ERR_* for its timeouts); an abort or a request
 * deadline arrives as a DOMException named AbortError/TimeoutError.
 *
 * This list is the definition of the "upstream unreachable" marker, so a code
 * NOT on it is counted as a proxy error instead — see logProxyFailure.
 */
const UNREACHABLE_CLASSES = new Set([
  // POSIX socket / DNS
  "ECONNREFUSED", "ECONNRESET", "ECONNABORTED", "ETIMEDOUT", "ENOTFOUND",
  "EAI_AGAIN", "EHOSTUNREACH", "EHOSTDOWN", "ENETUNREACH", "ENETDOWN",
  "EADDRNOTAVAIL", "EPIPE", "EPROTO",
  // undici
  "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT",
  "UND_ERR_SOCKET", "UND_ERR_ABORTED",
  // abort / deadline (DOMException .name — see upstreamErrorClass on why the
  // numeric .code must not be read here)
  "AbortError", "TimeoutError",
]);
// Deliberately NOT listed: TLS/certificate failures (CERT_HAS_EXPIRED,
// ERR_TLS_CERT_ALTNAME_INVALID, UNABLE_TO_VERIFY_LEAF_SIGNATURE, and the rest of
// OpenSSL's set). They are a trust/config fault with different remediation than
// "the host is down", and a partial list would split identical incidents across
// both markers — a complete rule over a narrow set beats a partial rule over a
// wide one. They land under "proxy error", which is logged, not silent.

/**
 * The error CLASS for a proxy failure: a transport code when there is one, else
 * the error name, else "unknown".
 *
 * A code counts only when it is a STRING. DOMException carries a legacy NUMERIC
 * `.code` (AbortError = 20, TimeoutError = 23), so reading `.code` unguarded
 * logs `class=20` for an aborted request — a bare number no sensor can match and
 * no reader can interpret, and it never reaches the `.name` that holds the real
 * class. Skipping non-strings lets those fall through to `.name`.
 *
 * Verified against Node 20.20.2 (2026-07-31): a refused connection puts
 * code="ECONNREFUSED" on `.cause` of TypeError("fetch failed"), DNS failure puts
 * "ENOTFOUND" there, and abort/timeout arrive as a bare DOMException with only
 * the numeric code and the name.
 */
function upstreamErrorClass(err: unknown): string {
  const e = err as { code?: unknown; name?: unknown; cause?: { code?: unknown; name?: unknown } };
  const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
  return str(e?.cause?.code) ?? str(e?.code) ?? str(e?.cause?.name) ?? str(e?.name) ?? "unknown";
}

/**
 * Log a paid proxy's catch-block failure under one of TWO markers. Closes the
 * coverage gap the monitor documents: a non-ok upstream RESPONSE is logged
 * ("upstream non-ok <status>"), but everything reaching a handler's catch logged
 * NOTHING, so "unit up, TCP refuses" was invisible in the journal and to any
 * sensor reading it — the likeliest next silent outage now that the GET feeds are
 * single-sourced on their live companions.
 *
 * The two markers are grep-stable, mutually exclusive, and deliberately distinct
 * from "upstream non-ok", so a sensor counts three failure classes separately:
 *
 *   upstream unreachable: feed=<id> class=<code>   transport-level, UNREACHABLE_CLASSES
 *   proxy error:          feed=<id> class=<code>   everything else in the catch
 *
 * The split exists because a catch here is wider than the fetch: it also takes a
 * fail-closed staleness/validation rejection from fetchFeedPayload, a
 * discovery-api non-ok (both plain Error, class=Error), and any bug in this
 * file. Counting those as "unreachable" would make a reachability sensor fire on
 * events where the upstream answered perfectly well — a sensor that cries wolf
 * gets muted, so it must count reachability and nothing else. Neither marker is
 * silent: an unclassified failure is still one line, just in the other bucket.
 *
 * Logs the feed id and the ERROR CLASS only (see upstreamErrorClass) — never a
 * body, URL, header, or key. The message itself is NOT logged, on either marker,
 * because it can carry the upstream host/port (the R4 leak class this file
 * already guards on the response path — fetchFeedPayload's throw messages
 * interpolate the publisher and the upstream URL).
 */
function logProxyFailure(feed: string, err: unknown): void {
  const cls = upstreamErrorClass(err);
  const marker = UNREACHABLE_CLASSES.has(cls) ? "upstream unreachable" : "proxy error";
  console.error(`[x402-gateway] ${marker}: feed=${feed} class=${cls}`);
}

/**
 * Deadline on every upstream oracle proxy fetch below (hardening plan §1.3).
 *
 * Node's fetch applies NO response deadline of its own, so before this an
 * upstream that accepted the TCP connection and then never answered held the
 * paying agent's request open indefinitely (and pinned a gateway socket). A
 * hung oracle is the worst shape for an agent: it cannot distinguish "slow" from
 * "never", so it stalls or retries — re-signing a fresh payment authorization
 * each loop.
 *
 * FAILS CLOSED, never a degraded 200. AbortSignal.timeout aborts the fetch with
 * a DOMException named "TimeoutError", which lands in each handler's catch:
 * logProxyFailure records it under `upstream unreachable` (TimeoutError is in
 * UNREACHABLE_CLASSES) and the handler answers 502. A >=400 makes the x402
 * middleware skip settlement, so a caller is never charged for a request that
 * timed out.
 *
 * 15s is the house AbortSignal.timeout pattern (mcp-server/src/tools/fact.ts
 * uses 5_000 against the local indexer) widened for these oracles: their slow
 * leg is live third-party network work at query time — local GPU inference for
 * reasoning-verdict, single upstream fetches for runtime-eol and threat-intel —
 * not an index read. The slow multi-leg oracles need more (merchant-screen,
 * address-reputation, pkg-verdict); see SLOW_UPSTREAM_FETCH_TIMEOUT_MS below.
 */
const UPSTREAM_FETCH_TIMEOUT_MS = 15_000;

/**
 * Wider deadline for the SLOW MULTI-LEG oracles (founder-authorized 2026-08-01:
 * "raise to 30s for the probing oracles", extended the same day to pkg-verdict).
 *
 * NAMED FOR THE PROPERTY IT ACTUALLY SELECTS. This was
 * named PROBING_UPSTREAM_FETCH_TIMEOUT_MS while it held only the two
 * subject-probing feeds; pkg-verdict is NOT probing, and filing it under that label would
 * have made the constant lie about its own membership. The property all three
 * share is narrower than "makes network calls" (every oracle does) and wider than
 * "probes the caller's subject": each runs SEVERAL SEQUENTIAL third-party legs
 * whose per-leg timeout already sums past 15s, so the old bound could abort a
 * request that was going to succeed.
 *
 *   merchant-screen    — SUBJECT-PROBING. gather_signals() runs fetch_domain_age
 *                        (RDAP), fetch_tls_ext (live TLS handshake against the
 *                        screened domain), fetch_redirect (live redirect probe) and
 *                        fetch_price_sanity (the merchant's own x402 manifest) in
 *                        sequence, each at HTTP_TIMEOUT_S = 10
 *                        (data-feeds/merchant-screen/resolvers.py). The screened
 *                        party controls that latency.
 *   address-reputation — SUBJECT-PROBING. gather_domain_signals() calls the SAME
 *                        shim (data-feeds/merchant-trust/resolvers.py) for rdap +
 *                        tls + dns + wayback, then an on-chain RPC leg. Its wayback
 *                        leg alone is timeout=25 (merchant-trust/resolvers.py:261) —
 *                        on its own more than the 15s bound it used to get.
 *   pkg-verdict        — NOT probing: it queries public package registries, not a
 *                        subject the caller chose, so nobody hostile controls the
 *                        latency. It is here on the sequential-legs property alone —
 *                        up to three sequential registry/OSV calls at
 *                        HTTP_TIMEOUT_S = 20 (data-feeds/pkg-verdict/resolvers.py:74,
 *                        called at :201, :264, :328), i.e. a worst case of ~60s
 *                        against a 15s bound. Slow-but-valid registry responses were
 *                        the realistic abort here, not an adversary.
 *
 * At 15s a legitimately slow but perfectly valid query was aborted, converting a
 * would-have-succeeded PAID call into a lost sale. Money-safe either way (the abort
 * is a >=400, so settlement is cancelled and nobody is charged), but a lost sale is
 * still a loss. Deliberately NOT fixed by cutting the Python-side timeouts instead:
 * for merchant-screen that changes whether a signal reads "measured" vs
 * "unverified", which changes signed answer content — ms-v1 is frozen, that is
 * ms-v2 work.
 *
 * The other five bounded routes stay at 15s on purpose: sanctions-screen (pinned/
 * cached list-states), reasoning-verdict (local GPU inference), runtime-eol and
 * threat-intel (single upstream fetch each), positioning-snapshot (venue legs at
 * HTTP_TIMEOUT = 10, but they do not stack the way these three do).
 */
const SLOW_UPSTREAM_FETCH_TIMEOUT_MS = 30_000;

/**
 * Buyer-facing `detail` for a proxy catch: name a deadline as a deadline.
 * "upstream unavailable" is honest but tells an agent nothing about whether to
 * retry; a timeout is a distinct, actionable condition. Every other failure
 * class keeps the existing opaque string (R4 leak-class defense — never echo an
 * upstream host, port, or error text to the buyer).
 *
 * Takes the route's own bound: since the probing routes wait 30s and the rest
 * wait 15s, a hardcoded number would tell half the callers the wrong deadline.
 */
function proxyFailureDetail(err: unknown, timeoutMs: number = UPSTREAM_FETCH_TIMEOUT_MS): string {
  return upstreamErrorClass(err) === "TimeoutError"
    ? `upstream did not respond within ${timeoutMs / 1000}s`
    : "upstream unavailable";
}

// ---------------------------------------------------------------------------
// Paid Endpoints
// ---------------------------------------------------------------------------

// crypto-top100 route REMOVED 2026-06-14 — CoinGecko free-tier no-resale, and it
// served data UNPAID (delisted from feedRegistry → no payment gate). Feed + fetcher
// retired. See OUTSTANDING_ACTIONS §5.4.

/** defi-yields — DELISTED 2026-07-03 (concentration cut). 410-Gone stub. */
app.get("/feeds/defi-yields", (_req, res) => {
  res.status(410).json({ error: "delisted", detail: "defi-yields was retired in the 2026-07-03 concentration cut — no longer served." });
});

/**
 * evidence-pack — DELISTED 2026-07-28 (founder-approved, in-session): serves
 * off-description output (catalog says "retrieve from PayPerByte factual
 * feeds"; TASK A found it actually retrieves from Wikipedia) with an
 * undisclosed third-party egress path, and marked a temporally bogus citation
 * (2008 Sichuan earthquake) as "supporting" a "last 24h" claim. NOT in
 * feedRegistry (lib/config.ts) — no payment gate — so this is an explicit
 * 410-Gone stub (NOT a live proxy), matching the token-safety pattern: the
 * route FAILS CLOSED and never reaches the upstream, closing the
 * dangling-route leak class (a handler outside the payment gate would serve
 * paid data free the moment its upstream came up).
 *
 * Re-list = fix the grounding source + disclose the egress path, restore the
 * proxy body, and re-add a feedRegistry entry so the payment gate covers it
 * (and re-add to POST_ORACLES + openapi POST_ORACLE_IDS). Until then the
 * pre-ship gate-engagement check (scripts/gate-engagement-check.mjs) asserts
 * this route stays 404/410.
 */
app.post("/feeds/evidence-pack", (_req, res) => {
  res.status(410).json({
    error: "delisted",
    detail:
      "evidence-pack is delisted pending a grounding-source fix and egress disclosure — it is not " +
      "currently served. It will return once re-listed with a payment gate.",
  });
});

/**
 * usc-statute — US Code statute Q&A oracle.
 * Body: { citation: string, subscriber_address?, subscriber_signature?, request_nonce?, deadline_unix? }
 *
 * Note: usc-statute is also registered as a publisher-backed indexerFeed
 * (the generic loop below sets up the GET route serving the latest broadcast).
 * This explicit POST proxy is the request-response synchronous path for
 * agents that don't want to subscribe — dual GET/POST pattern.
 */
app.post("/feeds/usc-statute", (_req, res) => {
  res.status(410).json({ error: "delisted", detail: "usc-statute was retired in the 2026-07-03 concentration cut — no longer served." });
});

/**
 * address-reputation — the agentic-payments go/no-go verdict (FEED_ROADMAP #1).
 * Body: { domain: string, address: 0x…, amount?: int, chain?: "base"|"arbitrum" }
 * 200: { answer: { verdict: ALLOW|WARN|BLOCK, score, reasons, signals, … },
 *        attestation: { payloadHash, signature, signer, domain, … },
 *        broadcast: { … disabled } }
 *
 * The 200 is forwarded BYTE-FOR-BYTE (no parse/re-stringify — the verdict's
 * embedded attestation signs the canonical insertion-order bytes, and values
 * like balance_wei can exceed 2^53, so a JSON round-trip could corrupt them)
 * and the gateway signs those same bytes into X-BYTE-Attestation: the paid
 * response carries both the publisher's verdict receipt and the gateway's
 * transport receipt over identical bytes.
 */
app.post("/feeds/address-reputation", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.addressReputationUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      // SUBJECT-PROBING route: 30s, not the 15s default — this upstream runs
      // rdap + tls + dns + wayback + on-chain RPC sequentially against the
      // caller-named subject. See SLOW_UPSTREAM_FETCH_TIMEOUT_MS.
      signal: AbortSignal.timeout(SLOW_UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("address-reputation", err);
    res.status(502).json({ error: "address-reputation proxy failed", detail: proxyFailureDetail(err, SLOW_UPSTREAM_FETCH_TIMEOUT_MS) });
  }
});

/** merchant-screen — pre-settlement merchant/storefront screen (x402 #225 ask).
 *  Body: { domain: string, address?: 0x…, observed_price_atomic?: string, chain?: "base" }
 *  200: { answer: { verdict, score, reasons, signals, … }, attestation: { … }, broadcast: { … disabled } }
 *  Forwarded BYTE-FOR-BYTE (sendAttestedRaw): the gateway signs the identical bytes into
 *  X-BYTE-Attestation, so the paid response carries the publisher's verdict receipt and
 *  the gateway's transport receipt over the same bytes. `observed_price_atomic` is a
 *  STRING upstream (may exceed 2^53) — never round-tripped through a JSON number here. */
app.post("/feeds/merchant-screen", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.merchantScreenUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      // SUBJECT-PROBING route: 30s, not the 15s default — this upstream runs
      // RDAP + live TLS + redirect + manifest probes sequentially against the
      // screened merchant. See SLOW_UPSTREAM_FETCH_TIMEOUT_MS.
      signal: AbortSignal.timeout(SLOW_UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("merchant-screen", err);
    res.status(502).json({ error: "merchant-screen proxy failed", detail: proxyFailureDetail(err, SLOW_UPSTREAM_FETCH_TIMEOUT_MS) });
  }
});

/**
 * pkg-verdict — supply-chain install gate (FEED_ROADMAP).
 * Body: { ecosystem: "npm"|"pypi", package: string, version?: string }
 * 200: { answer: { verdict: ALLOW|WARN|BLOCK, … }, attestation: { … }, broadcast: { … } }
 *
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw) — the feed's embedded EIP-712
 * PayloadAttestation signs the canonical answer bytes; a JSON round-trip
 * would corrupt the insertion-order canonical form.
 */
app.post("/feeds/pkg-verdict", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.pkgVerdictUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      // SLOW MULTI-LEG route: 30s, not the 15s default. NOT probing — this
      // upstream queries public package registries, not a caller-named subject
      // — it qualifies on sequential legs alone (up to 3 registry/OSV calls at
      // 20s each). See SLOW_UPSTREAM_FETCH_TIMEOUT_MS.
      signal: AbortSignal.timeout(SLOW_UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("pkg-verdict", err);
    res.status(502).json({ error: "pkg-verdict proxy failed", detail: proxyFailureDetail(err, SLOW_UPSTREAM_FETCH_TIMEOUT_MS) });
  }
});

/**
 * sanctions-screen — OFAC SDN + Consolidated sanctions screening.
 * Body: { address?: 0x…, name?: string, chain?: string }  (at least one of address|name)
 * 200: { answer: { verdict: ALLOW|WARN|BLOCK, list_state, … }, attestation: { … }, broadcast: { … } }
 *
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw).
 */
app.post("/feeds/sanctions-screen", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.sanctionsScreenUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      // EVIDENCE TTL (staged 2026-08-17, uncommitted — see
      // scratchpad/EVIDENCE_TTL_CHANGE.md): this is the ONLY call site passing
      // { feed } — sanctions-screen is the sole entry in attestation.ts's
      // EVIDENCE_FEED_IDS allowlist, so this is the ONLY response whose
      // receipt deadline differs from the 300s default. Every other
      // sendAttested/sendAttestedRaw call in this file is untouched.
      await sendAttestedRaw(res, text, { feed: "sanctions-screen" });
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("sanctions-screen", err);
    res.status(502).json({ error: "sanctions-screen proxy failed", detail: proxyFailureDetail(err) });
  }
});

/**
 * reasoning-verdict — GPU-backed local-LLM verify-before-act oracle.
 * Body: { subject: string, kind?: string, context?: string|object }
 * 200: { answer: { verdict: ALLOW|WARN|BLOCK|ABSTAIN, score, summary, reasons[], … },
 *        attestation: { … }, broadcast: { … } }
 *
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw): the verdict's embedded EIP-712
 * PayloadAttestation signs the canonical answer bytes; a JSON round-trip would
 * corrupt the insertion-order canonical form. The upstream FAILS CLOSED (502)
 * on an unusable model output, so a bogus/blank verdict is never served.
 */
app.post("/feeds/reasoning-verdict", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.reasoningVerdictUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("reasoning-verdict", err);
    res.status(502).json({ error: "reasoning-verdict proxy failed", detail: proxyFailureDetail(err) });
  }
});

/**
 * runtime-eol (POST gate) — deterministic signed end-of-life verdict.
 * Body: { product: string, version: string }   (e.g. { product: "nodejs", version: "18" })
 * 200: { answer: { status, verdict: ALLOW|WARN|BLOCK|ABSTAIN, eol, days_until_eol, … },
 *        attestation: { … }, broadcast: { … } }
 *
 * Dual feed: GET /feeds/runtime-eol serves the publisher EOL broadcast; this POST
 * is the decision tier (a per-version "supported as of T" compliance receipt).
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw); the gate FAILS CLOSED (502) when
 * endoflife.date is unreachable.
 */
app.post("/feeds/runtime-eol", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.runtimeEolGateUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("runtime-eol", err);
    res.status(502).json({ error: "runtime-eol gate proxy failed", detail: proxyFailureDetail(err) });
  }
});

/**
 * threat-intel (POST gate) — signed CISA-KEV exploit-exposure verdict.
 * Body: { components: [string, …] }   (product/vendor/package names or CVE ids)
 * 200: { answer: { verdict: ALLOW|WARN|BLOCK|ABSTAIN, matches[], kev_catalog{version,sha256}, … },
 *        attestation: { … }, broadcast: { … } }
 *
 * Dual feed: GET /feeds/threat-intel serves the publisher KEV/CVE digest; this POST
 * is the decision tier ("is anything I run actively exploited?"), with the pinned
 * KEV catalog version/date/sha256 in the signed receipt. Forwarded BYTE-FOR-BYTE
 * (sendAttestedRaw); FAILS CLOSED (502) when CISA is unreachable.
 */
app.post("/feeds/threat-intel", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.threatIntelGateUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("threat-intel", err);
    res.status(502).json({ error: "threat-intel gate proxy failed", detail: proxyFailureDetail(err) });
  }
});

/**
 * token-safety — DELISTED 2026-06-12 (honeypot/rug/mint go/no-go). Its provider
 * licensing contract (ts-v1) is not finalized, so it is NOT in feedRegistry and
 * NOT in the priced catalog. It is kept as an explicit 410-Gone stub (NOT a live
 * proxy) so the route FAILS CLOSED: it never reaches the upstream and never
 * serves data — closing the dangling-route leak class (a handler outside the
 * payment gate would serve paid data free the moment its upstream came up).
 *
 * Re-list = restore the proxy body AND add a feedRegistry entry so the payment
 * gate covers it (and re-add it to POST_ORACLES + openapi POST_ORACLE_IDS).
 * Until then the pre-ship gate-engagement check
 * (scripts/gate-engagement-check.mjs) asserts this route stays 404/410.
 */
app.post("/feeds/token-safety", (_req, res) => {
  res.status(410).json({
    error: "delisted",
    detail:
      "token-safety is delisted pending its provider licensing contract — it is not " +
      "currently served. It will return until re-listed with a payment gate.",
  });
});

/**
 * liquidation-stream — DELISTED 2026-07-28 (founder-approved, in-session): the
 * realized-liquidation collector has been dead since 2026-06-12 (no live
 * venue legs — see byte-liquidation-stream-api.service healthz
 * archive_days=[2026-06-09,2026-06-12]), so a paid query can only answer
 * INSUFFICIENT_DATA off a 7-week-stale archive. NOT in feedRegistry
 * (lib/config.ts) — no payment gate — so this is an explicit 410-Gone stub
 * (NOT a live proxy), matching the token-safety pattern: the route FAILS
 * CLOSED and never reaches the upstream, closing the dangling-route leak
 * class (a handler outside the payment gate would serve paid data free the
 * moment its upstream came up).
 *
 * Re-list = restore a live venue feed to the collector, restore the proxy
 * body, and re-add a feedRegistry entry so the payment gate covers it (and
 * re-add to POST_ORACLES + openapi POST_ORACLE_IDS). Until then the pre-ship
 * gate-engagement check (scripts/gate-engagement-check.mjs) asserts this
 * route stays 404/410.
 */
app.post("/feeds/liquidation-stream", (_req, res) => {
  res.status(410).json({
    error: "delisted",
    detail:
      "liquidation-stream is delisted pending a live venue-data collector — it is not " +
      "currently served. It will return once re-listed with a payment gate.",
  });
});

/**
 * positioning-snapshot — cross-venue perp positioning snapshot.
 * Body: { assets?: string[] }  (default BTC,ETH,SOL,ARB,AVAX)
 * 200: { answer: { verdict: COMPLETE|PARTIAL|UNAVAILABLE, signals: { assets: […] }, … },
 *        attestation: { … }, broadcast: { … } }
 *
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw).
 */
app.post("/feeds/positioning-snapshot", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.positioningSnapshotUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      // Bounded — a hung upstream must not hang the paying agent. Aborting
      // throws into the catch below (502, settlement cancelled): FAIL CLOSED.
      signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: safeUpstreamDetail(text) });
    }
  } catch (err: any) {
    logProxyFailure("positioning-snapshot", err);
    res.status(502).json({ error: "positioning-snapshot proxy failed", detail: proxyFailureDetail(err) });
  }
});

// BYTE Library publisher-backed feeds — generic handler serving the current
// payload. Driven by feedRegistry; adding a publisher only requires editing
// config.ts. fetchFeedPayload() (feeds/generic.ts) prefers each feed's live
// companion service (FEED_LIVE_URL, opt-in per feed — P1 fix 2026-07-28) over
// the discovery-api broadcast archive, and FAILS CLOSED (throws -> 502 here)
// rather than ever resolve with null or stale-beyond-tolerance data, so a
// paying caller is never charged for either (a >=400 response makes the x402
// middleware cancel settlement).
for (const feed of feedRegistry) {
  if (!feed.publisher) continue;
  const publisher = feed.publisher;
  const slug = feed.id;
  app.get(feed.endpoint, async (_req, res) => {
    try {
      const payload = await fetchFeedPayload({
        slug,
        publisher,
        liveUrl: FEED_LIVE_URL[slug] || undefined,
        staleAfterS: FEED_STALE_AFTER_S[slug],
      });
      if (payload.rawDataBytes !== undefined) {
        // Live-sourced (FD 2026-07-28, BLOCKER 3): splice the live-query
        // companion's `data` bytes VERBATIM into the envelope — never
        // JSON.stringify the parsed `payload` object for this case. A
        // parse -> re-stringify round trip can silently change bytes (e.g.
        // Python's json.dumps renders a float as "10.0"; the same value
        // survives JSON.parse -> JSON.stringify in Node as "10"), which
        // would break the `live` verify recipe's keccak256 recompute over
        // responseBody.data.answer — there is no on-chain fallback for a
        // live response the way there is for a broadcast one. Matches the
        // POST-oracle sendAttestedRaw discipline (lib/attestation.ts). The
        // wrapper fields (feed/publisher/timestamp/payloadHash) are plain
        // strings — JSON.stringify of a string is lossless, so only `data`
        // needs verbatim splicing.
        const body =
          `{"feed":${JSON.stringify(payload.feed)}` +
          `,"publisher":${JSON.stringify(payload.publisher)}` +
          `,"timestamp":${JSON.stringify(payload.timestamp)}` +
          `,"source":"live"` +
          (payload.payloadHash ? `,"payloadHash":${JSON.stringify(payload.payloadHash)}` : "") +
          `,"data":${payload.rawDataBytes}}`;
        await sendAttestedRaw(res, body);
      } else {
        // X-BYTE-Attestation: sign the exact bytes we return (verify-before-act).
        await sendAttested(res, payload);
      }
    } catch (err: any) {
      logProxyFailure(slug, err);
      res.status(502).json({ error: `Failed to fetch ${slug}`, detail: "upstream unavailable" });
    }
  });
}

// 404 — structured, with a /feeds/ hint. Agents that read agent.json skill ids
// and forget the /feeds/ prefix (GET /defi-yields) land here; point them at the
// real paid path. Registered after all routes, before the error handler.
app.use((req, res) => {
  // Method-mismatch on a known feed PATH → 405 (not a circular 404). E.g. a GET
  // to a POST-only oracle: tell the dev exactly which verb(s) the path accepts
  // instead of 404-pointing at the same path they just tried. Uses the live
  // paymentRoutes map so it stays in lockstep with the gated routes. (HEAD is
  // already 405'd upstream; delisted slugs aren't in paymentRoutes so they keep
  // their 404/410.)
  const np = normalizeGatePath(req.path);
  const allowed = ["GET", "POST"].filter((m) => paymentRoutes[`${m} ${np}`]);
  if (allowed.length > 0 && !allowed.includes(String(req.method).toUpperCase())) {
    res.setHeader("Allow", allowed.join(", "));
    return res.status(405).json({
      error: "method_not_allowed",
      detail: `${req.path} requires ${allowed.join(" or ")} — you used ${req.method}. See /openapi.json for the request contract.`,
    });
  }
  const slug = req.path.replace(/^\/+/, "").replace(/\/+$/, "").toLowerCase();
  const known = feedRegistry.some((f) => f.id === slug);
  res.status(404).json({
    error: "not_found",
    detail: known
      ? `No route at ${req.path}. This feed is served at /feeds/${slug} (paid x402).`
      : `No route at ${req.path}. Browse the catalog at /feeds; each feed is served at /feeds/<slug>.`,
  });
});

// ---------------------------------------------------------------------------
// Error handler — MUST be the last middleware (4-arg signature). Without it,
// express.json() body errors hit Express's default handler, which leaks an HTML
// stack trace incl. the absolute path /home/orkz/byte/x402-gateway/... Return a
// structured JSON error with NO path/stack: malformed JSON → 400, oversized body
// → 413, everything else → 500. (eslint-disable: the unused `next` is required
// to mark this as a 4-arg Express error handler.)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (res.headersSent) return;
  const type = err?.type;
  if (err instanceof SyntaxError || type === "entity.parse.failed") {
    return res.status(400).json({
      error: "invalid_json",
      detail: "Request body is not valid JSON.",
    });
  }
  if (type === "entity.too.large" || err?.status === 413 || err?.statusCode === 413) {
    return res.status(413).json({
      error: "payload_too_large",
      detail: "Request body exceeds the 32 KB limit.",
    });
  }
  // Never echo err.message/stack (path-leak class). Generic, opaque 500.
  console.error(`[x402-gateway] unhandled error: ${err instanceof Error ? err.message : err}`);
  return res.status(500).json({ error: "internal_error" });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(config.port, () => {
  console.log(`[x402-gateway] Byte Protocol data feed gateway running on port ${config.port}`);
  console.log(`[x402-gateway] EVM Network: ${config.network}`);
  console.log(`[x402-gateway] EVM PayTo: ${config.payTo}`);
  if (config.solanaPayTo && ExactSvmScheme) {
    console.log(`[x402-gateway] Solana Network: ${config.solanaNetwork}`);
    console.log(`[x402-gateway] Solana PayTo: ${config.solanaPayTo}`);
  }
  console.log(`[x402-gateway] Pricing: $${(Number(config.pricePerKBAtomic) / 1_000_000).toFixed(6)}/KB (floor $${(Number(config.priceFloorAtomic) / 1_000_000).toFixed(6)})`);
  console.log(`[x402-gateway] USDC asset: ${config.usdcAddress} (domain="${config.usdcDomainName}" v${config.usdcDomainVersion})`);
  console.log(`[x402-gateway] Facilitator: ${config.facilitatorUrl}`);
  console.log(`[x402-gateway] Feeds available: ${feedRegistry.length}`);
  for (const f of feedRegistry) {
    console.log(`[x402-gateway]   ${f.endpoint.padEnd(28)} ${f.price.padStart(8)} (${f.expectedSizeBytes}B)`);
  }
});
