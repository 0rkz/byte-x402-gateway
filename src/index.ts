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
import { config, feedRegistry, DISCLAIMER_TEXT, networkInfo } from "./lib/config.js";
import { buildOpenApiDoc, ORACLE_REQUEST_SCHEMAS, ORACLE_REQUEST_EXAMPLES } from "./lib/openapi.js";
import { fetchDefiYields } from "./feeds/defi.js";
import { fetchLatestPublisherPayload } from "./feeds/generic.js";
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
const POST_ORACLES = new Set(["evidence-pack", "usc-statute", "address-reputation", "pkg-verdict", "sanctions-screen", "liquidation-stream", "positioning-snapshot", "reasoning-verdict", "runtime-eol", "threat-intel"]);

// Bazaar discovery extension per route. Minimal output examples per feed shape
// — just enough for checkIfBazaarNeeded() in @x402/express to detect the
// extension and auto-register bazaarResourceServerExtension on the server.
// Per-feed enrichment (richer example payloads, input schemas, route templates)
// can be incremental — Agentic Market's validator only needs the extension
// surface to be present. See @x402/extensions/bazaar for the full schema.
//
// Note: the input config OMITS `method` — it's inferred from the route key
// (`GET /...` vs `POST /...`) and filled in later by
// bazaarResourceServerExtension.enrichDeclaration. The `bodyType` field is
// the discriminant between Query (GET/HEAD/DELETE) and Body (POST/PUT/PATCH)
// variants of the union.
function getExtensions(feedId: string, isPost: boolean): Record<string, unknown> {
  if (isPost) {
    return declareDiscoveryExtension({
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
      output: { example: { feed: feedId } },
    });
  }
  return declareDiscoveryExtension({
    output: { example: { feed: feedId } },
  });
}

const paymentRoutes: Record<string, any> = {};
for (const feed of feedRegistry) {
  const accepts = buildAccepts(feed.priceAtomic);
  if (POST_ORACLES.has(feed.id)) {
    paymentRoutes[`POST ${feed.endpoint}`] = {
      accepts,
      description: feed.description,
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

/**
 * Build the x402 payment middleware. Returns true on success, false (rather
 * than throwing) if the facilitator is unreachable — so the caller can retry.
 */
async function setupPaymentMiddleware(): Promise<boolean> {
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

// ── Universal disclaimer header (§14) ──────────────────────────────────────
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
    pricing: {
      model: "per-byte",
      pricePerKB: `$${(Number(config.pricePerKBAtomic) / 1_000_000).toFixed(6)}`,
      floor: `$${(Number(config.priceFloorAtomic) / 1_000_000).toFixed(6)}`,
      note: "Per-feed price = max(floor, ceil(expectedSizeBytes / 1024 × pricePerKB)). Each feed entry below carries its computed price + expectedSizeBytes.",
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
        // POST verdict oracles: the signature is EMBEDDED in the response body's
        // `attestation` object — recover it directly.
        oracle:
          "recompute keccak256(canonical(answer)) === attestation.payloadHash AND " +
          "recoverTypedDataAddress(domain, {PayloadAttestation}, message, attestation.signature) " +
          "=== attestation.signer (the feed's own per-feed key — NOT the gateway attester).",
      },
      note:
        "A distinct per-feed key, separate from the gateway X-BYTE-Attestation header. " +
        "First-party PayPerByte (not an independent third-party data source), NOT a " +
        "correctness guarantee. `signers` lists the on-chain publisher key per attested " +
        "feed; feeds absent from it carry only the gateway header receipt (the POST verdict " +
        "oracles among them additionally embed their own `attestation` in the body).",
      signers: Object.fromEntries(
        feedRegistry
          .filter((f) => f.provenance === "eip712-attested" && f.publisher)
          .map((f) => [f.id, f.publisher]),
      ),
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
      `Per-byte USDC data feeds and oracles for AI agents (display name: PayPerByte). ${feedRegistry.length} paid x402 resources served from https://x402.payperbyte.io, settled in USDC on Base mainnet (eip155:8453); flagship POST /feeds/address-reputation at $0.05. Every data response carries an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation header) that callers verify before acting.`,
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

/** Health check for load balancers and monitoring. */
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ---------------------------------------------------------------------------
// Paid Endpoints
// ---------------------------------------------------------------------------

// crypto-top100 route REMOVED 2026-06-14 — CoinGecko free-tier no-resale, and it
// served data UNPAID (delisted from feedRegistry → no payment gate). Feed + fetcher
// retired. See OUTSTANDING_ACTIONS §5.4.

/** Top DeFi yield pools across major chains. */
app.get("/feeds/defi-yields", async (_req, res) => {
  try {
    const data = await fetchDefiYields();
    await sendAttested(res, data);
  } catch (err: any) {
    res.status(502).json({ error: "Failed to fetch DeFi yield data", detail: "upstream unavailable" });
  }
});

/**
 * evidence-pack — RAG-citable meta-oracle (LAUNCH_PLAN §13).
 * Body: { claim: string, domains?: string[], max_sources?: int,
 *         subscriber_address?, subscriber_signature?, request_nonce?, deadline_unix? }
 */
app.post("/feeds/evidence-pack", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.evidencePackUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      // Add the gateway X-BYTE-Attestation receipt over the exact bytes — every
      // paid 200 carries it (the agent card advertises this); evidence-pack's
      // own embedded verdict attestation rides inside the body untouched.
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "evidence-pack proxy failed", detail: "upstream unavailable" });
  }
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
app.post("/feeds/usc-statute", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.uscStatuteUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      // Add the gateway X-BYTE-Attestation receipt — usc-statute carries no
      // embedded verdict attestation (it's statute text), so this is its ONLY
      // provenance receipt; without it a paid 200 had zero attestation despite
      // the agent card advertising one on every paid response.
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "usc-statute proxy failed", detail: "upstream unavailable" });
  }
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "address-reputation proxy failed", detail: "upstream unavailable" });
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "pkg-verdict proxy failed", detail: "upstream unavailable" });
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "sanctions-screen proxy failed", detail: "upstream unavailable" });
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "reasoning-verdict proxy failed", detail: "upstream unavailable" });
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "runtime-eol gate proxy failed", detail: "upstream unavailable" });
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "threat-intel gate proxy failed", detail: "upstream unavailable" });
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
 * liquidation-stream — Hawkes cascade-risk regime oracle.
 * Body: { asset: string, window_h?: number }
 * 200: { answer: { verdict: SUBCRITICAL|NEAR_CRITICAL|SUPERCRITICAL|INSUFFICIENT_DATA, … },
 *        attestation: { … }, broadcast: { … } }
 *
 * Forwarded BYTE-FOR-BYTE (sendAttestedRaw).
 */
app.post("/feeds/liquidation-stream", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.liquidationStreamUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "liquidation-stream proxy failed", detail: "upstream unavailable" });
  }
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
    });
    const text = await upstream.text();
    if (upstream.ok) {
      await sendAttestedRaw(res, text);
    } else {
      // Do NOT forward the upstream's raw body/headers — it can carry the upstream
      // host/IP, stack, or internal error text (R4 leak class). Log raw server-side;
      // return a generic body. Preserve a 4xx (caller's fault) but collapse 5xx→502.
      console.error(`[x402-gateway] upstream non-ok ${upstream.status}:`, String(text).slice(0, 500));
      res.status(upstream.status >= 500 ? 502 : upstream.status).json({ error: "upstream error", detail: "upstream error" });
    }
  } catch (err: any) {
    res.status(502).json({ error: "positioning-snapshot proxy failed", detail: "upstream unavailable" });
  }
});

// BYTE Library publisher-backed feeds — generic handler proxying the latest
// archived broadcast from the discovery-api. Driven by feedRegistry; adding a
// publisher only requires editing config.ts.
for (const feed of feedRegistry) {
  if (!feed.publisher) continue;
  const publisher = feed.publisher;
  const slug = feed.id;
  app.get(feed.endpoint, async (_req, res) => {
    try {
      const data = await fetchLatestPublisherPayload({ slug, publisher });
      // X-BYTE-Attestation: sign the exact bytes we return (verify-before-act).
      await sendAttested(res, data);
    } catch (err: any) {
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
