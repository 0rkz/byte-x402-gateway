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
import { HTTPFacilitatorClient } from "@x402/core/server";
import { config, feedRegistry, DISCLAIMER_TEXT } from "./lib/config.js";
import { buildOpenApiDoc } from "./lib/openapi.js";
import { fetchCryptoTop100 } from "./feeds/crypto.js";
import { fetchDefiYields } from "./feeds/defi.js";
import { fetchLatestPublisherPayload } from "./feeds/generic.js";
import {
  sendAttested,
  attestationEnabled,
  attesterAddress,
  attestationDomain,
} from "./lib/attestation.js";

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
const POST_ORACLES = new Set(["fact-oracle", "evidence-pack", "usc-statute"]);

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
      input: {},
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
      extensions: getExtensions(feed.id, true),
    };
  }
  if (feed.publisher) {
    // Publisher-backed feeds also serve the latest broadcast via GET — gate it.
    paymentRoutes[`GET ${feed.endpoint}`] = {
      accepts,
      description: feed.description,
      extensions: getExtensions(feed.id, false),
    };
  } else if (!POST_ORACLES.has(feed.id)) {
    // Bespoke non-oracle feeds (crypto-top100, defi-yields) are GET.
    paymentRoutes[`GET ${feed.endpoint}`] = {
      accepts,
      description: feed.description,
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

/** True iff this exact method+path is one of the payment-gated routes. */
function isPaidRoute(req: any): boolean {
  return Boolean(paymentRoutes[`${req.method} ${req.path}`]);
}

/**
 * Build the x402 payment middleware. Returns true on success, false (rather
 * than throwing) if the facilitator is unreachable — so the caller can retry.
 */
async function setupPaymentMiddleware(): Promise<boolean> {
  try {
    const facilitator = new HTTPFacilitatorClient({ url: config.facilitatorUrl });
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
  const cat = disclaimerByPath.get(req.path);
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
    protocol: "BYTE Library x402 Gateway",
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
    feeds: feedRegistry,
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
 * x402 resource discovery manifest (/.well-known/x402.json). Pull-based
 * discovery: x402 indexers (x402scan, x402engine, CDP discovery) crawl a
 * well-known path to enumerate payable resources without manual submission.
 * Complements the per-route Bazaar discovery extension (which feeds
 * Coinbase's CDP crawler specifically) by exposing the same catalog to
 * non-Coinbase indexers and the DNS-TXT discovery draft's manifest fetch.
 * Free, ungated; self-updates from feedRegistry.
 */
function buildX402Manifest() {
  return {
    x402Version: 1,
    name: "BYTE Library",
    description:
      "Per-byte USDC data feeds + oracles for AI agents on Arbitrum. First-party, verifiable, no token. Arbitrum Sepolia testnet.",
    provider: { organization: "BYTEDev Inc.", url: "https://www.payperbyte.io" },
    network: config.network,
    status: "testnet",
    facilitator: config.facilitatorUrl,
    catalog: "https://x402.payperbyte.io/feeds",
    resources: feedRegistry.map((feed) => ({
      resource: `https://x402.payperbyte.io${feed.endpoint}`,
      method: POST_ORACLES.has(feed.id) ? "POST" : "GET",
      name: feed.name,
      description: feed.description,
      category: feed.disclaimerCategory,
      provenance: feed.provenance,
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
  res.json({
    name: "BYTE Library",
    description:
      "Per-byte USDC data feeds + oracles for AI agents on Arbitrum. Subscribe to first-party feeds or pay-per-call via x402; every data response carries an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation) you verify before acting.",
    url: "https://x402.payperbyte.io",
    version: "0.3.0",
    provider: { organization: "BYTEDev Inc.", url: "https://www.payperbyte.io" },
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
    // X-BYTE-Attestation header. Omitted here only if no attestation key is set.
    receipt: attestationEnabled()
      ? {
          header: "X-BYTE-Attestation",
          scheme: "EIP712-PayloadAttestation",
          domain: attestationDomain(),
          attester: attesterAddress(),
          verify:
            "keccak256(responseBody) === payloadHash AND " +
            "recoverTypedDataAddress(domain, {PayloadAttestation}, message, signature) === attester",
        }
      : undefined,
    skills: feedRegistry.map((feed) => ({
      id: feed.id,
      name: feed.name,
      description: feed.description,
      tags: [feed.disclaimerCategory, "x402", "usdc", "arbitrum"],
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

/** Top 25 cryptocurrencies by market cap. */
app.get("/feeds/crypto-top100", async (_req, res) => {
  try {
    const data = await fetchCryptoTop100();
    await sendAttested(res, data);
  } catch (err: any) {
    res.status(502).json({ error: "Failed to fetch crypto data", detail: err.message });
  }
});

/** Top DeFi yield pools across major chains. */
app.get("/feeds/defi-yields", async (_req, res) => {
  try {
    const data = await fetchDefiYields();
    await sendAttested(res, data);
  } catch (err: any) {
    res.status(502).json({ error: "Failed to fetch DeFi yield data", detail: err.message });
  }
});

/**
 * Byte Fact Oracle — slashable factual Q&A.
 *
 * The gateway accepts an x402 payment, then forwards the question to
 * fact-oracle.payperbyte.io. fact-oracle returns a 202 ack; the actual
 * answer is delivered on-chain via DataStream.streamBroadcast to the
 * subscriber address provided in the request body.
 *
 * Body: { question: string, subscriber_address: 0x..., max_byte_cost?: int }
 *   - subscriber_address: where the on-chain answer is broadcast to
 *   - max_byte_cost: optional cap on payload size (default 2000)
 * 200: { request_id, est_eta_ms, publisher } (relayed from fact-oracle)
 * Non-2xx from fact-oracle is forwarded with its body.
 */
app.post("/feeds/fact-oracle", async (req, res) => {
  try {
    const body = req.body ?? {};
    const upstream = await fetch(`${config.factOracleUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await upstream.text();
    res.status(upstream.status).type(upstream.headers.get("content-type") ?? "application/json").send(text);
  } catch (err: any) {
    res.status(502).json({ error: "fact-oracle proxy failed", detail: err.message });
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
    res.status(upstream.status).type(upstream.headers.get("content-type") ?? "application/json").send(text);
  } catch (err: any) {
    res.status(502).json({ error: "evidence-pack proxy failed", detail: err.message });
  }
});

/**
 * usc-statute — US Code statute Q&A oracle.
 * Body: { citation: string, subscriber_address?, subscriber_signature?, request_nonce?, deadline_unix? }
 *
 * Note: usc-statute is also registered as a publisher-backed indexerFeed
 * (the generic loop below sets up the GET route serving the latest broadcast).
 * This explicit POST proxy is the request-response synchronous path for
 * agents that don't want to subscribe — same dual-pattern as fact-oracle.
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
    res.status(upstream.status).type(upstream.headers.get("content-type") ?? "application/json").send(text);
  } catch (err: any) {
    res.status(502).json({ error: "usc-statute proxy failed", detail: err.message });
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
      res.status(502).json({ error: `Failed to fetch ${slug}`, detail: err.message });
    }
  });
}

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
