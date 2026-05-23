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
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { config, feedRegistry } from "./lib/config.js";
import { buildOpenApiDoc } from "./lib/openapi.js";
import { fetchCryptoTop100 } from "./feeds/crypto.js";
import { fetchDefiYields } from "./feeds/defi.js";
import { fetchLatestPublisherPayload } from "./feeds/generic.js";

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
// per-feed price (computed from expectedSizeBytes). fact-oracle is POST
// because it carries a request body; everything else is GET.
const paymentRoutes: Record<string, any> = {};
for (const feed of feedRegistry) {
  const method = feed.id === "fact-oracle" ? "POST" : "GET";
  paymentRoutes[`${method} ${feed.endpoint}`] = {
    accepts: buildAccepts(feed.priceAtomic),
    description: feed.description,
  };
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
    res.json(data);
  } catch (err: any) {
    res.status(502).json({ error: "Failed to fetch crypto data", detail: err.message });
  }
});

/** Top DeFi yield pools across major chains. */
app.get("/feeds/defi-yields", async (_req, res) => {
  try {
    const data = await fetchDefiYields();
    res.json(data);
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
      res.json(data);
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
