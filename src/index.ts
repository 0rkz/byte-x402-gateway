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
import { fetchCryptoTop100 } from "./feeds/crypto.js";
import { fetchDefiYields } from "./feeds/defi.js";
import { fetchByteStatus } from "./feeds/status.js";

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
function buildAccepts() {
  const accepts: any[] = [
    {
      scheme: "exact",
      network: config.network,
      payTo: config.payTo,
      price: {
        asset: config.usdcAddress,
        amount: config.requestAmountAtomic,
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
      price: `$${Number(config.requestAmountAtomic) / 1_000_000}`,
      network: config.solanaNetwork,
      payTo: config.solanaPayTo,
    });
  }

  return accepts;
}

const paymentRoutes: Record<string, any> = {
  "GET /feeds/crypto-top100": {
    accepts: buildAccepts(),
    description: "Top 25 crypto prices, market caps, 24h change from CoinGecko",
  },
  "GET /feeds/defi-yields": {
    accepts: buildAccepts(),
    description: "Top DeFi yields across major chains from DeFiLlama",
  },
  "GET /feeds/byte-status": {
    accepts: buildAccepts(),
    description: "Byte Protocol live status and metrics",
  },
  "POST /feeds/fact-query": {
    accepts: buildAccepts(),
    description: "Slashable factual question/answer — proxied to fact-oracle.payperbyte.io; answer delivered on-chain via DataStream broadcast to the subscriber",
  },
};

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

async function setupPaymentMiddleware() {
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
    // payable request — payable feeds 500 instead of returning a clean 402.
    // Inside the try block on purpose: if the facilitator is unreachable at
    // startup, this throws → catch → discovery mode (free feeds), which is the
    // intended graceful-degradation behavior.
    await server.initialize();

    activePaymentMiddleware = paymentMiddleware(paymentRoutes, server, undefined, undefined, false);
    console.log("[x402-gateway] Payment middleware active");
  } catch (e) {
    console.warn("[x402-gateway] Payment middleware disabled -- feeds served free in discovery mode");
    console.warn(`[x402-gateway] Reason: ${e instanceof Error ? e.message : e}`);
  }
}

// Non-blocking — don't let facilitator failure prevent startup
setupPaymentMiddleware().catch(() => {});

// Synchronous pass-through wrapper — MUST be registered before any route so
// Express runs it first. Delegates to the real payment middleware once
// setupPaymentMiddleware() has it ready; until then, next() → discovery mode.
app.use((req, res, next) => {
  if (activePaymentMiddleware) return activePaymentMiddleware(req, res, next);
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
    protocol: "Byte Protocol x402 Gateway",
    version: "0.2.0",
    networks,
    facilitator: config.facilitatorUrl,
    pricePerRequest: `$${(Number(config.requestAmountAtomic) / 1_000_000).toFixed(4)}`,
    pricePerRequestAtomic: config.requestAmountAtomic,
    asset: config.usdcAddress,
    feeds: feedRegistry,
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

/** Live Byte Protocol on-chain metrics. */
app.get("/feeds/byte-status", async (_req, res) => {
  try {
    const data = await fetchByteStatus();
    res.json(data);
  } catch (err: any) {
    res.status(502).json({ error: "Failed to fetch protocol status", detail: err.message });
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
app.post("/feeds/fact-query", async (req, res) => {
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
  console.log(`[x402-gateway] Price per request: ${config.requestAmountAtomic} atomic units ($${Number(config.requestAmountAtomic) / 1_000_000})`);
  console.log(`[x402-gateway] USDC asset: ${config.usdcAddress} (domain="${config.usdcDomainName}" v${config.usdcDomainVersion})`);
  console.log(`[x402-gateway] Facilitator: ${config.facilitatorUrl}`);
  console.log(`[x402-gateway] Facilitator: ${config.facilitatorUrl}`);
  console.log(`[x402-gateway] Feeds available: ${feedRegistry.length}`);
});
