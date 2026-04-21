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
/** Build the accepts array — EVM always, Solana if configured. */
function buildAccepts() {
  const accepts: any[] = [
    {
      scheme: "exact",
      price: `$${config.requestPrice}`,
      network: config.network,
      payTo: config.payTo,
    },
  ];

  // Add Solana payment option if wallet is configured
  if (config.solanaPayTo && ExactSvmScheme) {
    accepts.push({
      scheme: "exact",
      price: `$${config.requestPrice}`,
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
};

/**
 * Build the x402 resource server that verifies payment receipts.
 * Uses the HTTPFacilitatorClient for remote verification and the
 * ExactEvmScheme for EVM-compatible payment settlement.
 */
// Payment middleware setup is deferred — facilitator may not be reachable.
// Gateway runs in discovery mode (free feeds) until facilitator DNS resolves.
async function setupPaymentMiddleware() {
  try {
    const facilitator = new HTTPFacilitatorClient({ url: config.facilitatorUrl });
    const server = new x402ResourceServer(facilitator)
      .register(config.network, new ExactEvmScheme());

    if (ExactSvmScheme && config.solanaPayTo) {
      server.register(config.solanaNetwork, new ExactSvmScheme());
      console.log(`[x402-gateway] Solana payments enabled: ${config.solanaNetwork}`);
    }

    app.use(paymentMiddleware(paymentRoutes, server, undefined, undefined, false));
    console.log("[x402-gateway] Payment middleware active");
  } catch (e) {
    console.warn("[x402-gateway] Payment middleware disabled -- feeds served free in discovery mode");
    console.warn(`[x402-gateway] Reason: ${e instanceof Error ? e.message : e}`);
  }
}

// Non-blocking — don't let facilitator failure prevent startup
setupPaymentMiddleware().catch(() => {});

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
    pricePerRequest: `$${config.requestPrice}`,
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
  console.log(`[x402-gateway] Price per request: $${config.requestPrice}`);
  console.log(`[x402-gateway] Facilitator: ${config.facilitatorUrl}`);
  console.log(`[x402-gateway] Feeds available: ${feedRegistry.length}`);
});
