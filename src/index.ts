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
const paymentRoutes: Record<string, any> = {
  "GET /feeds/crypto-top100": {
    accepts: {
      scheme: "exact",
      price: `$${config.requestPrice}`,
      network: config.network,
      payTo: config.payTo,
    },
    description:
      "Top 25 crypto prices, market caps, 24h change from CoinGecko",
  },
  "GET /feeds/defi-yields": {
    accepts: {
      scheme: "exact",
      price: `$${config.requestPrice}`,
      network: config.network,
      payTo: config.payTo,
    },
    description: "Top DeFi yields across major chains from DeFiLlama",
  },
  "GET /feeds/byte-status": {
    accepts: {
      scheme: "exact",
      price: `$${config.requestPrice}`,
      network: config.network,
      payTo: config.payTo,
    },
    description: "Byte Protocol live status and metrics",
  },
};

/**
 * Build the x402 resource server that verifies payment receipts.
 * Uses the HTTPFacilitatorClient for remote verification and the
 * ExactEvmScheme for EVM-compatible payment settlement.
 */
function createResourceServer(): x402ResourceServer | null {
  try {
    const facilitator = new HTTPFacilitatorClient({ url: config.facilitatorUrl });
    return new x402ResourceServer(facilitator)
      .register(config.network, new ExactEvmScheme());
  } catch {
    return null;
  }
}

const resourceServer = createResourceServer();

if (resourceServer) {
  app.use(paymentMiddleware(paymentRoutes, resourceServer));
} else {
  console.warn("[x402-gateway] Payment middleware disabled -- feeds served free in discovery mode");
}

// ---------------------------------------------------------------------------
// Free Endpoints
// ---------------------------------------------------------------------------

/** Feed discovery endpoint -- returns all available feeds with pricing and PQS scores. */
app.get("/feeds", (_req, res) => {
  res.json({
    protocol: "Byte Protocol x402 Gateway",
    version: "0.1.0",
    network: config.network,
    facilitator: config.facilitatorUrl,
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
  console.log(`[x402-gateway] Network: ${config.network}`);
  console.log(`[x402-gateway] PayTo: ${config.payTo}`);
  console.log(`[x402-gateway] Price per request: $${config.requestPrice}`);
  console.log(`[x402-gateway] Facilitator: ${config.facilitatorUrl}`);
  console.log(`[x402-gateway] Feeds available: ${feedRegistry.length}`);
});
