/**
 * BYTE x402 — agent-pays demo (TypeScript, PRIMARY)
 * =================================================
 * An autonomous agent that GETs a paid BYTE feed, lets the x402 client
 * auto-handle the HTTP 402 by signing a gasless USDC payment on Base, retries,
 * and prints the feed data + the on-chain settlement tx hash + a Basescan link.
 *
 * Matches the gateway's SDK exactly: @x402/core + @x402/evm v2.13.x, viem.
 * No high-level `wrapFetchWithPayment` exists in this v2 SDK — we compose the
 * documented primitives: x402Client (with ExactEvmScheme) -> x402HTTPClient ->
 * a small fetch loop. The wallet only SIGNS an EIP-3009 authorization; the
 * facilitator broadcasts + pays gas, so the agent needs USDC but no ETH.
 *
 * Run:
 *   npm install
 *   AGENT_PRIVATE_KEY=0x... npm start                 # defaults to x402-pulse on Base Sepolia
 *   AGENT_PRIVATE_KEY=0x... GATEWAY_URL=https://x402.payperbyte.io \
 *     FEED_PATH=/feeds/x402-pulse NETWORK=base-mainnet npm start
 *
 * Env:
 *   AGENT_PRIVATE_KEY  (REQUIRED) funded test/agent wallet private key. NEVER hardcode.
 *   GATEWAY_URL        gateway base URL (default http://127.0.0.1:3402)
 *   FEED_PATH          feed endpoint to buy (default /feeds/x402-pulse)
 *   NETWORK            "base-sepolia" (default) | "base-mainnet" — picks chain + Basescan host
 *   RPC_URL            optional override for the Base RPC (defaults to viem public RPC)
 */

import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

// ── Config from env ────────────────────────────────────────────────────────
const PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY as `0x${string}` | undefined;
const GATEWAY_URL = (process.env.GATEWAY_URL ?? "http://127.0.0.1:3402").replace(/\/$/, "");
const FEED_PATH = process.env.FEED_PATH ?? "/feeds/x402-pulse";
const NETWORK = process.env.NETWORK ?? "base-sepolia";

if (!PRIVATE_KEY) {
  console.error("ERROR: set AGENT_PRIVATE_KEY (a funded Base test wallet). Never hardcode it.");
  process.exit(1);
}
if (!/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) {
  console.error("ERROR: AGENT_PRIVATE_KEY must be a 0x-prefixed 32-byte hex private key.");
  process.exit(1);
}

const isMainnet = NETWORK === "base-mainnet";
const chain = isMainnet ? base : baseSepolia;
const basescan = isMainnet ? "https://basescan.org" : "https://sepolia.basescan.org";

// ── Wallet + signer ─────────────────────────────────────────────────────────
// The viem account satisfies the x402 ClientEvmSigner interface (address +
// signTypedData). We wrap it with a public client via toClientEvmSigner so the
// scheme can do optional on-chain reads (nonce/allowance) when needed.
const account = privateKeyToAccount(PRIVATE_KEY);
const publicClient = createPublicClient({
  chain,
  transport: http(process.env.RPC_URL),
});
const signer = toClientEvmSigner(account, publicClient);

// ── x402 client: exact-EVM scheme on Base, wrapped for HTTP ─────────────────
const core = registerExactEvmScheme(new x402Client(), { signer });
const x402 = new x402HTTPClient(core);

/**
 * One paid request. Sends the request; if the gateway answers 402, signs a
 * payment for the advertised requirements and retries with the payment header;
 * returns the parsed x402PaymentResult.
 */
async function payAndFetch(url: string, init: RequestInit = {}) {
  // 1) Unpaid attempt — discovers the 402 + payment requirements.
  const first = await fetch(url, init);
  if (first.status !== 402) {
    // Free route, error, or already paid — hand back as-is.
    return { result: await x402.processResponse(first), paid: false };
  }

  // 2) Parse the PaymentRequired (header on v2, body on v1) and build a payload.
  const paymentRequired = x402.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.clone().json().catch(() => undefined),
  );
  const payload = await x402.createPaymentPayload(paymentRequired);
  const paymentHeaders = x402.encodePaymentSignatureHeader(payload);

  // 3) Retry the SAME request with the signed payment header attached.
  const paidResp = await fetch(url, {
    ...init,
    headers: { ...(init.headers ?? {}), ...paymentHeaders },
  });
  return { result: await x402.processResponse(paidResp), paid: true };
}

async function main() {
  const url = `${GATEWAY_URL}${FEED_PATH}`;
  console.log(`[agent] wallet      : ${account.address}`);
  console.log(`[agent] network     : ${NETWORK} (chainId ${chain.id})`);
  console.log(`[agent] buying      : GET ${url}`);

  const { result, paid } = await payAndFetch(url, { method: "GET" });

  switch (result.kind) {
    case "success": {
      const s = result.settleResponse;
      console.log(`\n[agent] PAID + SETTLED ${paid ? "" : "(was free)"}`.trimEnd());
      console.log(`[agent] settlement  : success=${s.success} payer=${s.payer ?? account.address}`);
      console.log(`[agent] tx hash     : ${s.transaction}`);
      console.log(`[agent] basescan    : ${basescan}/tx/${s.transaction}`);
      console.log(`\n[agent] feed data   :\n${JSON.stringify(result.body, null, 2)}`);
      break;
    }
    case "passthrough":
      console.log(`\n[agent] free / no payment required:\n${JSON.stringify(result.body, null, 2)}`);
      break;
    case "settle_failed":
      console.error(`\n[agent] PAYMENT SIGNED BUT SETTLE FAILED.`);
      console.error(`[agent] settleResponse: ${JSON.stringify(result.settleResponse, null, 2)}`);
      console.error(`[agent] body: ${JSON.stringify(result.body, null, 2)}`);
      process.exit(2);
      break;
    case "payment_required":
      console.error(`\n[agent] still 402 after paying — requirements:`);
      console.error(JSON.stringify(result.paymentRequired, null, 2));
      process.exit(2);
      break;
    case "error":
      console.error(`\n[agent] gateway error ${result.status}: ${JSON.stringify(result.body)}`);
      process.exit(2);
      break;
  }
}

main().catch((err) => {
  console.error(`[agent] fatal: ${err instanceof Error ? err.stack : err}`);
  process.exit(1);
});
