/**
 * ONE-SHOT competitive probe — agentoracle.co /research paid receipt.
 * =================================================================
 * Purpose: make exactly ONE paid x402 call to a COMPETITOR endpoint to observe
 * the paywalled JWS receipt (the one thing not visible on their free routes).
 * Read-only intent otherwise: no contact, no repeat, no data written to them
 * beyond the query string below.
 *
 * SAFETY (money action — mainnet, founder-gated):
 *   - HARD CAPS: refuses to sign unless the 402 challenge is EXACTLY
 *       amount == "20000" (=$0.02 USDC, 6dp) · asset == USDC 0x8335..2913 ·
 *       network == eip155:8453 (Base) · payTo == 0xdF90..e109.
 *     Any mismatch => abort BEFORE signing. This bounds spend to a single $0.02.
 *   - One call. No loop, no retry-on-new-challenge.
 *   - The wallet only signs an EIP-3009 authorization; facilitator broadcasts.
 *
 * RUN (founder supplies the key for 0xE87c…; key never leaves your control):
 *   cd /home/orkz/byte/x402-gateway/examples/agent-client/ts
 *   npm install            # if not already
 *   AGENT_PRIVATE_KEY=0x<key-for-0xE87c9E19…> npx tsx probe-agentoracle.ts
 *
 * Prints: full JSON body, ALL response headers (receipt may ride a header),
 * any receipt/jws field, and the settlement tx hash + Basescan link.
 */

import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const URL = "https://agentoracle.co/research";
const BODY = { query: "What is the current price of Bitcoin?" };

// ── Hard caps (defense-in-depth spend bound) ────────────────────────────────
const CAP = {
  amount: "20000",                                                   // $0.02 USDC, 6 decimals
  asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",               // USDC on Base
  network: "eip155:8453",                                            // Base mainnet
  payTo: "0xdf90200b0031051bbf7a66bb9387d2ecf599e109",               // AgentOracle payTo
};
const EXPECT_WALLET = "0xe87c9e192df8dedcc2389260b15427c38a4a0ba6";  // the founder-named probe wallet

const PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY as `0x${string}` | undefined;
if (!PRIVATE_KEY || !/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) {
  console.error("ERROR: set AGENT_PRIVATE_KEY (0x + 64 hex) for wallet 0xE87c…. Never hardcode it.");
  process.exit(1);
}

const account = privateKeyToAccount(PRIVATE_KEY);
if (account.address.toLowerCase() !== EXPECT_WALLET) {
  console.error(`ABORT: key is for ${account.address}, not the authorized probe wallet 0xE87c…. Refusing to spend.`);
  process.exit(1);
}

const publicClient = createPublicClient({ chain: base, transport: http(process.env.RPC_URL) });
const signer = toClientEvmSigner(account, publicClient);
const core = registerExactEvmScheme(new x402Client(), { signer });
const x402 = new x402HTTPClient(core);

function assertChallengeWithinCap(pr: any): void {
  // Find the "exact" requirement the client would pay and validate every field.
  const accepts = pr?.accepts ?? pr?.paymentRequirements ?? [];
  const req = (Array.isArray(accepts) ? accepts : [accepts]).find(
    (a: any) => (a?.scheme ?? "exact") === "exact",
  );
  if (!req) { console.error("ABORT: no 'exact' payment requirement in challenge."); process.exit(1); }
  const got = {
    amount: String(req.amount ?? req.maxAmountRequired ?? ""),
    asset: String(req.asset ?? "").toLowerCase(),
    network: String(req.network ?? "").toLowerCase(),
    payTo: String(req.payTo ?? req.payto ?? "").toLowerCase(),
  };
  const bad = Object.entries(CAP).filter(([k, v]) => got[k as keyof typeof got] !== v);
  if (bad.length) {
    console.error("ABORT — challenge outside hard cap, NOT signing:");
    console.error("  expected:", CAP);
    console.error("  got     :", got);
    process.exit(1);
  }
  console.log(`[probe] cap OK — will pay ${got.amount} USDC units ($0.02) to ${got.payTo} on ${got.network}`);
}

async function main() {
  console.log(`[probe] wallet : ${account.address}`);
  console.log(`[probe] target : POST ${URL}`);
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(BODY),
  };

  const first = await fetch(URL, init);
  console.log(`[probe] unpaid status: ${first.status}`);
  if (first.status !== 402) {
    const t = await first.text();
    console.log(`[probe] non-402 (free or error). Headers:`);
    first.headers.forEach((v, k) => console.log(`   ${k}: ${v}`));
    console.log(`[probe] body:\n${t}`);
    return;
  }

  const paymentRequired = x402.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.clone().json().catch(() => undefined),
  );
  assertChallengeWithinCap(paymentRequired);

  const payload = await x402.createPaymentPayload(paymentRequired);
  const paymentHeaders = x402.encodePaymentSignatureHeader(payload);

  const paid = await fetch(URL, { ...init, headers: { ...(init.headers as any), ...paymentHeaders } });
  console.log(`\n[probe] PAID status: ${paid.status}`);
  console.log(`[probe] ── ALL response headers (receipt may ride a header) ──`);
  paid.headers.forEach((v, k) => console.log(`   ${k}: ${v}`));

  const text = await paid.text();
  console.log(`\n[probe] ── response body ──\n${text}`);

  // Highlight receipt-ish fields for the founder.
  try {
    const j = JSON.parse(text);
    const receipt = j.receipt ?? j.jws ?? j.signed_receipt ?? j.signature ?? j.attestation;
    if (receipt) console.log(`\n[probe] ★ RECEIPT FIELD:\n${JSON.stringify(receipt, null, 2)}`);
    else console.log(`\n[probe] no top-level receipt/jws field in body — check headers above (X-Receipt / PAYMENT-SIGNATURE / WWW-Authenticate).`);
  } catch { /* body not JSON */ }
}

main().catch((e) => { console.error(`[probe] fatal: ${e instanceof Error ? e.stack : e}`); process.exit(1); });
