/**
 * BYTE x402 — attestation delivery verifier (diagnostic, sweep item L10)
 * ======================================================================
 * Makes ONE real paid call against a gateway feed and verifies the paid 200
 * actually delivers the advertised X-BYTE-Attestation receipt:
 *   1. request → 402 → cap-check the advertised price (FAIL-CLOSED) → sign a
 *      gasless EIP-3009 USDC payment → retry with the payment header
 *   2. dump status + ALL response headers + decoded settlement info
 *   3. recompute keccak256(exact response bytes) and compare it to
 *      attestation.payloadHash — the tamper-evidence check a buyer runs
 *   4. write a capture file (headers + body + attestation) for downstream
 *      byte_verify_payload signature verification
 *
 * Same primitives as pay-and-fetch.ts (@x402/core + @x402/evm v2.13.x, viem).
 *
 * Run:
 *   AGENT_PRIVATE_KEY=0x... npx tsx verify-attestation.ts
 *
 * Env:
 *   AGENT_PRIVATE_KEY  (REQUIRED) payer wallet key. NEVER hardcode or commit.
 *   AGENT_KEY_FILE     alternative: path to a file holding the key (0x… hex)
 *   GATEWAY_URL        default https://x402.payperbyte.io
 *   FEED_PATH          default /feeds/address-reputation
 *   METHOD             default POST
 *   BODY               JSON request body (default: self-screen the prod Safe)
 *   NETWORK            "base-mainnet" (default) | "base-sepolia"
 *   MAX_USDC           per-call spend cap, default 0.25 — abort if the 402
 *                      asks for more OR if the price can't be determined
 *   OUT                capture file path (default ./attestation-capture.json)
 *
 * Exit codes: 0 = paid 200 + attestation present + hash MATCH
 *             2 = paid 200 but NO X-BYTE-Attestation header (L10 FAIL)
 *             3 = attestation present but hash MISMATCH (tamper-evidence FAIL)
 *             4 = spend cap exceeded / price indeterminable (nothing signed)
 *             1 = any other error
 */

import { readFileSync, writeFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http, keccak256 } from "viem";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

// ── Config from env ────────────────────────────────────────────────────────
let PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY as `0x${string}` | undefined;
if (!PRIVATE_KEY && process.env.AGENT_KEY_FILE) {
  let raw = readFileSync(process.env.AGENT_KEY_FILE, "utf8").trim();
  if (/^[0-9a-fA-F]{64}$/.test(raw)) raw = "0x" + raw; // tolerate missing 0x prefix
  PRIVATE_KEY = raw as `0x${string}`;
}
const GATEWAY_URL = (process.env.GATEWAY_URL ?? "https://x402.payperbyte.io").replace(/\/$/, "");
const FEED_PATH = process.env.FEED_PATH ?? "/feeds/address-reputation";
const METHOD = (process.env.METHOD ?? "POST").toUpperCase();
const BODY =
  process.env.BODY ??
  JSON.stringify({
    domain: "payperbyte.io",
    address: "0xffFf4B8Da8C165B556326453446F6940C8AFE0DB",
    chain: "base",
  });
const NETWORK = process.env.NETWORK ?? "base-mainnet";
const MAX_USDC = Number(process.env.MAX_USDC ?? "0.25");
const OUT = process.env.OUT ?? "./attestation-capture.json";

if (!PRIVATE_KEY) {
  console.error("ERROR: set AGENT_PRIVATE_KEY (or AGENT_KEY_FILE). Never hardcode it.");
  process.exit(1);
}
if (!/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) {
  console.error("ERROR: AGENT_PRIVATE_KEY must be a 0x-prefixed 32-byte hex private key.");
  process.exit(1);
}
if (!Number.isFinite(MAX_USDC) || MAX_USDC <= 0) {
  console.error("ERROR: MAX_USDC must be a positive number.");
  process.exit(4);
}
const MAX_ATOMIC = BigInt(Math.round(MAX_USDC * 1e6)); // USDC = 6 decimals

const isMainnet = NETWORK === "base-mainnet";
const chain = isMainnet ? base : baseSepolia;
const basescan = isMainnet ? "https://basescan.org" : "https://sepolia.basescan.org";

// ── Wallet + x402 client (same wiring as pay-and-fetch.ts) ─────────────────
const account = privateKeyToAccount(PRIVATE_KEY);
const publicClient = createPublicClient({ chain, transport: http(process.env.RPC_URL) });
const signer = toClientEvmSigner(account, publicClient);
const core = registerExactEvmScheme(new x402Client(), { signer });
const x402 = new x402HTTPClient(core);

/** Largest maxAmountRequired across the 402's accepts[] — FAIL-CLOSED: null if indeterminable. */
function maxAskedAtomic(paymentRequired: any): bigint | null {
  const accepts: any[] = paymentRequired?.accepts ?? [];
  if (!accepts.length) return null;
  let max = 0n;
  for (const a of accepts) {
    const raw = a?.maxAmountRequired ?? a?.amount ?? a?.amountRequired ?? a?.maxAmount;
    if (raw === undefined || raw === null) return null;
    let v: bigint;
    try {
      v = BigInt(raw);
    } catch {
      return null;
    }
    if (v > max) max = v;
  }
  return max;
}

async function main() {
  const url = `${GATEWAY_URL}${FEED_PATH}`;
  const init: RequestInit = {
    method: METHOD,
    headers: METHOD === "GET" ? {} : { "Content-Type": "application/json" },
    ...(METHOD === "GET" ? {} : { body: BODY }),
  };

  console.log(`[verify] wallet   : ${account.address}`);
  console.log(`[verify] network  : ${NETWORK} (chainId ${chain.id})`);
  console.log(`[verify] request  : ${METHOD} ${url}`);
  console.log(`[verify] cap      : $${MAX_USDC} (${MAX_ATOMIC} atomic)`);

  // 1) Unpaid attempt — discover the 402 + payment requirements.
  const first = await fetch(url, init);
  if (first.status !== 402) {
    console.error(`[verify] expected 402, got ${first.status} — free route or error; nothing paid.`);
    console.error((await first.text()).slice(0, 500));
    process.exit(1);
  }
  const paymentRequired = x402.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.clone().json().catch(() => undefined),
  );

  // 2) Spend-cap gate — fail closed BEFORE anything is signed.
  const asked = maxAskedAtomic(paymentRequired);
  if (asked === null) {
    console.error("[verify] CAP ABORT: could not determine advertised price from 402 accepts[]. Nothing signed.");
    process.exit(4);
  }
  console.log(`[verify] 402 asks : ${asked} atomic ($${Number(asked) / 1e6})`);
  if (asked > MAX_ATOMIC) {
    console.error(`[verify] CAP ABORT: 402 asks ${asked} atomic > cap ${MAX_ATOMIC}. Nothing signed.`);
    process.exit(4);
  }

  // 3) Sign payment + retry the SAME request with the payment header.
  const payload = await x402.createPaymentPayload(paymentRequired);
  const paymentHeaders = x402.encodePaymentSignatureHeader(payload);
  const paidResp = await fetch(url, {
    ...init,
    headers: { ...(init.headers as Record<string, string>), ...paymentHeaders },
  });

  // 4) Exact bytes + full header dump.
  const bodyBytes = new Uint8Array(await paidResp.arrayBuffer());
  const bodyText = Buffer.from(bodyBytes).toString("utf8");
  const headers: Record<string, string> = {};
  paidResp.headers.forEach((v, k) => (headers[k] = v));

  console.log(`\n[verify] paid status : ${paidResp.status}`);
  console.log(`[verify] response headers:`);
  for (const [k, v] of Object.entries(headers)) {
    console.log(`  ${k}: ${v.length > 300 ? v.slice(0, 300) + "…(truncated)" : v}`);
  }

  // Settlement info (base64 JSON header, name varies across x402 versions).
  let settle: any = null;
  for (const h of ["x-payment-response", "payment-response"]) {
    const raw = headers[h];
    if (!raw) continue;
    try {
      settle = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
    } catch {
      /* not base64 JSON — keep raw */
      settle = { raw };
    }
  }
  if (settle) {
    console.log(`\n[verify] settlement : success=${settle.success} payer=${settle.payer ?? account.address}`);
    if (settle.transaction) console.log(`[verify] tx         : ${basescan}/tx/${settle.transaction}`);
  } else {
    console.log(`\n[verify] settlement : no payment-response header found (see dump above)`);
  }

  // 5) The point of this script: is the receipt actually there, over these bytes?
  const attRaw = paidResp.headers.get("X-BYTE-Attestation");
  let exitCode = 0;
  let computedHash: string | null = null;
  let attestation: any = null;

  if (paidResp.status !== 200) {
    console.error(`\n[verify] RESULT: paid request did not return 200 — cannot judge attestation.`);
    exitCode = 1;
  } else if (!attRaw) {
    console.error(`\n[verify] RESULT: FAIL (L10) — paid 200 carries NO X-BYTE-Attestation header.`);
    console.error(`[verify] agent.json advertises a receipt this response did not deliver.`);
    exitCode = 2;
  } else {
    attestation = JSON.parse(attRaw);
    computedHash = keccak256(bodyBytes);
    const claimed = String(attestation.payloadHash ?? "").toLowerCase();
    if (claimed === computedHash.toLowerCase()) {
      console.log(`\n[verify] RESULT: PASS — X-BYTE-Attestation present, keccak256(body) matches payloadHash.`);
      console.log(`[verify] payloadHash : ${computedHash}`);
      console.log(`[verify] signer      : ${attestation.signer ?? "(not in header)"}`);
    } else {
      console.error(`\n[verify] RESULT: FAIL — attestation present but hash MISMATCH.`);
      console.error(`[verify] claimed  : ${claimed}`);
      console.error(`[verify] computed : ${computedHash}`);
      exitCode = 3;
    }
  }

  // 6) Capture for byte_verify_payload / the audit trail.
  writeFileSync(
    OUT,
    JSON.stringify(
      {
        capturedAt: new Date().toISOString(),
        request: { url, method: METHOD, body: METHOD === "GET" ? null : JSON.parse(BODY) },
        payer: account.address,
        status: paidResp.status,
        headers,
        settle,
        attestation,
        computedKeccak256: computedHash,
        body: bodyText,
      },
      null,
      2,
    ),
  );
  console.log(`\n[verify] capture written: ${OUT}`);
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(`[verify] fatal: ${err instanceof Error ? err.stack : err}`);
  process.exit(1);
});
