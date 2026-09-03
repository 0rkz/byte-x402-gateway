/**
 * E6 step 0 — one paid merchant-screen call, to settle ONE question:
 *   does the live merchant-screen response actually carry the FEED's embedded
 *   EIP-712 attestation over the exact `answer` bytes?
 *
 * Why this exists: test/wsq_smoke.ts hardcodes its paid leg to
 * address-reputation (:178), so it cannot answer the MERCHANT_SCREEN_SIGN_RESPONSE
 * question that E6's signed-bytes paragraph depends on. That flag defaults to "0"
 * (data-feeds/merchant-screen/server.py:82); when it is off, `attestation` is
 * ABSENT from the body entirely (server.py:370-372), not null.
 *
 * KEY HANDLING — fleet rule, 2026-09-03: no agent session reads ~/.byte-cold-keys.
 * The founder runs this himself. This script prints ONLY: presence/absence of
 * `attestation`, the signer ADDRESS, the two verification booleans, and the
 * verdict. It never prints, logs, or returns key material, and never echoes
 * PAYER_KEY_FILE's contents.
 *
 * Run (founder, plain terminal):
 *   cd ~/byte/x402-gateway
 *   PAYER_KEY_FILE=~/.byte-cold-keys/agent-payer-base-mainnet.json \
 *     NETWORK=base-mainnet GATEWAY_URL=https://x402.payperbyte.io \
 *     npx tsx test/e6_merchant_screen_attestation_check.ts
 *
 * Cost: one call at the live merchant-screen price ($0.100 at time of writing —
 * re-read /feeds before trusting that figure).
 */

import { readFileSync } from "fs";
import { keccak256, recoverTypedDataAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const GATEWAY_URL = (process.env.GATEWAY_URL ?? "https://x402.payperbyte.io").replace(/\/$/, "");
const NETWORK = process.env.NETWORK ?? "base-mainnet";
const PROBE_DOMAIN = process.env.PROBE_DOMAIN ?? "github.com";

let pass = 0, fail = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`); }
}

/** Same string/escape-aware brace walk as wsq_smoke.ts:67 — the embedded
 *  attestation signs canonical insertion-order bytes, so a parse/re-stringify
 *  round trip cannot be trusted to reproduce them. */
function sliceJsonObject(body: string, start: number): string {
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < body.length; i++) {
    const c = body[i];
    if (esc) { esc = false; continue; }
    if (c === "\\") { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return body.slice(start, i + 1); }
  }
  throw new Error("unbalanced JSON object");
}

const PAYLOAD_ATTESTATION_TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

function loadPayerKey(): Hex {
  if (process.env.AGENT_PRIVATE_KEY) return process.env.AGENT_PRIVATE_KEY as Hex;
  const file = process.env.PAYER_KEY_FILE;
  if (!file) { console.error("No AGENT_PRIVATE_KEY / PAYER_KEY_FILE — refusing to run."); process.exit(2); }
  const arr = JSON.parse(readFileSync(file.replace(/^~/, process.env.HOME ?? "~"), "utf8"));
  const entry = Array.isArray(arr) ? arr[0] : arr;
  return entry.private_key as Hex;   // never printed
}

async function main() {
  console.log(`E6 step 0 — merchant-screen embedded-attestation check @ ${GATEWAY_URL} (${NETWORK})`);
  const chain = NETWORK === "base-mainnet" ? base : baseSepolia;
  const account = privateKeyToAccount(loadPayerKey());
  const publicClient = createPublicClient({ chain, transport: http(process.env.RPC_URL) });
  const x402 = new x402HTTPClient(
    registerExactEvmScheme(new x402Client(), { signer: toClientEvmSigner(account, publicClient) }),
  );

  const url = `${GATEWAY_URL}/feeds/merchant-screen`;
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: PROBE_DOMAIN, chain: "base" }),   // only `domain` is required
  };

  const first = await fetch(url, init);
  check("unpaid POST returns 402", first.status === 402, `got ${first.status}`);
  if (first.status !== 402) process.exit(1);

  const paymentRequired = x402.getPaymentRequiredResponse(
    (n) => first.headers.get(n),
    await first.clone().json().catch(() => undefined),
  );
  const paid = await fetch(url, {
    ...init,
    headers: { ...(init.headers as Record<string, string>),
               ...x402.encodePaymentSignatureHeader(await x402.createPaymentPayload(paymentRequired)) },
  });
  check("paid POST returns 200", paid.status === 200, `got ${paid.status}`);
  if (paid.status !== 200) process.exit(1);

  const rawBody = await paid.text();
  const resp = JSON.parse(rawBody);

  // ── THE question E6 step 0 exists to answer ──────────────────────────────
  const att = resp?.attestation;
  const present = att !== undefined && att !== null;
  check("body carries `attestation` (MERCHANT_SCREEN_SIGN_RESPONSE=1)", present,
        "ABSENT — signing is OFF on the running unit; E6's signed-bytes paragraph must not ship as written");
  console.log(`        top-level keys, in wire order: ${Object.keys(resp).join(", ")}`);
  console.log(`        verdict: ${resp?.answer?.verdict} (methodology ${resp?.answer?.methodology})`);
  if (!present) { console.log(`\nE6 STEP 0: FAIL (${pass} passed, ${fail} failed)`); process.exit(1); }

  const answerBytes = new TextEncoder().encode(
    sliceJsonObject(rawBody, rawBody.indexOf("{", rawBody.indexOf('"answer":'))),
  );
  check("keccak256(exact answer bytes) == attestation.payloadHash",
        keccak256(answerBytes) === att.payloadHash);
  check("attestation.payloadLength == answer byte length",
        Number(att.payloadLength) === answerBytes.length,
        `att ${att.payloadLength} vs actual ${answerBytes.length}`);

  const recovered = await recoverTypedDataAddress({
    domain: att.domain, types: PAYLOAD_ATTESTATION_TYPES, primaryType: "PayloadAttestation",
    message: {
      publisher: (att.publisher ?? att.signer) as Hex,
      payloadHash: att.payloadHash as Hex,
      payloadLength: BigInt(att.payloadLength),
      deadline: BigInt(att.deadline),
    },
    signature: att.signature as Hex,
  });
  check("signature recovers to attestation.signer",
        recovered.toLowerCase() === (att.publisher ?? att.signer).toLowerCase(), `recovered ${recovered}`);
  check("signer == manifest receipt.embedded.signers['merchant-screen'] (0x86e6…0b54)",
        recovered.toLowerCase() === "0x86e67978b5dae33d134c431a47c1b73365440b54");
  check("domain == BYTE Library @ 421614",
        att.domain?.name === "BYTE Library" && att.domain?.chainId === 421614);

  console.log(`        signer address: ${recovered}`);
  console.log(`\nE6 STEP 0: ${fail === 0 ? "PASS" : "FAIL"} (${pass} passed, ${fail} failed)`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(`E6 STEP 0 ERROR: ${e?.message ?? e}`); process.exit(1); });
