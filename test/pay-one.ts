/**
 * pay-one.ts — one REAL x402 paid call to a single feed, verifying both
 * attestation layers. For targeted live-tests of one feed without the full
 * buy-all sweep (and without its $1.00 spend-guard floor).
 *
 *   PAYER_KEY_FILE=~/byte/keys/agent-payer-base-mainnet.json \
 *   FEED=/feeds/token-safety \
 *   BODY='{"token":"0x...","chain":"base"}' \
 *   npx tsx test/pay-one.ts
 */
import { readFileSync } from "fs";
import { keccak256, recoverTypedDataAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const GATEWAY = (process.env.GATEWAY_URL ?? "https://x402.payperbyte.io").replace(/\/$/, "");
const FEED = process.env.FEED ?? "/feeds/token-safety";
const BODY = process.env.BODY ?? "{}";
const pk = (process.env.AGENT_PRIVATE_KEY ?? JSON.parse(readFileSync(process.env.PAYER_KEY_FILE!, "utf8"))[0].private_key) as Hex;

const TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

async function verifyAtt(att: any, bytes: Uint8Array, label: string) {
  const hashOk = keccak256(bytes) === att.payloadHash && bytes.length === att.payloadLength;
  const recovered = await recoverTypedDataAddress({
    domain: att.domain, types: TYPES, primaryType: "PayloadAttestation",
    message: { publisher: (att.publisher ?? att.signer) as Hex, payloadHash: att.payloadHash as Hex,
      payloadLength: BigInt(att.payloadLength), deadline: BigInt(att.deadline) },
    signature: att.signature as Hex,
  });
  const signerOk = recovered.toLowerCase() === (att.publisher ?? att.signer).toLowerCase();
  console.log(`  ${label}: hash=${hashOk} sig=${signerOk} signer=${recovered} domain=${att.domain?.name}@${att.domain?.chainId}`);
  return hashOk && signerOk;
}

function sliceAnswer(raw: string): Uint8Array {
  const idx = raw.indexOf('"answer":'); const start = raw.indexOf("{", idx);
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < raw.length; i++) { const c = raw[i];
    if (esc) { esc = false; continue; } if (c === "\\") { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; } if (inStr) continue;
    if (c === "{") depth++; else if (c === "}") { depth--; if (!depth) return new TextEncoder().encode(raw.slice(start, i + 1)); } }
  throw new Error("no answer object");
}

async function main() {
  const account = privateKeyToAccount(pk);
  const publicClient = createPublicClient({ chain: base, transport: http(process.env.RPC_URL) });
  const signer = toClientEvmSigner(account, publicClient);
  const x402 = new x402HTTPClient(registerExactEvmScheme(new x402Client(), { signer }));
  const url = `${GATEWAY}${FEED}`;
  const init: RequestInit = { method: "POST", headers: { "Content-Type": "application/json" }, body: BODY };
  console.log(`[pay-one] ${url}  body=${BODY}\n[pay-one] payer ${account.address}`);

  const first = await fetch(url, init);
  console.log(`  unpaid -> ${first.status} (expect 402)`);
  if (first.status !== 402) return;
  const pr = x402.getPaymentRequiredResponse((n) => first.headers.get(n), await first.clone().json().catch(() => undefined));
  const payload = await x402.createPaymentPayload(pr);
  const headers = x402.encodePaymentSignatureHeader(payload);
  const paid = await fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), ...headers } });
  console.log(`  paid -> ${paid.status} (expect 200)`);
  if (paid.status !== 200) { console.log(await paid.text()); return; }

  const raw = await paid.text();
  const resp = JSON.parse(raw);
  console.log(`  verdict: ${resp.answer?.verdict}  score: ${resp.answer?.score}  reason: ${(resp.answer?.reasons ?? [])[0] ?? ""}`);
  const hdr = paid.headers.get("X-BYTE-Attestation");
  if (hdr) await verifyAtt(JSON.parse(hdr), new TextEncoder().encode(raw), "gateway X-BYTE-Attestation");
  else console.log("  gateway X-BYTE-Attestation: ABSENT");
  if (resp.attestation?.signature) await verifyAtt(resp.attestation, sliceAnswer(raw), "embedded verdict attestation");
}
main().catch((e) => { console.error("fatal:", e.message); process.exit(1); });
