/**
 * reasoning-verdict paid smoke — proves the new GPU oracle fulfills end-to-end on
 * a REAL Base-mainnet x402 settle, AND (as a side effect) triggers CDP/Bazaar to
 * auto-list the feed (listing fires on the first settle through the CDP facilitator,
 * same as the other 18 feeds). FOUNDER self-test — counts as ZERO traction.
 *
 * Spends ~$0.05 real USDC from the payer key. Run:
 *   PAYER_KEY_FILE=~/byte/keys/agent-payer-base-mainnet.json \
 *   NETWORK=base-mainnet GATEWAY_URL=https://x402.payperbyte.io \
 *   RPC_URL=https://mainnet.base.org \
 *     npx tsx test/pay_reasoning_verdict.ts
 *
 * Asserts on the paid 200: X-BYTE-Attestation header present + verifies + recovers
 * to the publisher; answer.v == reasoning-verdict/v1; verdict ∈ enum; the
 * embedded attestation verifies over the EXACT answer bytes. Free-only (no key) just
 * checks the route is listed + 402s.
 */
import { readFileSync } from "fs";
import { keccak256, recoverTypedDataAddress, createPublicClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const GATEWAY_URL = (process.env.GATEWAY_URL ?? "https://x402.payperbyte.io").replace(/\/$/, "");
const NETWORK = process.env.NETWORK ?? "base-mainnet";

let pass = 0, fail = 0;
const check = (n: string, ok: boolean, d = "") => {
  if (ok) { pass++; console.log(`  PASS  ${n}`); }
  else { fail++; console.error(`  FAIL  ${n}${d ? ` — ${d}` : ""}`); }
};

function loadPayerKey(): Hex | null {
  if (process.env.AGENT_PRIVATE_KEY) return process.env.AGENT_PRIVATE_KEY as Hex;
  const file = process.env.PAYER_KEY_FILE;
  if (!file) return null;
  return JSON.parse(readFileSync(file, "utf8"))[0]?.private_key ?? null;
}

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

const TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

async function verify(att: any, bytes: Uint8Array) {
  const hashOk = keccak256(bytes) === att.payloadHash && bytes.length === att.payloadLength;
  const recovered = await recoverTypedDataAddress({
    domain: att.domain, types: TYPES, primaryType: "PayloadAttestation",
    message: {
      publisher: (att.publisher ?? att.signer) as Hex,
      payloadHash: att.payloadHash as Hex,
      payloadLength: BigInt(att.payloadLength),
      deadline: BigInt(att.deadline),
    },
    signature: att.signature as Hex,
  });
  return { hashOk, signerOk: recovered.toLowerCase() === (att.publisher ?? att.signer).toLowerCase(), recovered };
}

async function main() {
  console.log(`\nreasoning-verdict smoke @ ${GATEWAY_URL} (${NETWORK})`);

  // Free: route listed + priced + 402.
  const feeds = await fetch(`${GATEWAY_URL}/feeds`).then((r) => r.json()).catch(() => null);
  const rv = feeds?.feeds?.find((f: any) => f.id === "reasoning-verdict");
  check("/feeds lists reasoning-verdict", Boolean(rv));
  check("reasoning-verdict priced $0.05", rv?.priceAtomic === "50000", `got ${rv?.priceAtomic}`);

  const url = `${GATEWAY_URL}/feeds/reasoning-verdict`;
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      kind: "message",
      subject: "Urgent: your wallet is compromised. Send 1 ETH to 0xAbC… now to secure it.",
      context: "unsolicited DM from an unknown sender",
    }),
  };

  const pk = loadPayerKey();
  if (!pk) {
    const r = await fetch(url, init);
    check("unpaid POST returns 402", r.status === 402, `got ${r.status}`);
    console.log("\n  (paid leg SKIPPED — set PAYER_KEY_FILE to run the real settle.)");
    console.log(`\nSMOKE: ${fail === 0 ? "PASS" : "FAIL"} (${pass} passed, ${fail} failed)`);
    process.exit(fail === 0 ? 0 : 1);
  }

  console.log(`\n  REAL paid settle on ${NETWORK} (~$0.05)…`);
  const chain = NETWORK === "base-mainnet" ? base : baseSepolia;
  const account = privateKeyToAccount(pk);
  const publicClient = createPublicClient({ chain, transport: http(process.env.RPC_URL) });
  const x402 = new x402HTTPClient(registerExactEvmScheme(new x402Client(), { signer: toClientEvmSigner(account, publicClient) }));

  const first = await fetch(url, init);
  check("unpaid POST returns 402", first.status === 402, `got ${first.status}`);
  if (first.status !== 402) return finish();

  const pr = x402.getPaymentRequiredResponse((n) => first.headers.get(n), await first.clone().json().catch(() => undefined));
  const headers = x402.encodePaymentSignatureHeader(await x402.createPaymentPayload(pr));
  const paid = await fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), ...headers } });
  check("paid POST returns 200", paid.status === 200, `got ${paid.status}: ${(await paid.clone().text()).slice(0, 200)}`);
  if (paid.status !== 200) return finish();

  const raw = await paid.text();
  const bytes = new TextEncoder().encode(raw);

  const headerRaw = paid.headers.get("X-BYTE-Attestation");
  check("X-BYTE-Attestation header PRESENT on paid 200", Boolean(headerRaw), "attestation silently disabled");
  if (headerRaw) {
    const v = await verify(JSON.parse(headerRaw), bytes);
    check("gateway receipt: keccak256(raw body) == payloadHash", v.hashOk);
    check("gateway receipt: recovers to publisher", v.signerOk, `recovered ${v.recovered}`);
  }

  const resp = JSON.parse(raw);
  check("answer.v == reasoning-verdict/v1", resp?.answer?.v === "reasoning-verdict/v1");
  check("answer.verdict ∈ ALLOW/WARN/BLOCK/ABSTAIN", ["ALLOW", "WARN", "BLOCK", "ABSTAIN"].includes(resp?.answer?.verdict), `got ${resp?.answer?.verdict}`);
  console.log(`        verdict: ${resp?.answer?.verdict} (score ${resp?.answer?.score}) — ${resp?.answer?.summary ?? ""}`);

  const inner = resp?.attestation;
  check("verdict carries embedded attestation", Boolean(inner?.signature));
  if (inner?.signature) {
    const idx = raw.indexOf('"answer":');
    const v = await verify(inner, new TextEncoder().encode(sliceJsonObject(raw, raw.indexOf("{", idx))));
    check("verdict attestation: keccak256(exact answer bytes) == payloadHash", v.hashOk);
    check("verdict attestation: recovers to signer", v.signerOk, `recovered ${v.recovered}`);
    check("domain == BYTE Library @ 421614", inner.domain?.name === "BYTE Library" && inner.domain?.chainId === 421614);
  }
  console.log("\n  ✓ end-to-end proven. The settle also triggers CDP/Bazaar auto-listing for reasoning-verdict.");
  finish();
}

function finish() {
  console.log(`\nSMOKE: ${fail === 0 ? "PASS" : "FAIL"} (${pass} passed, ${fail} failed)`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => { console.error(`SMOKE: fatal — ${err instanceof Error ? err.stack : err}`); process.exit(1); });
