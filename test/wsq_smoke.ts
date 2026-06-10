/**
 * WSQ smoke — run BEFORE and AFTER every gateway deploy (DISTRIBUTION_RUNBOOK §0/§4).
 *
 * Two layers:
 *   1. FREE surface checks (always run): /health, /feeds catalog,
 *      /openapi.json, /.well-known/x402.json (+ aliases), /.well-known/agent.json.
 *      Asserts address-reputation is registered everywhere and the agent card
 *      advertises the attestation receipt (attester address present).
 *   2. PAID leg (runs when a payer key is provided): a REAL x402 payment to
 *      POST /feeds/address-reputation, then asserts on the paid 200:
 *        - X-BYTE-Attestation header IS PRESENT  ← kills the silent-disable footgun
 *        - keccak256(raw response bytes) == header attestation payloadHash
 *        - EIP-712 recovery of the header attestation == advertised attester
 *        - answer.verdict ∈ {ALLOW, WARN, BLOCK}
 *        - the verdict's own embedded attestation verifies over the exact
 *          `answer` bytes sliced from the raw body (no JSON round-trip)
 *
 * The demo/proof feed is address-reputation — never crypto-top100 (cut feed,
 * meaningless receipt).
 *
 * Run:
 *   npx tsx test/wsq_smoke.ts                                   # free checks only
 *   PAYER_KEY_FILE=~/byte/keys/agent-payer-base-sepolia.json \
 *     NETWORK=base-sepolia npx tsx test/wsq_smoke.ts            # + real paid 200
 *
 * Env:
 *   GATEWAY_URL        gateway base URL (default http://127.0.0.1:3402)
 *   AGENT_PRIVATE_KEY  payer key (enables the paid leg)
 *   PAYER_KEY_FILE     JSON file [{address, private_key}] (alternative to above)
 *   NETWORK            "base-sepolia" (default) | "base-mainnet"
 *   EXPECT_NETWORK     optional CAIP-2 id the manifest must advertise (e.g. eip155:84532)
 */

import { readFileSync } from "fs";
import { keccak256, recoverTypedDataAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const GATEWAY_URL = (process.env.GATEWAY_URL ?? "http://127.0.0.1:3402").replace(/\/$/, "");
const NETWORK = process.env.NETWORK ?? "base-sepolia";
const EXPECT_NETWORK = process.env.EXPECT_NETWORK ?? "";

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, detail = "") {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`); }
}

function loadPayerKey(): Hex | null {
  if (process.env.AGENT_PRIVATE_KEY) return process.env.AGENT_PRIVATE_KEY as Hex;
  const file = process.env.PAYER_KEY_FILE;
  if (!file) return null;
  const arr = JSON.parse(readFileSync(file, "utf8"));
  return arr[0]?.private_key ?? null;
}

/** Slice the exact bytes of a top-level JSON object value out of `body`,
 *  starting at the value's opening `{`. String- and escape-aware brace walk —
 *  the embedded verdict attestation signs the canonical insertion-order bytes
 *  (which may carry >2^53 integers), so a parse/re-stringify cannot be trusted
 *  to reproduce them. */
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

async function verifyPayloadAttestation(att: any, bodyBytes: Uint8Array): Promise<{ hashOk: boolean; signerOk: boolean; recovered: string }> {
  const hashOk = keccak256(bodyBytes) === att.payloadHash && bodyBytes.length === att.payloadLength;
  const recovered = await recoverTypedDataAddress({
    domain: att.domain,
    types: PAYLOAD_ATTESTATION_TYPES,
    primaryType: "PayloadAttestation",
    message: {
      publisher: (att.publisher ?? att.signer) as Hex,
      payloadHash: att.payloadHash as Hex,
      payloadLength: BigInt(att.payloadLength),
      deadline: BigInt(att.deadline),
    },
    signature: att.signature as Hex,
  });
  const signerOk = recovered.toLowerCase() === (att.publisher ?? att.signer).toLowerCase();
  return { hashOk, signerOk, recovered };
}

async function freeChecks(): Promise<{ attester: string | null }> {
  console.log(`\nWSQ §1 — free discovery surfaces @ ${GATEWAY_URL}`);

  const health = await fetch(`${GATEWAY_URL}/health`).then((r) => r.json()).catch(() => null);
  check("/health 200 ok", health?.status === "ok");

  const feeds = await fetch(`${GATEWAY_URL}/feeds`).then((r) => r.json()).catch(() => null);
  const arFeed = feeds?.feeds?.find((f: any) => f.id === "address-reputation");
  check("/feeds lists address-reputation", Boolean(arFeed));
  check("address-reputation priced $0.05", arFeed?.priceAtomic === "50000", `got ${arFeed?.priceAtomic}`);

  const openapi = await fetch(`${GATEWAY_URL}/openapi.json`).then((r) => r.json()).catch(() => null);
  check("/openapi.json has POST /feeds/address-reputation", Boolean(openapi?.paths?.["/feeds/address-reputation"]?.post));
  check("/openapi.json declares x402Payment scheme", Boolean(openapi?.components?.securitySchemes?.x402Payment));

  const manifest = await fetch(`${GATEWAY_URL}/.well-known/x402.json`).then((r) => r.json()).catch(() => null);
  const arRes = manifest?.resources?.find((r: any) => r.name === "Address Reputation Oracle");
  check("/.well-known/x402.json lists address-reputation (POST)", arRes?.method === "POST");
  check("manifest status field populated", manifest?.status === "testnet" || manifest?.status === "mainnet", `got ${manifest?.status}`);
  if (EXPECT_NETWORK) check(`manifest network == ${EXPECT_NETWORK}`, manifest?.network === EXPECT_NETWORK, `got ${manifest?.network}`);

  for (const alias of ["/x402-manifest", "/.well-known/x402"]) {
    const r = await fetch(`${GATEWAY_URL}${alias}`).catch(() => null);
    check(`${alias} alias 200`, r?.status === 200);
  }

  const agent = await fetch(`${GATEWAY_URL}/.well-known/agent.json`).then((r) => r.json()).catch(() => null);
  check("agent card lists address-reputation skill", Boolean(agent?.skills?.find((s: any) => s.id === "address-reputation")));
  const attester = agent?.receipt?.attester ?? null;
  // The receipt block is omitted when no attestation key is set — that IS the footgun.
  check("agent card advertises attestation receipt (key is set)", Boolean(attester), "receipt block missing — GATEWAY_ATTESTATION_KEY unset?");
  check("attestation domain anchored on chainId 421614", agent?.receipt?.domain?.chainId === 421614, `got ${agent?.receipt?.domain?.chainId}`);
  return { attester };
}

async function paidLeg(attester: string | null) {
  const pk = loadPayerKey();
  if (!pk) {
    console.log("\nWSQ §2 — paid leg SKIPPED (no AGENT_PRIVATE_KEY / PAYER_KEY_FILE). The footgun assertion did not run.");
    return;
  }
  console.log(`\nWSQ §2 — REAL paid 200 on ${NETWORK}`);

  const chain = NETWORK === "base-mainnet" ? base : baseSepolia;
  const account = privateKeyToAccount(pk);
  const publicClient = createPublicClient({ chain, transport: http(process.env.RPC_URL) });
  const signer = toClientEvmSigner(account, publicClient);
  const x402 = new x402HTTPClient(registerExactEvmScheme(new x402Client(), { signer }));

  const url = `${GATEWAY_URL}/feeds/address-reputation`;
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: "github.com", address: account.address, amount: 1_000_000, chain: "base" }),
  };

  const first = await fetch(url, init);
  check("unpaid POST returns 402", first.status === 402, `got ${first.status}`);
  if (first.status !== 402) return;

  const paymentRequired = x402.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.clone().json().catch(() => undefined),
  );
  const payload = await x402.createPaymentPayload(paymentRequired);
  const paymentHeaders = x402.encodePaymentSignatureHeader(payload);
  const paid = await fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), ...paymentHeaders } });
  check("paid POST returns 200", paid.status === 200, `got ${paid.status}: ${(await paid.clone().text()).slice(0, 200)}`);
  if (paid.status !== 200) return;

  const rawBody = await paid.text();
  const bodyBytes = new TextEncoder().encode(rawBody);

  // ── THE footgun assertion: the receipt must ride every real paid 200 ──────
  const headerRaw = paid.headers.get("X-BYTE-Attestation");
  check("X-BYTE-Attestation header PRESENT on paid 200", Boolean(headerRaw), "header missing — attestation silently disabled");
  if (headerRaw) {
    const att = JSON.parse(headerRaw);
    const v = await verifyPayloadAttestation(att, bodyBytes);
    check("gateway receipt: keccak256(raw body) == payloadHash", v.hashOk);
    check("gateway receipt: signature recovers to its publisher", v.signerOk, `recovered ${v.recovered}`);
    if (attester) check("gateway receipt signer == agent-card attester", v.recovered.toLowerCase() === attester.toLowerCase(), `recovered ${v.recovered}, card says ${attester}`);
    check("gateway receipt domain == BYTE Library @ 421614", att.domain?.name === "BYTE Library" && att.domain?.chainId === 421614);
  }

  // ── The product: a signed verdict ─────────────────────────────────────────
  const resp = JSON.parse(rawBody);
  const verdict = resp?.answer?.verdict;
  check("answer.verdict is ALLOW/WARN/BLOCK", ["ALLOW", "WARN", "BLOCK"].includes(verdict), `got ${verdict}`);
  console.log(`        verdict: ${verdict} (score ${resp?.answer?.score}) — ${resp?.answer?.reasons?.[0] ?? ""}`);

  const inner = resp?.attestation;
  check("verdict carries embedded publisher attestation", Boolean(inner?.signature));
  if (inner?.signature) {
    // Verify over the EXACT answer bytes sliced from the raw body.
    const idx = rawBody.indexOf('"answer":');
    const answerBytes = new TextEncoder().encode(sliceJsonObject(rawBody, rawBody.indexOf("{", idx)));
    const v = await verifyPayloadAttestation(inner, answerBytes);
    check("verdict attestation: keccak256(exact answer bytes) == payloadHash", v.hashOk);
    check("verdict attestation: signature recovers to signer", v.signerOk, `recovered ${v.recovered}`);
    check("verdict attestation domain == BYTE Library @ 421614", inner.domain?.name === "BYTE Library" && inner.domain?.chainId === 421614);
  }
}

async function main() {
  const { attester } = await freeChecks();
  await paidLeg(attester);
  console.log(`\nWSQ SMOKE: ${fail === 0 ? "PASS" : "FAIL"} (${pass} passed, ${fail} failed)`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(`WSQ SMOKE: fatal — ${err instanceof Error ? err.stack : err}`);
  process.exit(1);
});
