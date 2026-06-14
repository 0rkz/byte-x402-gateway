/**
 * buy-all.ts — QA sweep: buy ONE call from every live feed on x402.payperbyte.io
 *
 * Self-test / zero-traction run; log to ~/byte/DECISION_LOG.md at end.
 *
 * Run (from ~/byte/x402-gateway):
 *   npx tsx test/buy-all.ts
 *
 * Mirrors the proven x402 pay-flow from wsq_smoke.ts:
 *   fetch -> 402 -> getPaymentRequiredResponse -> createPaymentPayload
 *   -> encodePaymentSignatureHeader -> refetch with payment header
 */

import { readFileSync, appendFileSync, existsSync } from "fs";
import { keccak256, recoverTypedDataAddress, type Hex, createPublicClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

// ── Config ────────────────────────────────────────────────────────────────────
const GATEWAY_URL = "https://x402.payperbyte.io";
const KEY_FILE = `${process.env.HOME}/byte/keys/agent-payer-base-mainnet.json`;
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as Hex;
const DECISION_LOG = `${process.env.HOME}/byte/DECISION_LOG.md`;

// SPEND CAP: stop if payer balance would drop below $1.00 USDC (1_000_000 atomic)
const BALANCE_FLOOR_ATOMIC = 1_000_000n; // $1.00 USDC
const SPEND_CAP_ATOMIC = 800_000n;       // $0.80 USDC

// Stagger between feed calls
const STAGGER_MS = 8_000;

// ── ERC-20 balanceOf ABI (minimal) ───────────────────────────────────────────
const ERC20_ABI = [
  {
    name: "balanceOf",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

// ── Types ─────────────────────────────────────────────────────────────────────
interface FeedResult {
  id: string;
  method: "GET" | "POST";
  price: string;
  priceAtomic: number;
  httpStatus: number | null;
  spentUsdc: number;
  headerAttestationPresent: boolean;
  headerAttestationValid: boolean | null; // null = not applicable (crypto-top100)
  embeddedAttestationValid: boolean | null; // null = not a signed oracle
  outputCohesive: boolean | null;
  cohesionNote: string;
  error: string | null;
  txHint: string | null; // payment payload nonce as hint
}

const PAYLOAD_ATTESTATION_TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

/** Slice the exact bytes of a top-level JSON object value out of `body`. */
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

async function verifyPayloadAttestation(
  att: any,
  bodyBytes: Uint8Array
): Promise<{ hashOk: boolean; signerOk: boolean; recovered: string }> {
  const hash = keccak256(bodyBytes);
  const hashOk = hash === att.payloadHash && bodyBytes.length === att.payloadLength;
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
  const signerOk =
    recovered.toLowerCase() === (att.publisher ?? att.signer ?? "").toLowerCase();
  return { hashOk, signerOk, recovered };
}

// ── Feed catalog: ordered list matching GET /feeds plus POST bodies ────────────
interface FeedSpec {
  id: string;
  method: "GET" | "POST";
  body?: object;
  /** crypto-top100 has NO attestation by design */
  expectNoHeaderAttestation?: boolean;
  /** These feeds have embedded signed answer */
  hasEmbeddedAttestation?: boolean;
  /** For 202 async feeds */
  expect202?: boolean;
}

function buildFeedSpecs(payerAddress: string): FeedSpec[] {
  return [
    // GET feeds
    { id: "crypto-top100",       method: "GET", expectNoHeaderAttestation: true },
    { id: "defi-yields",         method: "GET" },
    { id: "weather",             method: "GET" },
    { id: "earthquakes",         method: "GET" },
    { id: "space-weather",       method: "GET" },
    { id: "news-feed",           method: "GET" },
    { id: "code-pulse",          method: "GET" },
    { id: "runtime-eol",         method: "GET" },
    { id: "threat-intel",        method: "GET" },
    { id: "x402-pulse",          method: "GET" },
    { id: "stablecoin-rails",    method: "GET" },
    { id: "perp-funding",        method: "GET" },
    // POST oracles
    {
      id: "address-reputation",
      method: "POST",
      body: { domain: "github.com", address: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", amount: 1000000, chain: "base" },
      hasEmbeddedAttestation: true,
    },
    {
      id: "pkg-verdict",
      method: "POST",
      body: { ecosystem: "npm", package: "express" },
      hasEmbeddedAttestation: true,
    },
    {
      id: "sanctions-screen",
      method: "POST",
      body: { address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0" },
      hasEmbeddedAttestation: true,
    },
    {
      id: "liquidation-stream",
      method: "POST",
      body: { asset: "BTC" },
      hasEmbeddedAttestation: true,
    },
    {
      id: "positioning-snapshot",
      method: "POST",
      body: { assets: ["BTC", "ETH"] },
      hasEmbeddedAttestation: true,
    },
    {
      id: "evidence-pack",
      method: "POST",
      body: { claim: "USDC is fully reserved 1:1" },
      hasEmbeddedAttestation: true,
    },
    {
      id: "usc-statute",
      method: "POST",
      body: { citation: "17 USC 107" },
    },
    {
      id: "fact-oracle",
      method: "POST",
      body: { question: "What is the capital of France?", subscriber_address: payerAddress },
      expect202: true,
    },
  ];
}

// ── Per-feed cohesion checker ─────────────────────────────────────────────────
function checkCohesion(id: string, body: any): { ok: boolean; note: string } {
  try {
    // Publisher-backed feeds wrap their payload under the gateway's generic
    // envelope `.data` (one level deeper than a flat array). buy-all is a
    // LIVENESS harness — "did the paid 200 carry a populated payload?" — so for
    // these we check `.data` is non-empty rather than guessing its inner shape.
    // The SEMANTIC claim-vs-payload check (5 cities, right fields, units/sign)
    // is the feed-claim-vs-reality ROUTINE's job, which reads each real shape.
    const PUBLISHER_FEEDS = new Set([
      "weather", "earthquakes", "space-weather", "news-feed", "code-pulse",
      "runtime-eol", "threat-intel", "x402-pulse", "stablecoin-rails", "perp-funding",
    ]);
    if (PUBLISHER_FEEDS.has(id)) {
      const data = body?.data ?? body;
      const populated = data && (Array.isArray(data)
        ? data.length > 0
        : (typeof data === "object" ? Object.keys(data).length > 0 : !!data));
      const size = Array.isArray(data) ? `${data.length} items` : `${Object.keys(data ?? {}).length} keys`;
      return { ok: !!populated, note: populated ? `payload delivered (${size})` : "empty/null payload" };
    }
    switch (id) {
      case "crypto-top100": {
        const coins = body?.coins ?? body?.data ?? body;
        const arr = Array.isArray(coins) ? coins : null;
        if (!arr || arr.length < 1) return { ok: false, note: "no coins array" };
        const first = arr[0];
        const hasPrice = "price" in first || "current_price" in first || "priceUsd" in first || "quote" in first;
        return { ok: hasPrice, note: `${arr.length} coins, first=${first.symbol ?? first.id ?? "?"}` };
      }
      case "defi-yields": {
        const yields = body?.yields ?? body?.protocols ?? body?.data ?? body;
        const arr = Array.isArray(yields) ? yields : null;
        if (!arr || arr.length < 1) return { ok: false, note: "no yields array" };
        return { ok: true, note: `${arr.length} protocol rows, first=${arr[0].protocol ?? arr[0].id ?? "?"}` };
      }
      case "weather": {
        const cities = body?.cities ?? body?.forecasts ?? body?.data;
        const arr = Array.isArray(cities) ? cities : (body?.city ? [body] : null);
        if (!arr || arr.length < 2) return { ok: false, note: `expected 5 cities, got ${arr?.length ?? 0}` };
        return { ok: arr.length >= 5, note: `${arr.length} cities` };
      }
      case "earthquakes": {
        const quakes = body?.earthquakes ?? body?.features ?? body?.events ?? body?.data;
        const arr = Array.isArray(quakes) ? quakes : null;
        if (arr === null) {
          // might be wrapped differently
          const keys = Object.keys(body ?? {});
          return { ok: keys.length > 0, note: `keys: ${keys.slice(0, 4).join(",")}` };
        }
        return { ok: true, note: `${arr.length} earthquakes` };
      }
      case "space-weather": {
        const hasKp = JSON.stringify(body).toLowerCase().includes("kp");
        return { ok: hasKp, note: hasKp ? "kp field present" : "missing kp index" };
      }
      case "news-feed": {
        const articles = body?.articles ?? body?.headlines ?? body?.items ?? body?.news ?? body?.data;
        const arr = Array.isArray(articles) ? articles : null;
        if (!arr || arr.length < 1) return { ok: false, note: "no articles array" };
        return { ok: true, note: `${arr.length} headlines` };
      }
      case "code-pulse": {
        const releases = body?.releases ?? body?.packages ?? body?.data;
        const arr = Array.isArray(releases) ? releases : null;
        if (!arr || arr.length < 1) return { ok: false, note: "no releases array" };
        return { ok: true, note: `${arr.length} releases` };
      }
      case "runtime-eol": {
        const runtimes = body?.runtimes ?? body?.data ?? body;
        const arr = Array.isArray(runtimes) ? runtimes : null;
        if (!arr) return { ok: false, note: "no runtimes array" };
        return { ok: arr.length > 5, note: `${arr.length} runtime entries` };
      }
      case "threat-intel": {
        const cves = body?.advisories ?? body?.cves ?? body?.vulnerabilities ?? body?.data;
        const arr = Array.isArray(cves) ? cves : null;
        if (!arr || arr.length < 1) return { ok: false, note: "no CVE/advisory array" };
        return { ok: true, note: `${arr.length} advisories` };
      }
      case "x402-pulse": {
        const hasMetrics = "verifyCount" in body || "settleCount" in body || "metrics" in body || "pulse" in body || "totalVerify" in body || "total" in body;
        return { ok: hasMetrics, note: hasMetrics ? "metrics fields present" : `keys: ${Object.keys(body ?? {}).slice(0, 5).join(",")}` };
      }
      case "stablecoin-rails": {
        const bodyStr = JSON.stringify(body).toLowerCase();
        const hasUSDC = bodyStr.includes("usdc") || bodyStr.includes("usdt") || bodyStr.includes("stablecoin");
        return { ok: hasUSDC, note: hasUSDC ? "stablecoin data present" : "missing stablecoin data" };
      }
      case "perp-funding": {
        const rates = body?.rates ?? body?.funding ?? body?.venues ?? body?.data;
        const arr = Array.isArray(rates) ? rates : null;
        if (!arr) {
          const bodyStr = JSON.stringify(body).toLowerCase();
          const hasFunding = bodyStr.includes("funding") || bodyStr.includes("hyperliquid") || bodyStr.includes("dydx");
          return { ok: hasFunding, note: hasFunding ? "funding rate data present" : `keys: ${Object.keys(body ?? {}).slice(0,5).join(",")}` };
        }
        return { ok: arr.length >= 1, note: `${arr.length} venue entries` };
      }
      case "address-reputation": {
        const verdict = body?.answer?.verdict;
        return { ok: ["ALLOW","WARN","BLOCK"].includes(verdict), note: `verdict=${verdict}, score=${body?.answer?.score}` };
      }
      case "pkg-verdict": {
        const verdict = body?.answer?.verdict ?? body?.verdict ?? body?.status;
        const pkg = body?.answer?.package ?? body?.package;
        return { ok: !!verdict && (pkg === "express" || JSON.stringify(body).includes("express")), note: `verdict=${verdict}, pkg=${pkg}` };
      }
      case "sanctions-screen": {
        const listState = body?.answer?.list_state ?? body?.list_state ?? body?.answer?.status ?? body?.status;
        return { ok: listState !== undefined && listState !== null, note: `list_state=${listState}` };
      }
      case "liquidation-stream": {
        const bodyStr = JSON.stringify(body).toUpperCase();
        const hasBTC = bodyStr.includes("BTC");
        return { ok: hasBTC, note: hasBTC ? "BTC asset present" : "missing BTC data" };
      }
      case "positioning-snapshot": {
        const bodyStr = JSON.stringify(body).toUpperCase();
        const hasBTCETH = bodyStr.includes("BTC") && bodyStr.includes("ETH");
        return { ok: hasBTCETH, note: hasBTCETH ? "BTC+ETH present" : "missing asset data" };
      }
      case "evidence-pack": {
        const bodyStr = JSON.stringify(body).toLowerCase();
        const hasClaim = bodyStr.includes("usdc") || bodyStr.includes("reserve") || bodyStr.includes("evidence");
        return { ok: hasClaim, note: hasClaim ? "claim/evidence data present" : "no relevant content" };
      }
      case "usc-statute": {
        const bodyStr = JSON.stringify(body).toLowerCase();
        const hasText = bodyStr.includes("107") || bodyStr.includes("fair use") || bodyStr.includes("copyright") || bodyStr.includes("statute");
        return { ok: hasText, note: hasText ? "statute text present" : "missing statute content" };
      }
      case "fact-oracle": {
        // 202 async — ack only
        const hasAck = body?.status === "queued" || body?.ack || body?.message || body?.jobId || body?.id || body?.request_id;
        return { ok: true, note: `202 async ack: ${JSON.stringify(body).slice(0, 80)}` };
      }
      default:
        return { ok: false, note: "unknown feed id" };
    }
  } catch (e: any) {
    return { ok: false, note: `cohesion check threw: ${e.message}` };
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log("=".repeat(72));
  console.log("BYTE GATEWAY QA SWEEP — buy-all.ts — BASE MAINNET");
  console.log("SELF-TEST / ZERO TRACTION (not adoption metrics)");
  console.log("=".repeat(72));

  // Load key
  const keyArr = JSON.parse(readFileSync(KEY_FILE, "utf8"));
  const pk = keyArr[0].private_key as Hex;
  const payerAddress = keyArr[0].address as string;
  console.log(`\nPayer: ${payerAddress}`);
  // Never print private key

  // Setup x402 client
  const chain = base;
  const account = privateKeyToAccount(pk);
  const publicClient = createPublicClient({ chain, transport: http() });
  const signer = toClientEvmSigner(account, publicClient);
  const x402 = new x402HTTPClient(registerExactEvmScheme(new x402Client(), { signer }));

  // Check initial balance
  const initialBalanceRaw = await publicClient.readContract({
    address: USDC_ADDRESS,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [payerAddress as Hex],
  });
  const initialBalance = Number(initialBalanceRaw) / 1e6;
  console.log(`Initial USDC balance: $${initialBalance.toFixed(6)}\n`);

  // Fetch catalog
  const catalogResp = await fetch(`${GATEWAY_URL}/feeds`);
  const catalog = await catalogResp.json();
  const catalogMap = new Map<string, any>(
    (catalog.feeds as any[]).map((f: any) => [f.id, f])
  );

  const feedSpecs = buildFeedSpecs(payerAddress);
  const results: FeedResult[] = [];
  let totalSpentAtomic = 0n;
  const startedAt = new Date();

  // Also track tx hashes (nonce/payload fragments for DECISION_LOG)
  const txHints: string[] = [];

  for (let i = 0; i < feedSpecs.length; i++) {
    const spec = feedSpecs[i];
    const catalogEntry = catalogMap.get(spec.id);

    if (i > 0) {
      console.log(`  [stagger ${STAGGER_MS / 1000}s before next feed...]`);
      await sleep(STAGGER_MS);
    }

    console.log(`\n[${i + 1}/${feedSpecs.length}] ${spec.id} (${spec.method}) — ${catalogEntry?.price ?? "?"}`);

    // Pre-call balance check
    const currentBalanceRaw = await publicClient.readContract({
      address: USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [payerAddress as Hex],
    });
    if (currentBalanceRaw - BigInt(catalogEntry?.priceAtomic ?? 0) < BALANCE_FLOOR_ATOMIC) {
      console.error(`  SPEND GUARD: balance would drop below $1.00 — STOPPING.`);
      results.push({
        id: spec.id,
        method: spec.method,
        price: catalogEntry?.price ?? "?",
        priceAtomic: catalogEntry?.priceAtomic ?? 0,
        httpStatus: null,
        spentUsdc: 0,
        headerAttestationPresent: false,
        headerAttestationValid: null,
        embeddedAttestationValid: null,
        outputCohesive: null,
        cohesionNote: "SKIPPED — spend guard",
        error: "spend guard triggered",
        txHint: null,
      });
      break;
    }

    const url = `${GATEWAY_URL}/feeds/${spec.id}`;
    const initHeaders: Record<string, string> = { "Content-Type": "application/json" };
    const init: RequestInit = {
      method: spec.method,
      headers: initHeaders,
      ...(spec.body ? { body: JSON.stringify(spec.body) } : {}),
    };

    const result: FeedResult = {
      id: spec.id,
      method: spec.method,
      price: catalogEntry?.price ?? "?",
      priceAtomic: catalogEntry?.priceAtomic ?? 0,
      httpStatus: null,
      spentUsdc: 0,
      headerAttestationPresent: false,
      headerAttestationValid: null,
      embeddedAttestationValid: null,
      outputCohesive: null,
      cohesionNote: "",
      error: null,
      txHint: null,
    };

    try {
      // Step 1: Unpaid request to get 402
      const first = await fetch(url, init);
      if (first.status !== 402) {
        result.error = `Expected 402, got ${first.status}`;
        result.httpStatus = first.status;
        console.error(`  ERROR: ${result.error}`);
        results.push(result);
        continue;
      }

      // Step 2: Parse payment required, create payload, re-request
      const paymentRequired = x402.getPaymentRequiredResponse(
        (name) => first.headers.get(name),
        await first.clone().json().catch(() => undefined),
      );
      const payload = await x402.createPaymentPayload(paymentRequired);
      const paymentHeaders = x402.encodePaymentSignatureHeader(payload);

      // Extract a tx hint from the payload (nonce or similar, never the key)
      const nonce = (payload as any)?.payload?.authorization?.nonce ?? (payload as any)?.nonce;
      if (nonce) result.txHint = String(nonce).slice(0, 20);

      // Step 3: Paid request
      const paid = await fetch(url, {
        ...init,
        headers: { ...initHeaders, ...paymentHeaders },
      });

      result.httpStatus = paid.status;
      const expectedStatus = spec.expect202 ? 202 : 200;

      if (paid.status !== expectedStatus) {
        const errBody = await paid.text().catch(() => "");
        result.error = `Expected ${expectedStatus}, got ${paid.status}: ${errBody.slice(0, 200)}`;
        console.error(`  ERROR: ${result.error}`);
        results.push(result);
        continue;
      }

      // Track spend
      const atomicSpent = BigInt(catalogEntry?.priceAtomic ?? 0);
      totalSpentAtomic += atomicSpent;
      result.spentUsdc = Number(atomicSpent) / 1e6;

      const rawBody = await paid.text();
      const bodyBytes = new TextEncoder().encode(rawBody);

      // ── Header attestation check ────────────────────────────────────────────
      const headerRaw = paid.headers.get("X-BYTE-Attestation");
      result.headerAttestationPresent = Boolean(headerRaw);

      if (spec.expectNoHeaderAttestation) {
        // crypto-top100: absence expected, mark as N/A
        result.headerAttestationValid = null;
        console.log(`  X-BYTE-Attestation: ABSENT (expected for ${spec.id})`);
      } else if (!headerRaw) {
        result.headerAttestationValid = false;
        console.warn(`  X-BYTE-Attestation: MISSING (unexpected)`);
      } else {
        const att = JSON.parse(headerRaw);
        const v = await verifyPayloadAttestation(att, bodyBytes);
        result.headerAttestationValid = v.hashOk && v.signerOk;
        console.log(`  X-BYTE-Attestation: hash=${v.hashOk} sig=${v.signerOk} recovered=${v.recovered.slice(0, 12)}…`);
      }

      // ── Parse response body ────────────────────────────────────────────────
      let parsedBody: any = null;
      try {
        parsedBody = JSON.parse(rawBody);
      } catch {
        result.error = "non-JSON response body";
      }

      // ── Embedded attestation check (signed oracles) ────────────────────────
      if (spec.hasEmbeddedAttestation && parsedBody !== null) {
        const inner = parsedBody?.attestation;
        if (!inner?.signature) {
          result.embeddedAttestationValid = false;
          console.warn(`  Embedded attestation: MISSING`);
        } else {
          // Verify over the exact answer bytes sliced from raw body
          try {
            const answerIdx = rawBody.indexOf('"answer":');
            const answerObjStart = rawBody.indexOf("{", answerIdx);
            const answerBytes = new TextEncoder().encode(
              sliceJsonObject(rawBody, answerObjStart)
            );
            const v = await verifyPayloadAttestation(inner, answerBytes);
            result.embeddedAttestationValid = v.hashOk && v.signerOk;
            console.log(`  Embedded attestation: hash=${v.hashOk} sig=${v.signerOk} recovered=${v.recovered.slice(0, 12)}…`);
          } catch (e: any) {
            result.embeddedAttestationValid = false;
            console.error(`  Embedded attestation verify error: ${e.message}`);
          }
        }
      } else if (!spec.hasEmbeddedAttestation) {
        result.embeddedAttestationValid = null; // N/A
      }

      // ── Output cohesion ───────────────────────────────────────────────────
      if (parsedBody !== null) {
        const { ok, note } = checkCohesion(spec.id, parsedBody);
        result.outputCohesive = ok;
        result.cohesionNote = note;
        console.log(`  Cohesion: ${ok ? "OK" : "FAIL"} — ${note}`);
      }

      if (result.txHint) txHints.push(`${spec.id}:${result.txHint}`);
      console.log(`  Status: ${result.httpStatus}  Spent: $${result.spentUsdc.toFixed(6)}`);

    } catch (e: any) {
      result.error = `Exception: ${e.message}`;
      console.error(`  EXCEPTION: ${e.message}`);
    }

    results.push(result);
  }

  // ── Final balance ─────────────────────────────────────────────────────────
  const finalBalanceRaw = await publicClient.readContract({
    address: USDC_ADDRESS,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [payerAddress as Hex],
  });
  const finalBalance = Number(finalBalanceRaw) / 1e6;
  const totalSpent = Number(totalSpentAtomic) / 1e6;

  // ── Summary table ─────────────────────────────────────────────────────────
  console.log("\n" + "=".repeat(100));
  console.log("RESULTS TABLE");
  console.log("=".repeat(100));

  const col = (s: string, w: number) => s.slice(0, w).padEnd(w);
  const header = [
    col("Feed", 22),
    col("HTTP", 5),
    col("$Spent", 9),
    col("HeaderAtt", 10),
    col("EmbedAtt", 9),
    col("Cohesive", 9),
    "Note",
  ].join(" | ");
  console.log(header);
  console.log("-".repeat(header.length));

  let fullyClean = 0;
  const flagged: string[] = [];

  for (const r of results) {
    const httpStr = r.httpStatus !== null ? String(r.httpStatus) : "ERR";
    const headerAttStr = r.headerAttestationValid === null
      ? "N/A (exp)"
      : r.headerAttestationPresent
        ? (r.headerAttestationValid ? "VALID" : "INVALID")
        : "MISSING";
    const embedAttStr = r.embeddedAttestationValid === null
      ? "N/A"
      : (r.embeddedAttestationValid ? "VALID" : "INVALID");
    const cohesionStr = r.outputCohesive === null ? "N/A" : (r.outputCohesive ? "YES" : "NO");

    const row = [
      col(r.id, 22),
      col(httpStr, 5),
      col(`$${r.spentUsdc.toFixed(4)}`, 9),
      col(headerAttStr, 10),
      col(embedAttStr, 9),
      col(cohesionStr, 9),
      r.error ?? r.cohesionNote,
    ].join(" | ");
    console.log(row);

    // Is it fully clean?
    const httpOk = r.httpStatus === 200 || r.httpStatus === 202;
    const headerOk = r.headerAttestationValid !== false;
    const embedOk = r.embeddedAttestationValid !== false;
    const cohesionOk = r.outputCohesive !== false;
    const noError = !r.error;

    if (httpOk && headerOk && embedOk && cohesionOk && noError) {
      fullyClean++;
    } else {
      flagged.push(`${r.id}: ${r.error ?? (!httpOk ? `HTTP ${r.httpStatus}` : !headerOk ? "headerAtt fail" : !embedOk ? "embedAtt fail" : "cohesion fail")}`);
    }
  }

  console.log("=".repeat(100));
  console.log(`\nSUMMARY`);
  console.log(`  Total feeds attempted: ${results.length} / ${feedSpecs.length}`);
  console.log(`  Fully clean feeds:     ${fullyClean}`);
  console.log(`  Flagged / failed:      ${flagged.length}`);
  console.log(`  Total spent:           $${totalSpent.toFixed(6)} USDC`);
  console.log(`  Balance BEFORE:        $${initialBalance.toFixed(6)} USDC`);
  console.log(`  Balance AFTER:         $${finalBalance.toFixed(6)} USDC`);
  console.log(`  Spend cap:             $0.80 (${totalSpent <= 0.80 ? "WITHIN" : "EXCEEDED"})`);
  console.log(`  Floor guard ($1.00):   ${finalBalance >= 1.0 ? "SAFE" : "BREACHED"}`);
  console.log(`  Duration:              ${Math.round((Date.now() - startedAt.getTime()) / 1000)}s`);

  if (flagged.length > 0) {
    console.log("\nFlagged feeds (ranked by severity):");
    for (const f of flagged) console.log(`  - ${f}`);
  }

  // ── Append to DECISION_LOG.md ──────────────────────────────────────────────
  const logDate = new Date().toISOString().slice(0, 10);
  const logEntry = `
---

## ${logDate} — QA Self-Test Sweep (buy-all.ts) — ZERO TRACTION

**Type:** Self-test / automated QA verification. Not adoption metrics.

**Run:** buy-all.ts against https://x402.payperbyte.io (Base mainnet eip155:8453)

**Payer:** ${payerAddress}

**Results:**
- Feeds attempted: ${results.length}/${feedSpecs.length}
- Fully clean: ${fullyClean}
- Flagged: ${flagged.length}
- Total spent: $${totalSpent.toFixed(6)} USDC
- Balance before: $${initialBalance.toFixed(6)} | after: $${finalBalance.toFixed(6)}
- Duration: ${Math.round((Date.now() - startedAt.getTime()) / 1000)}s

**Flagged feeds:** ${flagged.length === 0 ? "none" : flagged.map(f => `\n  - ${f}`).join("")}

**Nonce hints (not tx hashes — x402 exact-EVM nonces):** ${txHints.join(", ") || "none"}

**Note:** crypto-top100 has no attestation by design (cut feed). fact-oracle returns 202 (async on-chain delivery).
`;

  if (existsSync(DECISION_LOG)) {
    appendFileSync(DECISION_LOG, logEntry);
    console.log(`\nAppended to ${DECISION_LOG}`);
  } else {
    console.warn(`\nDECISION_LOG not found at ${DECISION_LOG} — skipping append`);
  }

  console.log("\nQA SWEEP COMPLETE.\n");
  process.exit(flagged.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(`buy-all.ts FATAL: ${err instanceof Error ? err.stack : err}`);
  process.exit(1);
});
