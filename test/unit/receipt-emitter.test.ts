/**
 * Unit tests for src/lib/receipt-emitter.ts. Pure-function surface only —
 * HMAC/hash copy parity, resource derivation, context building, outcome
 * classification, guard evaluation, and delivered-response parsing. No
 * network, no filesystem, no clock dependency beyond an explicit
 * `nowSeconds` argument the caller controls.
 *
 * test/fixtures/hmac-vectors.json + test/fixtures/canonical-vectors.json
 * provenance (updated, G2/G3): both are now VERBATIM, byte-identical copies
 * of /home/orkz/byte/receipts/test/fixtures/{hmac-vectors,canonical-vectors}.json
 * — receipts is the source of truth for both (it generates and tests them
 * against its own computeContextHmac / canonicalJson+hashCanonical). The
 * two repos previously carried divergent hmac-vectors fixtures (different
 * vectors AND a different key name, `hmacHex` vs `hmac_hex`), which made the
 * cross-repo parity lock vacuous — each side was only proving its own copy
 * self-consistent, never that the two copies agreed with each other.
 *
 * RULE: never hand-edit either fixture file here. Re-copy verbatim from
 * receipts (`cp /home/orkz/byte/receipts/test/fixtures/<name>.json
 * test/fixtures/<name>.json`) whenever receipts changes its copy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  computeContextHmac,
  canonicalJson,
  hashCanonical,
  deriveResource,
  buildPaymentContext,
  classifyOutcome,
  parseDeliveredSignal,
  evaluateSettleGuards,
  normalizeGatePath,
  extractAuthorization,
  CONTEXT_WINDOW_SECONDS,
  REGIME_SIGNAL_PATH,
  type SettleSignal,
} from "../../src/lib/receipt-emitter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── HMAC parity vectors ─────────────────────────────────────────────────

interface HmacVector {
  secret: string;
  raw: string;
  hmac_hex: string;
}

const vectors: HmacVector[] = JSON.parse(
  readFileSync(path.join(__dirname, "..", "fixtures", "hmac-vectors.json"), "utf8"),
);

test("computeContextHmac reproduces every fixture vector (receipts' own hmac-vectors.json, adopted verbatim)", () => {
  assert.ok(vectors.length > 0, "fixture must not be empty");
  for (const v of vectors) {
    assert.equal(computeContextHmac(v.raw, v.secret), v.hmac_hex, `vector mismatched for raw=${v.raw}`);
  }
});

test("computeContextHmac is sensitive to both raw bytes and secret", () => {
  const v = vectors[0];
  assert.notEqual(computeContextHmac(v.raw + " ", v.secret), v.hmac_hex);
  assert.notEqual(computeContextHmac(v.raw, v.secret + "x"), v.hmac_hex);
});

test("hmac-vectors.json full-context vectors carry 40-hex payers (receipts' R8 fix)", () => {
  const fullContextVectors = vectors.filter((v) => v.raw.includes('"payer"'));
  assert.ok(fullContextVectors.length > 0, "expected at least one full-context vector");
  for (const v of fullContextVectors) {
    const m = /"payer":"(0x[0-9a-fA-F]*)"/.exec(v.raw);
    assert.ok(m, `vector has no payer field: ${v.raw}`);
    assert.equal(m![1].length - 2, 40, `payer must be 40 hex chars (20 bytes): ${m![1]}`);
  }
});

// ── canonical-vectors.json parity (G3) ──────────────────────────────────

interface CanonicalVector {
  name: string;
  input: unknown;
  canonical_json: string;
  hash: string;
}

const canonicalVectors: CanonicalVector[] = JSON.parse(
  readFileSync(path.join(__dirname, "..", "fixtures", "canonical-vectors.json"), "utf8"),
);

test("canonical-vectors.json: this module's canonicalJson/hashCanonical reproduce every receipts vector", () => {
  assert.ok(canonicalVectors.length >= 4, "fixture must not be empty");
  for (const v of canonicalVectors) {
    assert.equal(canonicalJson(v.input as any), v.canonical_json, `canonical_json mismatch for "${v.name}"`);
    assert.equal(hashCanonical(v.input as any), v.hash, `hash mismatch for "${v.name}"`);
  }
});

// ── hashCanonical / canonicalJson parity ────────────────────────────────

test("canonicalJson sorts object keys deterministically regardless of insertion order", () => {
  const a = canonicalJson({ b: 1, a: 2, c: 3 });
  const b = canonicalJson({ c: 3, a: 2, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":2,"b":1,"c":3}');
});

test("canonicalJson recurses into nested objects but preserves array order", () => {
  const out = canonicalJson({ z: [3, 1, 2], a: { y: 1, x: 2 } });
  assert.equal(out, '{"a":{"x":2,"y":1},"z":[3,1,2]}');
});

test("canonicalJson rejects non-finite numbers", () => {
  assert.throws(() => canonicalJson({ a: Infinity }));
  assert.throws(() => canonicalJson({ a: NaN }));
});

test("hashCanonical is order-independent (same logical object -> same hash)", () => {
  const h1 = hashCanonical({ regime: "range", confidence: 0.5, asset: "BTC" });
  const h2 = hashCanonical({ asset: "BTC", confidence: 0.5, regime: "range" });
  assert.equal(h1, h2);
  assert.match(h1, /^0x[0-9a-f]{64}$/);
});

test("hashCanonical differs for logically different objects", () => {
  const h1 = hashCanonical({ asset: "BTC" });
  const h2 = hashCanonical({ asset: "ETH" });
  assert.notEqual(h1, h2);
});

// ── resource derivation ─────────────────────────────────────────────────

test("deriveResource: uppercases asset and uses h", () => {
  assert.equal(deriveResource({ asset: "btc", h: 4 }), "regime-signal:BTC:4");
});

test("deriveResource: ETH casing", () => {
  assert.equal(deriveResource({ asset: "eth", h: 24 }), "regime-signal:ETH:24");
});

test("deriveResource: falls back to horizon_h when h is absent", () => {
  assert.equal(deriveResource({ asset: "BTC", horizon_h: 24 }), "regime-signal:BTC:24");
});

test("deriveResource: h takes precedence over horizon_h when both present (matches Number(body.h ?? body.horizon_h))", () => {
  assert.equal(deriveResource({ asset: "BTC", h: 4, horizon_h: 24 }), "regime-signal:BTC:4");
});

test("deriveResource: string horizon values coerce via Number(), matching the server's isHorizon(\"4\"|\"24\") acceptance", () => {
  assert.equal(deriveResource({ asset: "BTC", h: "4" }), "regime-signal:BTC:4");
});

test("deriveResource: missing/undefined body degrades to the same string shape the server would derive from an empty body", () => {
  assert.equal(deriveResource(undefined), "regime-signal::NaN");
  assert.equal(deriveResource({}), "regime-signal::NaN");
});

// ── buildPaymentContext ──────────────────────────────────────────────────

test("buildPaymentContext: 600s window, serialize-once invariant, response_hash always present", () => {
  const nowSeconds = 1_800_000_000;
  const signalObj = { asset: "BTC", regime: "range", confidence: 0.5 };
  const built = buildPaymentContext(
    {
      payer: "0x1111111111111111111111111111111111111111",
      nonce: `0x${"cd".repeat(32)}` as `0x${string}`,
      txHash: `0x${"ab".repeat(32)}` as `0x${string}`,
      body: { asset: "BTC", h: 4 },
      signalObj,
      nowSeconds,
    },
    "a-test-secret",
  );

  assert.equal(built.context.issued_at, nowSeconds);
  assert.equal(built.context.expires_at, nowSeconds + CONTEXT_WINDOW_SECONDS);
  assert.equal(built.context.expires_at - built.context.issued_at, 600);
  assert.equal(built.context.resource, "regime-signal:BTC:4");
  assert.equal(built.context.response_hash, hashCanonical(signalObj));

  // Serialize-once: the HMAC must cover EXACTLY `raw`, not a fresh re-stringify.
  assert.equal(built.hmac, computeContextHmac(built.raw, "a-test-secret"));
  assert.equal(JSON.parse(built.raw).payer, built.context.payer);
  // A second stringify of the same context object must reproduce the same
  // bytes (sanity check that the context has no non-deterministic fields
  // like Date objects that would make "serialize once" load-bearing beyond
  // the HMAC-vs-raw coupling already asserted above).
  assert.equal(JSON.stringify(built.context), built.raw);
});

test("buildPaymentContext: normalizes payer address via getAddress (checksum)", () => {
  const built = buildPaymentContext(
    {
      payer: "0x1111111111111111111111111111111111111111".toLowerCase(),
      nonce: `0x${"11".repeat(32)}` as `0x${string}`,
      txHash: `0x${"22".repeat(32)}` as `0x${string}`,
      body: { asset: "ETH", h: 24 },
      signalObj: { a: 1 },
      nowSeconds: 1_000,
    },
    "s",
  );
  assert.equal(built.context.payer, "0x1111111111111111111111111111111111111111");
});

test("buildPaymentContext: settlement_tx passes through null unchanged (defensive — this emitter never actually calls it with null)", () => {
  const built = buildPaymentContext(
    {
      payer: "0x1111111111111111111111111111111111111111",
      nonce: `0x${"11".repeat(32)}` as `0x${string}`,
      txHash: null,
      body: { asset: "BTC", h: 4 },
      signalObj: { a: 1 },
      nowSeconds: 1_000,
    },
    "s",
  );
  assert.equal(built.context.settlement_tx, null);
});

// ── classifyOutcome ───────────────────────────────────────────────────────

test("classifyOutcome: 200 with a receipt object -> minted", () => {
  assert.equal(classifyOutcome(200, { signal: {}, receipt: { id: "x" }, receipt_id: "x" }), "minted");
});

test("classifyOutcome: 200 with receipt:null -> permanent (never retry)", () => {
  assert.equal(classifyOutcome(200, { signal: {}, receipt: null, receipt_reason: "settlement pending" }), "permanent");
});

test("classifyOutcome: 200 with receipt:null + 'payment_nonce already used' reason -> already_minted, not permanent (G9)", () => {
  assert.equal(
    classifyOutcome(200, {
      signal: {},
      receipt: null,
      receipt_reason: "payment_nonce already used — a receipt was already minted for this payment",
    }),
    "already_minted",
  );
});

test("classifyOutcome: already_minted match is case-insensitive and substring-based (robust to minor wording drift)", () => {
  assert.equal(classifyOutcome(200, { receipt: null, receipt_reason: "PAYMENT_NONCE ALREADY USED" }), "already_minted");
});

test("classifyOutcome: a reason merely mentioning 'used' without the exact phrase stays permanent, not already_minted", () => {
  assert.equal(classifyOutcome(200, { receipt: null, receipt_reason: "nonce format is unused/invalid" }), "permanent");
});

test("classifyOutcome: 502 (receipt minting failed, nonce already burned) -> permanent", () => {
  assert.equal(classifyOutcome(502, { error: "receipt minting failed" }), "permanent");
});

test("classifyOutcome: 503 -> retryable", () => {
  assert.equal(classifyOutcome(503, null), "retryable");
});

test("classifyOutcome: other 5xx -> retryable", () => {
  assert.equal(classifyOutcome(500, null), "retryable");
  assert.equal(classifyOutcome(504, null), "retryable");
});

test("classifyOutcome: network error (status null) -> retryable", () => {
  assert.equal(classifyOutcome(null, null), "retryable");
});

test("classifyOutcome: unexpected 4xx -> permanent (retrying a bad request cannot succeed)", () => {
  assert.equal(classifyOutcome(400, null), "permanent");
});

test("classifyOutcome: 200 with unparsable/non-object body -> permanent", () => {
  assert.equal(classifyOutcome(200, null), "permanent");
});

// ── parseDeliveredSignal ─────────────────────────────────────────────────

test("parseDeliveredSignal: extracts .signal from a valid JSON body (Buffer input, matching transportContext.responseBody)", () => {
  const body = Buffer.from(JSON.stringify({ signal: { asset: "BTC" }, receipt: null }));
  const result = parseDeliveredSignal(body);
  assert.deepEqual(result, { ok: true, signal: { asset: "BTC" } });
});

test("parseDeliveredSignal: malformed JSON -> loud skip reason, never a guessed context", () => {
  const result = parseDeliveredSignal(Buffer.from("not json"));
  assert.equal(result.ok, false);
});

test("parseDeliveredSignal: valid JSON but no .signal field -> loud skip", () => {
  const result = parseDeliveredSignal(Buffer.from(JSON.stringify({ receipt: null })));
  assert.equal(result.ok, false);
});

test("parseDeliveredSignal: JSON array (not an object) -> loud skip", () => {
  const result = parseDeliveredSignal(Buffer.from("[1,2,3]"));
  assert.equal(result.ok, false);
});

// ── evaluateSettleGuards ──────────────────────────────────────────────────

function baseSignal(overrides: Partial<SettleSignal> = {}): SettleSignal {
  return {
    success: true,
    network: "eip155:8453",
    txHash: `0x${"ab".repeat(32)}`,
    payer: "0x1111111111111111111111111111111111111111",
    nonce: `0x${"cd".repeat(32)}`,
    path: REGIME_SIGNAL_PATH,
    hmacSecretConfigured: true,
    authKind: "eip3009",
    ...overrides,
  };
}

test("evaluateSettleGuards: happy path proceeds", () => {
  assert.deepEqual(evaluateSettleGuards(baseSignal()), { proceed: true });
});

test("evaluateSettleGuards: success:false -> silent skip", () => {
  const r = evaluateSettleGuards(baseSignal({ success: false }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, false);
});

test("evaluateSettleGuards: wrong path -> silent skip", () => {
  const r = evaluateSettleGuards(baseSignal({ path: "/feeds/weather" }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, false);
});

test("evaluateSettleGuards: GATEWAY_HMAC_SECRET unset -> silent skip", () => {
  const r = evaluateSettleGuards(baseSignal({ hmacSecretConfigured: false }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, false);
});

test("evaluateSettleGuards: non-EVM (Solana) settle -> silent skip, distinct reason", () => {
  const r = evaluateSettleGuards(baseSignal({ network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }));
  assert.equal(r.proceed, false);
  if (!r.proceed) {
    assert.equal(r.loud, false);
    assert.match(r.reason, /non-evm/i);
  }
});

test("evaluateSettleGuards: missing nonce -> loud skip", () => {
  const r = evaluateSettleGuards(baseSignal({ nonce: undefined }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, true);
});

test("evaluateSettleGuards: malformed nonce (wrong length) -> loud skip", () => {
  const r = evaluateSettleGuards(baseSignal({ nonce: "0xdead" }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, true);
});

test("evaluateSettleGuards: missing txHash -> loud skip", () => {
  const r = evaluateSettleGuards(baseSignal({ txHash: undefined }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, true);
});

test("evaluateSettleGuards: missing payer -> loud skip", () => {
  const r = evaluateSettleGuards(baseSignal({ payer: undefined }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, true);
});

test("evaluateSettleGuards: guard precedence — success:false wins over every other failure", () => {
  const r = evaluateSettleGuards(
    baseSignal({ success: false, path: "/feeds/weather", network: "solana:x", nonce: undefined }),
  );
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.reason, "settle not successful");
});

// ── path normalization (G1) ───────────────────────────────────────────────
//
// Live gateway 402s on payable URL variants — /feeds/regime-signal/,
// /Feeds/Regime-Signal, /FEEDS/regime-signal — because express req.path
// passes them through verbatim (loose routing). An exact-string guard
// silently drops receipts on every one of those. normalizeGatePath is
// copied from src/index.ts's function of the same name (verified
// byte-for-byte at write time) specifically so this module's path check
// agrees with the gateway's own paywall on which requests are "the same
// route".

test("normalizeGatePath: exact match is a no-op", () => {
  assert.equal(normalizeGatePath("/feeds/regime-signal"), "/feeds/regime-signal");
});

test("normalizeGatePath: trailing slash is stripped", () => {
  assert.equal(normalizeGatePath("/feeds/regime-signal/"), "/feeds/regime-signal");
});

test("normalizeGatePath: uppercase/mixed case is lowercased", () => {
  assert.equal(normalizeGatePath("/Feeds/Regime-Signal"), "/feeds/regime-signal");
  assert.equal(normalizeGatePath("/FEEDS/REGIME-SIGNAL"), "/feeds/regime-signal");
});

test("normalizeGatePath: duplicate slashes collapse", () => {
  assert.equal(normalizeGatePath("/feeds//regime-signal"), "/feeds/regime-signal");
});

test("normalizeGatePath: %2F-encoded slash decodes before normalizing", () => {
  assert.equal(normalizeGatePath("/feeds%2Fregime-signal"), "/feeds/regime-signal");
});

test("normalizeGatePath: root path is left as '/' (length guard prevents stripping the only slash)", () => {
  assert.equal(normalizeGatePath("/"), "/");
});

test("evaluateSettleGuards: trailing-slash path variant still proceeds (regression for G1)", () => {
  const r = evaluateSettleGuards(baseSignal({ path: "/feeds/regime-signal/" }));
  assert.deepEqual(r, { proceed: true });
});

test("evaluateSettleGuards: uppercase path variant still proceeds (regression for G1)", () => {
  const r = evaluateSettleGuards(baseSignal({ path: "/FEEDS/Regime-Signal" }));
  assert.deepEqual(r, { proceed: true });
});

test("evaluateSettleGuards: double-slash path variant still proceeds (regression for G1)", () => {
  const r = evaluateSettleGuards(baseSignal({ path: "/feeds//regime-signal" }));
  assert.deepEqual(r, { proceed: true });
});

test("evaluateSettleGuards: a genuinely different route (even case/slash-normalized) still mismatches", () => {
  const r = evaluateSettleGuards(baseSignal({ path: "/feeds/weather/" }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.equal(r.loud, false);
});

// ── Permit2 vs EIP-3009 payload shape (G6) ─────────────────────────────────

test("extractAuthorization: EIP-3009 shape (payload.authorization.nonce)", () => {
  const out = extractAuthorization({ authorization: { from: "0xabc", nonce: "0xdeadbeef" } });
  assert.deepEqual(out, { kind: "eip3009", from: "0xabc", nonce: "0xdeadbeef" });
});

test("extractAuthorization: Permit2 shape (payload.permit2Authorization.nonce) is classified distinctly", () => {
  const out = extractAuthorization({ permit2Authorization: { from: "0xabc", nonce: "12345" } });
  assert.deepEqual(out, { kind: "permit2", from: "0xabc", nonce: "12345" });
});

test("extractAuthorization: Permit2 takes precedence when (hypothetically) both keys are present", () => {
  const out = extractAuthorization({
    authorization: { from: "0xeip3009", nonce: "0xaaaa" },
    permit2Authorization: { from: "0xpermit2", nonce: "999" },
  });
  assert.equal(out.kind, "permit2");
});

test("extractAuthorization: neither key present -> kind 'none'", () => {
  assert.deepEqual(extractAuthorization({}), { kind: "none", from: undefined, nonce: undefined });
  assert.deepEqual(extractAuthorization(undefined), { kind: "none", from: undefined, nonce: undefined });
  assert.deepEqual(extractAuthorization(null), { kind: "none", from: undefined, nonce: undefined });
});

test("evaluateSettleGuards: Permit2 settle skips with a distinct, accurate reason — not 'missing or malformed payment_nonce' (regression for G6)", () => {
  const r = evaluateSettleGuards(baseSignal({ authKind: "permit2", nonce: undefined }));
  assert.equal(r.proceed, false);
  if (!r.proceed) {
    assert.equal(r.loud, false, "permit2 is a routine/expected refusal, not an anomaly worth paging on");
    assert.match(r.reason, /permit2/i);
    assert.doesNotMatch(r.reason, /malformed payment_nonce/i);
  }
});

test("evaluateSettleGuards: Permit2 settle is refused even when it happens to carry a well-formed 0x64-hex nonce (never minted from Permit2)", () => {
  const r = evaluateSettleGuards(baseSignal({ authKind: "permit2", nonce: `0x${"11".repeat(32)}` }));
  assert.equal(r.proceed, false);
  if (!r.proceed) assert.match(r.reason, /permit2/i);
});

test("evaluateSettleGuards: EIP-3009 settle (authKind default) is unaffected by the Permit2 guard", () => {
  assert.deepEqual(evaluateSettleGuards(baseSignal({ authKind: "eip3009" })), { proceed: true });
});
