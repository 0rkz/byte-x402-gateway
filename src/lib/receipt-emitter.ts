/**
 * Receipts payment-context emitter (Plan-1 Week-2, "receipts on every paid
 * call"). Runs POST-settle, off `x402ResourceServer.onAfterSettle` (registered
 * in index.ts next to the `x402ResourceServer` instance) — x402 settlement
 * happens AFTER the route handler already forwarded the caller's request to
 * `/feeds/regime-signal`'s upstream, so at upstream-fetch time the gateway has
 * no txHash yet and the receipts service refuses to mint on `settlement_tx:
 * null`. This module makes the SECOND, authenticated `/query` call — now
 * carrying the real settle result — that actually mints the receipt.
 *
 * Wire contract (receipts service POST /query, verified 2026-08-30):
 * headers X-BYTE-PAYMENT-CONTEXT (raw JSON string) + X-BYTE-PAYMENT-CONTEXT-HMAC
 * (HMAC-SHA256 hex over the EXACT raw string, UTF-8, key GATEWAY_HMAC_SECRET).
 * See receipts/src/lib/payment-context.ts and receipts/src/service/index.ts:104
 * (resource derivation) — both cross-checked file:line before this was written.
 *
 * Architecture: pure, synchronous, fully-unit-testable core (HMAC/hash copies,
 * resource derivation, context building, outcome classification, guard
 * evaluation, response-body parsing) + a thin IO shell (fetch loop, JSONL/
 * stdout logging, the `@x402/core` settle-context hook shape) at the bottom.
 * Every exported function down to `emitFromSettleContext` is pure; only
 * `postPaymentContext`, `emitWithRetry`, `logReceiptOutcome`, and
 * `emitFromSettleContext` itself touch the network, the clock, or the
 * filesystem.
 */
import { getAddress, keccak256, toBytes, type Address, type Hex } from "viem";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ── copied from receipts (private/unpublished repo) ──────────────────────
//
// receipts/src/lib/payment-context.ts:79-81 — computeContextHmac. Copied
// verbatim (not imported: receipts is a private, unpublished sibling repo,
// not an npm dependency of this public one) so the gateway signs with the
// IDENTICAL algorithm the receipts service verifies with. Fidelity is locked
// by test/fixtures/hmac-vectors.json, which is a VERBATIM copy of
// receipts/test/fixtures/hmac-vectors.json — receipts is the source of truth;
// re-sync from there, never edit the gateway copy in place (see the provenance
// block in test/unit/receipt-emitter.test.ts).
//
// HMAC-SHA256 of the exact raw JSON bytes (UTF-8), hex-encoded.
export function computeContextHmac(rawContextJson: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(rawContextJson, "utf8").digest("hex");
}

// receipts/src/lib/canonical.ts — canonicalJson + hashCanonical. Copied
// verbatim for the same reason (private/unpublished sibling repo). Used here
// ONLY to compute `response_hash` over the exact `.signal` object the caller
// received — must match keccak256(canonical bytes) byte-for-byte with
// whatever the receipts service itself would compute over the same signal,
// once it validates response_hash (receipts lane B, this Week-2 slice).
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue | undefined };

function canonicalizeValue(value: JsonValue | undefined): string {
  if (value === undefined || value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`canonicalJson: non-finite number ${value} has no canonical JSON form`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalizeValue(v)).join(",")}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalizeValue(value[k])}`);
  return `{${parts.join(",")}}`;
}

/** Deterministic JSON string: sorted object keys, no whitespace, stable across runs/platforms. */
export function canonicalJson(value: JsonValue): string {
  return canonicalizeValue(value);
}

/** keccak256 of the canonical JSON encoding of `value`, as UTF-8 bytes. */
export function hashCanonical(value: JsonValue): Hex {
  return keccak256(toBytes(canonicalJson(value)));
}

// ── resource derivation ───────────────────────────────────────────────────

/**
 * Mirrors receipts/src/service/index.ts:97-104 EXACTLY: `String(body.asset ??
 * "").toUpperCase()` + `Number(body.h ?? body.horizon_h)`. Must produce the
 * identical string the receipts service computes for the same body, or the
 * `resource` equality check in verifyPaymentContext (payment-context.ts)
 * refuses every context this emitter ever sends.
 */
export function deriveResource(body: { asset?: unknown; h?: unknown; horizon_h?: unknown } | null | undefined): string {
  const assetRaw = String(body?.asset ?? "").toUpperCase();
  const horizonH = Number((body as { h?: unknown } | null | undefined)?.h ?? (body as { horizon_h?: unknown } | null | undefined)?.horizon_h);
  return `regime-signal:${assetRaw}:${horizonH}`;
}

// ── payment context ────────────────────────────────────────────────────────

/**
 * Recommended gateway-side validity window (receipts/src/lib/payment-context.ts
 * doc comment: "~10 minutes"; hard cap there is MAX_CONTEXT_VALIDITY_SECONDS =
 * 15*60). 600s leaves comfortable headroom under that cap while still giving
 * the retry loop (worst case ~40s) a huge margin before expiry.
 */
export const CONTEXT_WINDOW_SECONDS = 600;

const NONCE_OR_TX_RE = /^0x[0-9a-fA-F]{64}$/;

export interface PaymentContext {
  payer: Address;
  payment_nonce: Hex;
  settlement_tx: Hex | null;
  resource: string;
  issued_at: number;
  expires_at: number;
  /**
   * Always included (per Week-2 gateway design) even though the current
   * receipts `PaymentContext` validator (payment-context.ts, as of this
   * write) does not yet check it — unknown keys are ignored by the
   * validator but still covered by the HMAC, so this is forward-compatible
   * with the receipts-side `response_hash` binding fix (plan §B) without a
   * synchronized deploy.
   */
  response_hash: Hex;
}

export interface BuildPaymentContextArgs {
  /** Raw payer address in any case — normalized via viem `getAddress`. */
  payer: string;
  /** The REAL EIP-3009 authorization nonce (0x + 64 hex) from the settled payment. */
  nonce: Hex;
  /** The on-chain settlement tx hash (0x + 64 hex). Never null from this emitter — it only ever runs post-settle. */
  txHash: Hex | null;
  /** The original caller request body — used only to re-derive `resource` identically to the server. */
  body: { asset?: unknown; h?: unknown; horizon_h?: unknown };
  /** The exact `.signal` object the caller was delivered (parsed from the delivered response bytes). */
  signalObj: unknown;
  /** unix seconds */
  nowSeconds: number;
}

export interface BuiltPaymentContext {
  context: PaymentContext;
  /** The exact JSON string that was serialized ONCE — this is what ships as the header value and what the HMAC covers. Never re-serialize. */
  raw: string;
  hmac: string;
}

/**
 * Builds the context, serializes it ONCE, and HMACs that exact string — never
 * re-serializes afterward (a second `JSON.stringify` of the same object is not
 * guaranteed to reproduce identical bytes, and a mismatch here would silently
 * desync the header value from the value the HMAC actually covers).
 */
export function buildPaymentContext(args: BuildPaymentContextArgs, secret: string): BuiltPaymentContext {
  const context: PaymentContext = {
    payer: getAddress(args.payer),
    payment_nonce: args.nonce,
    settlement_tx: args.txHash,
    resource: deriveResource(args.body),
    issued_at: args.nowSeconds,
    expires_at: args.nowSeconds + CONTEXT_WINDOW_SECONDS,
    response_hash: hashCanonical(args.signalObj as JsonValue),
  };
  const raw = JSON.stringify(context);
  const hmac = computeContextHmac(raw, secret);
  return { context, raw, hmac };
}

// ── outcome classification ─────────────────────────────────────────────────

export type EmitOutcome = "minted" | "permanent" | "retryable" | "already_minted";

/**
 * receipts' exact wording for a retry that lands after an earlier attempt's
 * success response was lost in flight (receipts/src/service/index.ts:177):
 * `receipt_reason: "payment_nonce already used — a receipt was already
 * minted for this payment"`. Matched by substring/case-insensitive, not
 * exact-string, so minor wording drift on the receipts side degrades to
 * "permanent" (still correct, just uncounted as already_minted) instead of
 * silently no-op-ing this classification.
 */
const ALREADY_MINTED_REASON_RE = /payment_nonce already used/i;

/**
 * status === null means no HTTP response was ever received (network error /
 * fetch abort / timeout) — the only IO-shaped input this pure function takes,
 * kept as a plain value so it stays trivially unit-testable.
 *
 *   200 + receipt object                          -> minted
 *   200 + receipt: null, reason "already used"     -> already_minted (a retry landed after an EARLIER attempt's success response was lost — the receipt DOES exist, just minted under that earlier attempt; distinct from every other refusal so it isn't under-counted as a miss, see G9)
 *   200 + receipt: null (any other reason)         -> permanent  (every remaining receipt_reason here is a considered refusal — never retry)
 *   502 (receipts' ONLY minting-failure status; nonce already consumed by then) -> permanent
 *   503 / other 5xx / network error                -> retryable
 *   anything else (4xx etc.)                        -> permanent  (retrying a structurally bad request cannot succeed)
 */
export function classifyOutcome(status: number | null, parsedBody: unknown): EmitOutcome {
  if (status === null) return "retryable";
  if (status === 200) {
    const body = parsedBody as { receipt?: unknown; receipt_reason?: unknown } | null;
    if (body?.receipt != null) return "minted";
    if (typeof body?.receipt_reason === "string" && ALREADY_MINTED_REASON_RE.test(body.receipt_reason)) {
      return "already_minted";
    }
    return "permanent";
  }
  if (status === 502) return "permanent";
  if (status === 503) return "retryable";
  if (status >= 500) return "retryable";
  return "permanent";
}

// ── delivered-response parsing ─────────────────────────────────────────────

export type ParsedSignalResult = { ok: true; signal: unknown } | { ok: false; reason: string };

/**
 * Parses the EXACT bytes delivered to the caller (transportContext.responseBody)
 * and pulls out `.signal` — the same object the receipts service itself hashes
 * for `response_hash`. Any parse failure is a loud skip: never emit a
 * malformed/guessed context.
 */
export function parseDeliveredSignal(responseBody: unknown): ParsedSignalResult {
  let text: string;
  try {
    text = String(responseBody);
  } catch {
    return { ok: false, reason: "delivered response body could not be stringified" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: "delivered response body is not valid JSON" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: "delivered response body is not a JSON object" };
  }
  const signal = (parsed as Record<string, unknown>).signal;
  if (signal === undefined || signal === null) {
    return { ok: false, reason: "delivered response body has no .signal field" };
  }
  return { ok: true, signal };
}

// ── settle-context guards ───────────────────────────────────────────────────

/** The one route this emitter is wired to — no route-handler changes, this is purely a hook-side filter. */
export const REGIME_SIGNAL_PATH = "/feeds/regime-signal";

/**
 * Path normalization — copied from src/index.ts's `normalizeGatePath`
 * (verified byte-for-byte against src/index.ts:489-499) rather than
 * imported: index.ts has a module-level `app.listen()` side effect
 * (confirmed at src/index.ts:2393), so importing anything from it here would
 * start a second gateway server the instant this module — or its unit tests
 * — loads. The live gateway 402s on `/feeds/regime-signal/`,
 * `/Feeds/Regime-Signal`, `/FEEDS/regime-signal` etc. (loose Express
 * routing decodes %2F, collapses `//`, and is case-insensitive), so
 * `transportContext.request.path` reaches this module in any of those
 * forms too. Comparing it against `REGIME_SIGNAL_PATH` with exact `===`
 * silently drops receipts on every variant but the one exact string,
 * exactly as it silently drops the fail-closed paywall stub without this
 * normalization (see index.ts's own comment). Must stay byte-for-byte
 * identical to index.ts's version — a divergence here would make this
 * module's notion of "the regime-signal route" disagree with the gateway's.
 */
export function normalizeGatePath(p: string): string {
  let s = p;
  try {
    s = decodeURIComponent(s);
  } catch {
    /* keep raw on a malformed escape */
  }
  s = s.replace(/\/{2,}/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s.toLowerCase();
}

/**
 * `@x402/core`'s "exact" EVM payload is a union (`ExactEvmPayloadV2`,
 * verified against node_modules/@x402/evm/dist/esm/index.d.mts:58-65):
 * EIP-3009 payloads carry `payload.authorization.nonce`; Permit2 payloads
 * carry `payload.permit2Authorization.nonce` instead (its own
 * `isPermit2Payload` guard just checks for the `permit2Authorization` key —
 * mirrored here). Receipts' `payment_nonce` semantics are EIP-3009-only (the
 * settle txHash + this nonce reconstruct the exact `transferWithAuthorization`
 * call); a Permit2 nonce is a structurally different value and must never be
 * sent as if it were one.
 */
export type AuthKind = "eip3009" | "permit2" | "none";

export interface ExtractedAuth {
  kind: AuthKind;
  from: string | undefined;
  nonce: string | undefined;
}

export interface RawEvmPayload {
  authorization?: { from?: unknown; nonce?: unknown };
  permit2Authorization?: { from?: unknown; nonce?: unknown };
}

/** Pure extraction/classification of the EIP-3009-vs-Permit2 payload shape. */
export function extractAuthorization(payload: RawEvmPayload | null | undefined): ExtractedAuth {
  if (payload?.permit2Authorization) {
    const pa = payload.permit2Authorization;
    return {
      kind: "permit2",
      from: typeof pa.from === "string" ? pa.from : undefined,
      nonce: typeof pa.nonce === "string" ? pa.nonce : undefined,
    };
  }
  if (payload?.authorization) {
    const a = payload.authorization;
    return {
      kind: "eip3009",
      from: typeof a.from === "string" ? a.from : undefined,
      nonce: typeof a.nonce === "string" ? a.nonce : undefined,
    };
  }
  return { kind: "none", from: undefined, nonce: undefined };
}

/** Plain-value extraction of exactly the fields the guards need — kept separate from the real `@x402/core` types so guard logic is pure and testable with plain object literals. */
export interface SettleSignal {
  success: boolean;
  network: string | undefined;
  txHash: string | undefined;
  payer: string | undefined;
  nonce: string | undefined;
  path: string | undefined;
  hmacSecretConfigured: boolean;
  authKind: AuthKind;
}

export type GuardResult = { proceed: true } | { proceed: false; loud: boolean; reason: string };

/**
 * Guard order mirrors the build brief exactly. Each failure carries a
 * distinct reason; `loud` marks the ones that should be logged (missing/
 * malformed nonce, txHash, or payer — genuinely unexpected on a successful
 * EVM settle) versus the routine/expected ones (wrong route, non-EVM
 * network, no HMAC secret configured) which stay silent per request — the
 * missing-secret case gets its own ONE-TIME startup warning elsewhere
 * (fail-quiet: identical behavior to before this feature existed).
 */
export function evaluateSettleGuards(signal: SettleSignal): GuardResult {
  if (signal.success !== true) {
    return { proceed: false, loud: false, reason: "settle not successful" };
  }
  if (!signal.path || normalizeGatePath(signal.path) !== REGIME_SIGNAL_PATH) {
    return { proceed: false, loud: false, reason: `path mismatch (${signal.path ?? "unknown"})` };
  }
  if (!signal.hmacSecretConfigured) {
    return { proceed: false, loud: false, reason: "GATEWAY_HMAC_SECRET not configured" };
  }
  if (!signal.network || !signal.network.startsWith("eip155:")) {
    return { proceed: false, loud: false, reason: "non-evm settle, no receipt" };
  }
  if (signal.authKind === "permit2") {
    // Routine/expected, same tier as the non-EVM case above — not a
    // malformed settle, just a payment method receipts doesn't understand
    // yet. Silent: never mint, and never misreport it as a malformed
    // EIP-3009 nonce (the bug this guard replaces).
    return { proceed: false, loud: false, reason: "permit2 settle — receipts unsupported" };
  }
  if (!signal.nonce || !NONCE_OR_TX_RE.test(signal.nonce)) {
    return { proceed: false, loud: true, reason: "missing or malformed payment_nonce on a successful EVM settle" };
  }
  if (!signal.txHash || !NONCE_OR_TX_RE.test(signal.txHash)) {
    return { proceed: false, loud: true, reason: "missing or malformed settlement_tx on a successful EVM settle" };
  }
  if (!signal.payer) {
    return { proceed: false, loud: true, reason: "missing payer on a successful EVM settle" };
  }
  return { proceed: true };
}

// ── IO shell ─────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 10_000;
const MAX_ATTEMPTS = 3;
/** Delay BEFORE attempt 2 and attempt 3, respectively — all attempts finish well inside CONTEXT_WINDOW_SECONDS (600s). */
const BACKOFF_MS = [2_000, 8_000];

interface RawAttemptResult {
  status: number | null;
  parsedBody: unknown;
}

export async function postPaymentContext(url: string, requestBody: unknown, raw: string, hmac: string): Promise<RawAttemptResult> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-BYTE-PAYMENT-CONTEXT": raw,
        "X-BYTE-PAYMENT-CONTEXT-HMAC": hmac,
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const text = await res.text();
    let parsedBody: unknown = null;
    try {
      parsedBody = JSON.parse(text);
    } catch {
      /* leave null — classifyOutcome treats a non-JSON 200 as permanent, others as their status dictates */
    }
    return { status: res.status, parsedBody };
  } catch {
    // Network error / abort / timeout — no response was ever received.
    return { status: null, parsedBody: null };
  }
}

export interface EmitLoopResult {
  outcome: EmitOutcome;
  attempts: number;
  receiptId: string | null;
  receiptReason: string | null;
  /** The final attempt's raw HTTP status (null on a network error/timeout) — see G4: 502 means the nonce is now burned and a receipt is impossible forever, distinct from every other refusal. */
  httpStatus: number | null;
}

/** Up to MAX_ATTEMPTS, identical raw context bytes every attempt (never rebuilt), backing off only on a retryable outcome. */
export async function emitWithRetry(url: string, requestBody: unknown, built: BuiltPaymentContext): Promise<EmitLoopResult> {
  let attempts = 0;
  let last: RawAttemptResult = { status: null, parsedBody: null };
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    if (i > 0) {
      await new Promise((resolve) => setTimeout(resolve, BACKOFF_MS[i - 1]));
    }
    attempts += 1;
    last = await postPaymentContext(url, requestBody, built.raw, built.hmac);
    const outcome = classifyOutcome(last.status, last.parsedBody);
    if (outcome !== "retryable") {
      const body = last.parsedBody as { receipt_id?: unknown; receipt_reason?: unknown } | null;
      return {
        outcome,
        attempts,
        receiptId: typeof body?.receipt_id === "string" ? body.receipt_id : null,
        receiptReason: typeof body?.receipt_reason === "string" ? body.receipt_reason : null,
        httpStatus: last.status,
      };
    }
  }
  // Exhausted retries still retryable — give up, log honestly as retryable-exhausted.
  return { outcome: "retryable", attempts, receiptId: null, receiptReason: "exhausted retries", httpStatus: last.status };
}

// ── outcome logging ─────────────────────────────────────────────────────────

/**
 * Separate JSONL file from gateway-deliveries.jsonl — the revenue watcher
 * parses that one for feed-attribution telemetry and must never see
 * receipt-emission outcomes mixed in.
 *
 * Read lazily (per call, not memoized) rather than once at module load: lets
 * a test point this at a scratch path via the env var without needing to
 * control import order (see G8/G5), and stays correct if the process's env
 * is ever mutated post-load.
 */
function receiptsLogFile(): string {
  return process.env.GATEWAY_RECEIPTS_LOG || "/home/orkz/byte/logs/gateway-receipts.jsonl";
}

export interface OutcomeLogRecord {
  ts: string;
  feed: string;
  payer: string;
  nonce: string;
  txHash: string | null;
  outcome: EmitOutcome;
  receipt_id?: string;
  receipt_reason?: string;
  attempts: number;
  /** Final attempt's raw HTTP status; null on a network error/timeout. See G4. */
  http_status: number | null;
}

/** Throw-free, like delivery-log.ts's logDelivery — logging must never break or delay anything. */
export function logReceiptOutcome(rec: OutcomeLogRecord): void {
  try {
    const line = JSON.stringify(rec);
    process.stdout.write(`[receipt] ${line}\n`);
    const file = receiptsLogFile();
    // Lazy — only touches the filesystem on an actual write, not at module
    // import time (G8). fs.mkdirSync(..., {recursive:true}) is idempotent
    // and cheap, so no need to memoize "already created".
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
    } catch {
      /* best-effort — appendFile below is itself best-effort */
    }
    fs.appendFile(file, line + "\n", () => {});
  } catch {
    /* never let logging break anything */
  }
}

// ── hook entry point ─────────────────────────────────────────────────────

export interface EmitterConfig {
  regimeSignalUrl: string;
}

/**
 * Minimal shape this module reads off the real `@x402/core` `SettleResultContext`
 * (server/index.d.mts -> x402Client-*.d.mts `SettleResultContext`/`SettleResponse`/
 * `PaymentPayload`/`HTTPTransportContext`, all read+confirmed against the .d.mts
 * and the express adapter (node_modules/@x402/express/dist/esm/index.mjs) before
 * writing this — not trusted from the build brief's line numbers). Declared
 * loosely (not importing the real type) so this file has zero compile-time
 * coupling to `@x402/core`'s internal type re-export chain; index.ts imports the
 * real `SettleResultContext` type and passes it in, structurally compatible.
 */
export interface SettleHookContext {
  result?: { success?: boolean; transaction?: string; payer?: string; network?: string } | null;
  paymentPayload?: { payload?: RawEvmPayload } | null;
  transportContext?: {
    request?: { path?: string; adapter?: { getBody?: () => unknown } };
    responseBody?: unknown;
  } | null;
}

let warnedNoSecret = false;

/**
 * Read lazily, at emit/registration time — NOT once at module load. A
 * top-level `const` here would only ever see whatever `process.env` held at
 * the instant this module was first imported, which works only by
 * import-order luck (relying on config.js's dotenv call having already run
 * before index.ts's `import ... from "./lib/receipt-emitter.js"` — see G7).
 * Reading it fresh on every call removes that ordering dependency entirely.
 */
function getHmacSecret(): string | null {
  return (process.env.GATEWAY_HMAC_SECRET || "").trim() || null;
}

/** One-time startup warning, called from index.ts at hook-registration time — silent skips thereafter (fail-quiet: identical behavior to before this feature existed). */
export function warnIfHmacSecretMissing(): void {
  if (!getHmacSecret() && !warnedNoSecret) {
    warnedNoSecret = true;
    console.warn(
      "[receipt-emitter] GATEWAY_HMAC_SECRET is unset — receipt emission stays disabled; " +
        "every paid regime-signal call keeps getting receipt:null (unchanged from before this " +
        "feature). Founder-provisioned via x402-gateway/.env.receipts.",
    );
  }
}

/**
 * Fire-and-forget entry point: `void emitFromSettleContext(ctx, config)` from
 * inside the `onAfterSettle` hook (the hook itself is awaited pre-flush, so
 * this must never be awaited there). Entirely throw-free — any failure here
 * must never surface as an unhandled rejection or affect the already-
 * delivered response (settlement is already final by the time this runs).
 */
export async function emitFromSettleContext(ctxIn: unknown, cfg: EmitterConfig): Promise<void> {
  try {
    // Accepted as `unknown`, not the real `@x402/core` `SettleResultContext`
    // type, on purpose: that type's own `transportContext` field is typed
    // `unknown` too (SettleContext, x402Client-*.d.mts) since it is
    // transport-adapter-defined — the HTTP shape used here is confirmed only
    // by reading the express adapter, not by the exported types. Extraction
    // below is fully defensive (every field optional-chained) so a shape
    // drift degrades to a silent/loud skip, never a throw.
    const ctx = (ctxIn ?? {}) as SettleHookContext;
    const result = ctx.result ?? {};
    const tc = ctx.transportContext ?? undefined;
    const auth = extractAuthorization(ctx.paymentPayload?.payload);
    const hmacSecret = getHmacSecret();

    const path = tc?.request?.path;
    const resultPayer = typeof result.payer === "string" && result.payer ? result.payer : undefined;
    const authFrom = auth.from;

    const signal: SettleSignal = {
      success: result.success === true,
      network: typeof result.network === "string" ? result.network : undefined,
      txHash: typeof result.transaction === "string" ? result.transaction : undefined,
      payer: resultPayer ?? authFrom,
      nonce: auth.nonce,
      path,
      hmacSecretConfigured: hmacSecret !== null,
      authKind: auth.kind,
    };

    const guard = evaluateSettleGuards(signal);
    if (!guard.proceed) {
      if (guard.loud) {
        console.warn(`[receipt-emitter] skip: ${guard.reason}`);
      }
      return;
    }

    const body = tc?.request?.adapter?.getBody?.();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      console.warn("[receipt-emitter] skip: missing/malformed request body — cannot derive resource");
      return;
    }

    const parsedSignal = parseDeliveredSignal(tc?.responseBody);
    if (!parsedSignal.ok) {
      console.warn(`[receipt-emitter] skip: ${parsedSignal.reason}`);
      return;
    }

    let built: BuiltPaymentContext;
    try {
      built = buildPaymentContext(
        {
          payer: signal.payer as string,
          nonce: signal.nonce as Hex,
          txHash: signal.txHash as Hex,
          body: body as { asset?: unknown; h?: unknown; horizon_h?: unknown },
          signalObj: parsedSignal.signal,
          nowSeconds: Math.floor(Date.now() / 1000),
        },
        hmacSecret as string,
      );
    } catch (e) {
      console.warn(`[receipt-emitter] skip: failed to build payment context — ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    const loopResult = await emitWithRetry(`${cfg.regimeSignalUrl}/query`, body, built);

    if (loopResult.httpStatus === 502) {
      // Receipts' ONLY minting-failure status: the payment_nonce is already
      // burned by the time it returns 502, so a receipt for this payment is
      // now impossible forever — never a benign/routine refusal. Loud on
      // purpose (see G4): a plain JSONL line under `console.warn` volume
      // buries this next to routine skips.
      console.error(
        `[receipt-emitter] 502 from receipts — payment_nonce burned, receipt impossible forever ` +
          `(payer=${built.context.payer} nonce=${built.context.payment_nonce} resource=${built.context.resource})`,
      );
    }

    const rec: OutcomeLogRecord = {
      ts: new Date().toISOString(),
      feed: "regime-signal",
      payer: built.context.payer,
      nonce: built.context.payment_nonce,
      txHash: built.context.settlement_tx,
      outcome: loopResult.outcome,
      attempts: loopResult.attempts,
      http_status: loopResult.httpStatus,
    };
    if (loopResult.receiptId) rec.receipt_id = loopResult.receiptId;
    if (loopResult.receiptReason) rec.receipt_reason = loopResult.receiptReason;
    logReceiptOutcome(rec);
  } catch (err) {
    console.warn(`[receipt-emitter] unexpected error, skipping: ${err instanceof Error ? err.message : String(err)}`);
  }
}
