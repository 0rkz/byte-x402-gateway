/**
 * Per-paid-delivery logging — feed-attribution telemetry for the revenue watcher.
 *
 * On every PAID delivery (a 200 whose x402 payment actually SETTLED on-chain),
 * emit ONE structured record so an external buy can be attributed to a FEED:
 *   { ts, feed, status, payer, amountUSDC, txHash, nonce }
 *
 *   payer   — the EIP-3009 authorizer `from` (== the on-chain USDC Transfer
 *             `from`). Read from the AUTHORITATIVE x402 settle response, falling
 *             back to the inbound X-PAYMENT authorization.
 *   txHash  — the on-chain settlement tx hash from the settle response. This is
 *             the SAME tx the revenue watcher sees in the USDC Transfer log, so
 *             it is the exact (1:1) settle→delivery join key.
 *   nonce   — the EIP-3009 authorization nonce (bytes32). It is ALSO encoded in
 *             the on-chain `transferWithAuthorization` (0xe3ee160e) tx input, so
 *             the watcher can join even when txHash is unavailable — killing
 *             same-payer same-block ambiguity.
 *
 * GATE: log iff the x402 PAYMENT-RESPONSE header is present — i.e. the
 * facilitator SETTLED. The publisher's X-BYTE-Attestation rides FREE broadcasts
 * and cached reads too, so it is NOT a paid-delivery marker; gating on it logged
 * non-paid 200s as `payer:null` noise (~20/23 rows). Gating on the settle header
 * records ONLY real sales.
 *
 * NO request bodies, NO secrets, NO payment signatures — just the attribution
 * tuple (payer/amount/nonce are public on-chain anyway).
 *
 * Written to BOTH:
 *   - stdout  → the systemd USER journal (`journalctl --user -u byte-x402`);
 *   - a file  → /home/orkz/byte/logs/gateway-deliveries.jsonl (the durable join
 *               source the watcher reads, independent of journal retention).
 *
 * Best-effort + throw-free: logging must NEVER break or delay a delivery.
 */

import fs from "fs";
import path from "path";
import type { Request, Response } from "express";

const LOG_FILE =
  process.env.GATEWAY_DELIVERY_LOG || "/home/orkz/byte/logs/gateway-deliveries.jsonl";

// Best-effort: ensure the log directory exists once at startup.
try {
  fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
} catch {
  /* ignore — appendFile below is itself best-effort */
}

/** `/feeds/<slug>[/...]` → `slug`, else null. */
function feedSlug(p: string): string | null {
  const m = /^\/feeds\/([^/?#]+)/.exec(p || "");
  return m ? m[1].toLowerCase() : null;
}

/**
 * Decode the x402 settle response (PAYMENT-RESPONSE header, base64 JSON). This
 * header is set by @x402/express ONLY after the facilitator settles on-chain
 * (`createSettlementHeaders` → { "PAYMENT-RESPONSE": <base64> }), so its presence
 * is the authoritative "a payment actually happened" signal. Body shape:
 *   { success, transaction, network, payer, ... }
 * Defensive across shapes; returns nulls on anything malformed — never throws.
 */
function parseSettle(header: string | null): {
  settled: boolean;
  payer: string | null;
  txHash: string | null;
  amountAtomic: string | null;
} {
  if (!header) return { settled: false, payer: null, txHash: null, amountAtomic: null };
  try {
    const r = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    return {
      // The header only exists on a settle; treat anything not explicitly
      // success:false as settled (older facilitators may omit the flag).
      settled: r?.success !== false,
      payer: typeof r?.payer === "string" ? r.payer : null,
      txHash: typeof r?.transaction === "string" ? r.transaction : null,
      // The settle schema carries `amount` (atomic USDC, nullish) — the
      // on-chain-true figure, used to recover the amount if the inbound header
      // is absent/malformed on a genuine settle.
      amountAtomic: r?.amount != null ? String(r.amount) : null,
    };
  } catch {
    return { settled: false, payer: null, txHash: null, amountAtomic: null };
  }
}

/**
 * Extract the payer (EIP-3009 authorizer `from`), atomic amount, and nonce from
 * the inbound x402 payment header (base64 JSON). Defensive across payload shapes;
 * returns nulls on anything malformed — never throws.
 */
function parsePayment(header: string | undefined): {
  payer: string | null;
  amountAtomic: string | null;
  nonce: string | null;
} {
  if (!header) return { payer: null, amountAtomic: null, nonce: null };
  try {
    const json = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    const auth = json?.payload?.authorization ?? json?.authorization ?? {};
    const payer = typeof auth.from === "string" ? auth.from : null;
    const amountAtomic = auth.value != null ? String(auth.value) : null;
    const nonce = typeof auth.nonce === "string" ? auth.nonce : null;
    return { payer, amountAtomic, nonce };
  } catch {
    return { payer: null, amountAtomic: null, nonce: null };
  }
}

/** First present header value (Express getHeader is case-insensitive). */
function header(res: Response, name: string): string | null {
  const v = res.getHeader(name);
  return typeof v === "string" ? v : null;
}

/**
 * Log a paid delivery iff the response is a 200 on a `/feeds/<slug>` route whose
 * x402 payment SETTLED (PAYMENT-RESPONSE header present). Safe to call from a
 * `res.on("finish")` hook on every request — 402 challenges, free broadcasts,
 * cached reads, and errors carry no settle header and are skipped.
 */
export function logDelivery(req: Request, res: Response): void {
  try {
    if (res.statusCode !== 200) return;
    const feed = feedSlug(req.path || req.url || "");
    if (!feed) return;

    // Authoritative paid-delivery gate: a settle happened iff x402 wrote the
    // PAYMENT-RESPONSE header. (Some stacks/clients prefix it X-PAYMENT-RESPONSE.)
    const settleHdr = header(res, "PAYMENT-RESPONSE") ?? header(res, "X-PAYMENT-RESPONSE");
    if (!settleHdr) return; // not a paid delivery — free broadcast / cached / probe
    const settle = parseSettle(settleHdr);
    // Defense-in-depth: a 200 carrying a success:false settle response is not a
    // paid delivery (today @x402 sends those non-200, so this is belt-and-braces).
    if (!settle.settled) return;

    const payHdr = (req.headers["x-payment"] ?? req.headers["payment-signature"]) as
      | string
      | undefined;
    const { payer: hdrPayer, amountAtomic: hdrAmount, nonce } = parsePayment(payHdr);

    // Payer: prefer the on-chain settle authorizer; fall back to the inbound
    // authorization.from.
    const payer = settle.payer ?? hdrPayer;
    // Amount: the inbound EIP-3009 authorization value is unambiguously atomic
    // USDC; fall back to the settle response's amount when the inbound header is
    // absent/malformed on a genuine settle (so a real sale is never amountUSDC:null
    // when the figure is recoverable).
    const amountAtomic = hdrAmount ?? settle.amountAtomic;
    const amountUSDC =
      amountAtomic != null ? Number((Number(amountAtomic) / 1e6).toFixed(6)) : null;

    const rec = {
      ts: new Date().toISOString(), // iso8601 UTC
      feed,
      status: 200,
      payer: payer ? payer.toLowerCase() : null,
      amountUSDC,
      // Deterministic settle→delivery join keys for the revenue watcher.
      txHash: settle.txHash ? settle.txHash.toLowerCase() : null,
      nonce: nonce ? nonce.toLowerCase() : null,
    };
    const line = JSON.stringify(rec);
    // stdout → user journal; file → durable join source for the revenue watcher.
    process.stdout.write(`[delivery] ${line}\n`);
    fs.appendFile(LOG_FILE, line + "\n", () => {});

    // Attribution telemetry: a settled paid delivery with NO payer is a hard hole
    // (no join key of any kind); a delivery with a payer but no deterministic key
    // (txHash/nonce) still attributes via the watcher's payer+time heuristic, so
    // it is a softer notice. Surface both so neither masquerades as "covered".
    if (!rec.payer) {
      process.stdout.write(
        `[delivery][WARN] settled paid 200 on /feeds/${feed} but NO payer captured — ` +
          `cannot attribute this sale to a buyer\n`,
      );
    } else if (!rec.txHash && !rec.nonce) {
      process.stdout.write(
        `[delivery][NOTICE] settled paid 200 on /feeds/${feed} with payer but no ` +
          `deterministic join key (txHash/nonce) — watcher falls back to payer+time heuristic\n`,
      );
    }
  } catch {
    /* never let logging break a delivery */
  }
}
