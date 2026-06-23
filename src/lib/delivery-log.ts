/**
 * Per-paid-delivery logging — feed-attribution telemetry for the revenue watcher.
 *
 * On every successful paid 200 that carries an X-BYTE-Attestation receipt, emit
 * ONE structured record so an external buy can be attributed to a FEED:
 *   { ts, feed, status, payer, amountUSDC }
 * where `payer` is the EIP-3009 authorizer `from` (== the on-chain USDC Transfer
 * `from`), recovered from the inbound x402 payment header. NO request bodies, NO
 * secrets, NO payment signatures — just the attribution tuple.
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
 * Extract the payer (EIP-3009 authorizer `from`) + atomic amount from the inbound
 * x402 payment header (base64 JSON). Defensive across payload shapes; returns
 * nulls on anything malformed — never throws.
 */
function parsePayment(header: string | undefined): {
  payer: string | null;
  amountAtomic: string | null;
} {
  if (!header) return { payer: null, amountAtomic: null };
  try {
    const json = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    const auth = json?.payload?.authorization ?? json?.authorization ?? {};
    const payer = typeof auth.from === "string" ? auth.from : null;
    const amountAtomic = auth.value != null ? String(auth.value) : null;
    return { payer, amountAtomic };
  } catch {
    return { payer: null, amountAtomic: null };
  }
}

/**
 * Log a paid delivery iff the response is a 200 carrying an X-BYTE-Attestation on
 * a `/feeds/<slug>` route. Safe to call from a `res.on("finish")` hook on every
 * request — non-deliveries (402 challenges, free routes, errors) are skipped.
 */
export function logDelivery(req: Request, res: Response): void {
  try {
    if (res.statusCode !== 200) return;
    if (!res.getHeader("X-BYTE-Attestation")) return;
    const feed = feedSlug(req.path || req.url || "");
    if (!feed) return;

    const hdr = (req.headers["x-payment"] ?? req.headers["payment-signature"]) as
      | string
      | undefined;
    const { payer, amountAtomic } = parsePayment(hdr);
    const amountUSDC =
      amountAtomic != null ? Number((Number(amountAtomic) / 1e6).toFixed(6)) : null;

    const rec = {
      ts: new Date().toISOString(), // iso8601 UTC
      feed,
      status: 200,
      payer: payer ? payer.toLowerCase() : null,
      amountUSDC,
    };
    const line = JSON.stringify(rec);
    // stdout → user journal; file → durable join source for the revenue watcher.
    process.stdout.write(`[delivery] ${line}\n`);
    fs.appendFile(LOG_FILE, line + "\n", () => {});
  } catch {
    /* never let logging break a delivery */
  }
}
