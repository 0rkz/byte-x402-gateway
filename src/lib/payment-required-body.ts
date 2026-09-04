/**
 * Mirror the x402 PAYMENT-REQUIRED challenge into the 402 body.
 *
 * @x402/express (2.13.0) answers an unpaid request with the full v2 challenge
 * in the base64 PAYMENT-REQUIRED header and `{}` in the body — its
 * payment-error branch copies `response.headers` and then does
 * `res.json(response.body || {})` (node_modules/@x402/express/dist/esm/index.mjs).
 * Core builds the challenge object for the header only; the adapter offers no
 * option to put it in the body. Measured on the loopback gateway 2026-09-04:
 * `GET /feeds/earthquakes` → 402, Content-Length 2.
 *
 * A client that reads bodies — most HTTP tooling, every log line, urllib —
 * therefore sees a 402 with nothing in it: no `accepts`, no price, no `payTo`.
 * It walks away with nothing to log. Silent loss.
 *
 * This wrapper leaves the header untouched and, ONLY when the body would be
 * empty, writes the DECODED header as the body. Body and header are then the
 * same object by construction; a client may read either. Everything else —
 * a non-402, a 402 that already carries a body (a verify-failure message),
 * a 402 with no challenge header, the HTML paywall path (`res.send`) — goes
 * out exactly as before. Never throws; on any doubt the original body wins.
 */
import type { Response } from "express";
import { decodePaymentRequiredHeader } from "@x402/core/http";

const CHALLENGE_HEADER = "PAYMENT-REQUIRED";

function isEmptyBody(body: unknown): boolean {
  if (body === undefined || body === null) return true;
  return (
    typeof body === "object" &&
    !Array.isArray(body) &&
    Object.keys(body as Record<string, unknown>).length === 0
  );
}

/**
 * Decode a PAYMENT-REQUIRED header value with core's own decoder.
 * Null on anything that is not a string or does not decode to an object.
 */
export function decodeChallenge(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    const decoded = decodePaymentRequiredHeader(value) as unknown;
    return decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? (decoded as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

type Mirrored = Response & { __paymentRequiredBodyMirrored?: true };

/**
 * Install on a response before the payment middleware runs. Idempotent —
 * a second call on the same response is a no-op.
 */
export function mirrorPaymentRequiredBody(res: Response): void {
  const r = res as Mirrored;
  if (r.__paymentRequiredBodyMirrored) return;
  r.__paymentRequiredBodyMirrored = true;

  const originalJson = res.json.bind(res);
  res.json = ((body?: unknown) => {
    if (res.statusCode === 402 && isEmptyBody(body)) {
      const challenge = decodeChallenge(res.getHeader(CHALLENGE_HEADER));
      if (challenge) return originalJson(challenge);
    }
    return originalJson(body);
  }) as Response["json"];
}
