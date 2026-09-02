/**
 * Receipt-id validation + the proxy's status-mapping decision, extracted from
 * index.ts so both are unit-testable without booting the server.
 *
 * These are the two pieces of the receipt-transparency routes that carry real
 * risk: the validator is the only thing standing between a caller-supplied path
 * segment and an upstream URL, and the status mapping decides what a buyer is
 * told when a lookup misses. Both were shipped untested in the first cut of
 * this change; a verifier flagged that, correctly.
 */

/**
 * A receipt id is `keccak256(0x00 || canonical_json)` — 0x plus 64 hex digits.
 * Uppercase A-F is accepted as INPUT TOLERANCE only; callers must normalize
 * with normalizeReceiptId before forwarding, because the upstream store lookup
 * is case-sensitive and would answer an authoritative "receipt not found" for a
 * receipt that exists.
 */
export const RECEIPT_ID_RE = /^0x[0-9a-fA-F]{64}$/;

/** Lowercase the id so the case-sensitive upstream lookup can never miss on case alone. */
export function normalizeReceiptId(raw: unknown): string {
  return String(raw ?? "").toLowerCase();
}

/** True only for a well-formed receipt id. Anything else must be rejected at the gateway. */
export function isValidReceiptId(raw: unknown): boolean {
  return RECEIPT_ID_RE.test(normalizeReceiptId(raw));
}

export interface UpstreamMapping {
  /** HTTP status the gateway should answer with. */
  status: number;
  /** Value for the response body's `error` field. */
  error: string;
}

/**
 * Map an upstream status onto the gateway's answer.
 *
 * 4xx is PRESERVED, not collapsed: "receipt not found" is the honest answer to
 * an id that was never minted, and a 502 there would tell a buyer the service is
 * broken when their lookup simply missed. 5xx collapses to 502 so an upstream
 * fault never masquerades as the caller's problem.
 */
export function mapUpstreamStatus(upstreamStatus: number): UpstreamMapping {
  if (upstreamStatus >= 500) return { status: 502, error: "upstream error" };
  if (upstreamStatus === 404) return { status: 404, error: "not_found" };
  return { status: upstreamStatus, error: "upstream error" };
}
