/**
 * Public pricing copy shared by every discovery surface — /openapi.json,
 * /.well-known/x402(.json) + /x402-manifest, /.well-known/agent.json,
 * /.well-known/agent-registration.json — and the startup log, so the wording
 * cannot drift between them.
 *
 * Why "fixed per-call": every paid route is gated on buildAccepts(feed.priceAtomic)
 * (index.ts), a static per-feed amount; nothing in the payment path meters the
 * served bytes. The per-KB formula in config.ts (computePriceAtomic) is only a
 * fallback for a feed registered without an explicit price, and even then it is
 * computed once from the static expectedSizeBytes. These surfaces said
 * "Per-byte" / "$X/KB" until 2026-10-07 — copy only, no price changed.
 *
 * Pure strings (no config import) so tests can render them without starting the
 * gateway: index.ts calls app.listen() at import.
 */

/** The one pricing sentence every public surface carries. */
export const PER_CALL_PRICING =
  "Each feed has a fixed per-call price, not metered by payload size — the exact " +
  "USDC amount is listed per feed in GET /feeds and quoted in that endpoint's 402 " +
  "payment challenge.";

/** `description` of the x402 manifest (/.well-known/x402.json and aliases). */
export function x402ManifestDescription(networkLabel: string): string {
  return (
    "USDC data feeds + oracles for AI agents. First-party, with a verify-before-act " +
    "EIP-712 receipt (authenticity + tamper-evidence, not data correctness); no token. " +
    `Settlement on ${networkLabel}. ${PER_CALL_PRICING}`
  );
}

/** `description` of the A2A agent card (/.well-known/agent.json). */
export function agentCardDescription(networkLabel: string): string {
  return (
    `USDC data feeds + oracles for AI agents — pay-per-call via x402, settled in USDC on ${networkLabel}. ` +
    "Data responses carry an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation) you verify " +
    "before acting; the attestation domain is anchored on Arbitrum (chainId 421614) regardless of " +
    `settlement rail. ${PER_CALL_PRICING}`
  );
}

/** `description` of the ERC-8004 registration (/.well-known/agent-registration.json). */
export function agentRegistrationDescription(feedCount: number): string {
  return (
    "USDC data feeds and oracles for AI agents (display name: PayPerByte). " +
    `${feedCount} paid x402 resources served from https://x402.payperbyte.io, settled in USDC on ` +
    "Base mainnet (eip155:8453); flagship POST /feeds/address-reputation at $0.10. Every data " +
    "response carries an EIP-712 PayloadAttestation receipt (X-BYTE-Attestation header) that " +
    `callers verify before acting. ${PER_CALL_PRICING}`
  );
}

/**
 * Startup-log pricing line. The per-KB rate is printed only as what it is — the
 * fallback for a feed without an explicit price — never as THE price; the
 * per-feed amounts are logged right after it.
 */
export function pricingLogLine(pricePerKBAtomic: string, priceFloorAtomic: string): string {
  const usd = (atomic: string) => `$${(Number(atomic) / 1_000_000).toFixed(6)}`;
  return (
    "[x402-gateway] Pricing: fixed per-call, per feed (amounts below); per-KB fallback for a " +
    `feed without an explicit price: ${usd(pricePerKBAtomic)}/KB (floor ${usd(priceFloorAtomic)})`
  );
}
