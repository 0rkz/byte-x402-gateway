/**
 * Feeds served as synchronous POST request-response oracles (JSON request body),
 * not GET broadcast pulls. The ONE source for both sides of the contract:
 *   - index.ts gates `POST /feeds/<id>` for every feedRegistry entry in this set
 *     (paymentRoutes), validates its body, and derives each feed's methods;
 *   - openapi.ts emits the POST operations and the x-guidance oracle list.
 * Until 2026-10-07 each file kept its own copy ("must stay in sync"), and the
 * x-guidance prose kept a third, hand-written one that had drifted (named the
 * delisted usc-statute, omitted cctp-attestation-latency and regime-signal).
 *
 * Pure (no imports) so openapi.ts and tests can read it without pulling in
 * index.ts, which calls app.listen() at import.
 *
 * evidence-pack, liquidation-stream and token-safety are DELISTED (410-Gone stubs
 * in index.ts) — re-add an id here only together with its feedRegistry entry.
 */
export const POST_ORACLES: ReadonlySet<string> = new Set([
  "address-reputation",
  "pkg-verdict",
  "sanctions-screen",
  "positioning-snapshot",
  "reasoning-verdict",
  "runtime-eol",
  "threat-intel",
  "merchant-screen",
  "cctp-attestation-latency",
  "regime-signal",
]);

/**
 * What a POST oracle's 200 BODY carries besides the answer. Every paid 200
 * ALSO carries the gateway's X-BYTE-Attestation header regardless — the POST
 * handlers forward the upstream body byte-for-byte via sendAttestedRaw, which
 * fails closed (503) without a gateway key (attestation.ts sendAttestedRaw).
 *
 *   "always"       — the upstream signs every 200 body (`attestation` field) and
 *                    fails closed (503) with no usable key.
 *   "when-enabled" — the upstream adds `attestation` only when its
 *                    <FEED>_SIGN_RESPONSE env flag is "1" (default "0"); with the
 *                    flag off the field is omitted. Deploy config, not code,
 *                    decides — so public copy must not promise it.
 *   "receipt-after-settlement" — no body attestation (`receipt: null`): the
 *                    gateway forwards no X-BYTE-PAYMENT-CONTEXT, so the upstream
 *                    cannot mint in-band; the signed DeliveryReceipt is minted out
 *                    of band by the onAfterSettle emitter (when
 *                    GATEWAY_HMAC_SECRET is set) and served at GET /proof/:id.
 *
 * Verified from upstream code 2026-10-07 (~/byte/data-feeds, ~/byte/receipts) —
 * the test pins each entry against that source when the checkout is present:
 *   always:       reasoning-verdict/server.py:224, runtime-eol/gate.py:282,
 *                 threat-intel/gate.py:300
 *   when-enabled: address-reputation/server.py:80,361,384;
 *                 merchant-screen/server.py:82,347,371; pkg-verdict/server.py:78,310,333;
 *                 sanctions-screen/server.py:82,354,377;
 *                 positioning-snapshot/server.py:77,291,313;
 *                 cctp-attestation-latency/http_api.py:79,200,204
 *   receipt-after-settlement: receipts/src/service/index.ts:136-138
 */
export type BodyAttestation = "always" | "when-enabled" | "receipt-after-settlement";

export const ORACLE_BODY_ATTESTATION: Readonly<Record<string, BodyAttestation>> = {
  "address-reputation": "when-enabled",
  "pkg-verdict": "when-enabled",
  "sanctions-screen": "when-enabled",
  "positioning-snapshot": "when-enabled",
  "reasoning-verdict": "always",
  "runtime-eol": "always",
  "threat-intel": "always",
  "merchant-screen": "when-enabled",
  "cctp-attestation-latency": "when-enabled",
  "regime-signal": "receipt-after-settlement",
};

/** Free lookup route for a receipt-after-settlement oracle's DeliveryReceipt (index.ts app.get). */
export const RECEIPT_PROOF_ROUTE = "GET /proof/{id}";
/** Where a buyer learns to derive the receipt id (index.ts /proof/:id 400 detail). */
export const RECEIPT_ID_DOCS_URL = "https://www.payperbyte.io/docs/receipts";
