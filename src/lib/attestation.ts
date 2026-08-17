/**
 * X-BYTE-Attestation — EIP-712 PayloadAttestation over the exact response bytes.
 *
 * Closes the gap where the agent card advertises "every response carries an
 * EIP-712 PayloadAttestation receipt" but the data path delivered only a
 * payloadHash/txHash (feeds/generic.ts). The gateway now signs a verify-before-
 * act receipt over the EXACT canonical bytes it returns, emitted as the
 * `X-BYTE-Attestation` response header. A buyer recomputes keccak256(body) and
 * recovers the signer BEFORE acting — the same recompute-hash + recover-signer
 * pattern the on-chain DataStreamLib verifier and the SDK already use.
 *
 * ADDITIVE ONLY. This reuses the consensus-critical "BYTE Library"
 * PayloadAttestation domain + struct VERBATIM (DEPLOY_REVIEW §3): the name is a
 * hard constant and is never renamed; chainId / verifyingContract default to the
 * canonical r2 values and are env-overridable only for a clean Base cutover.
 *
 * NO-KEY POSTURE — FAIL CLOSED (2026-08-01, hardening plan §1.4). If
 * GATEWAY_ATTESTATION_KEY is unset, sendAttested/sendAttestedRaw REFUSE the
 * response with 503 instead of serving a paid 200 with no X-BYTE-Attestation
 * header and no marker. It used to be the opposite ("attestation is disabled and
 * responses are byte-for-byte what they were before — a pure superset"), which
 * is a silent degrade: the catalog, agent.json and /openapi.json all promise
 * that "every data response carries an EIP-712 PayloadAttestation receipt", and
 * a buyer that verifies before acting cannot distinguish "this deployment has no
 * key" from "someone stripped the header in transit". Same class as the
 * merchant-screen fail-closed 503 (data-feeds/merchant-screen/server.py) and
 * required by CLAUDE.md §3: if it cannot be verified, it does not proceed.
 *
 * Scope of the refusal: these two helpers are called ONLY from the paid feed
 * routes (the POST oracle proxies and the publisher-backed GET loop in
 * index.ts — grep sendAttested). The free discovery surfaces (/feeds, /health,
 * /openapi.json, agent.json, .well-known) never call them, so they are
 * unaffected; attestationReceiptBlock() already omits the receipt block from
 * those documents when attestation is disabled. A >=400 makes @x402/express
 * skip settlement, so a refused request is never charged.
 */

import { keccak256, type Hex } from "viem";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";

// ── domain (BYTE Library PayloadAttestation — DEPLOY_REVIEW §3) ──────────────
// name is consensus-critical — NEVER rename or env-override it.
const DOMAIN_NAME = "BYTE Library" as const;
const DOMAIN_VERSION = process.env.ATTESTATION_DOMAIN_VERSION || "1";
const CHAIN_ID = Number(process.env.ATTESTATION_CHAIN_ID || "421614");
// r2 DataStreamLib — the canonical verifyingContract the on-chain attestation +
// SDK already bind to. Override only on a deliberate Base redeploy.
const VERIFYING_CONTRACT = (process.env.ATTESTATION_VERIFYING_CONTRACT ||
  "0x44729bB148F46d8Db509E47b0453edc271e06e95") as Hex;

const ATTESTATION_TTL_S = Number(process.env.ATTESTATION_TTL_S || "300");

// ── Per-feed evidence TTL — SINGLE SEAM (shipped 2026-08-17 in ef78663; see
// docs/EVIDENCE_TTL.md for the full writeup + revert steps).
//
// Evidence-grade feeds (durable compliance artifacts, e.g. sanctions-screen /
// OFAC) need a receipt that outlives the 300s freshness window: a buyer who
// screened a counterparty in a prior period needs the *receipt* to stay
// verifiable long after the *decision* has aged. Grounded design finding
// (EVIDENCE_TTL_DESIGN.md, 2026-08-15): deadline=0 ("never expires") is NOT
// safe — it hard-reverts the on-chain verifier
// (DataStreamLib.sol:514 `if (block.timestamp > att.deadline) revert
// AttestationExpired()` — block.timestamp is always > 0, so 0 always
// reverts) and is rejected as already-expired by 4 of the estate's 5
// verifiers (mcp-server, sdk, both conformance verifiers). So: a far-future
// FINITE deadline, not 0.
//
// EVIDENCE_FEED_IDS is the ONLY allowlist. A feed id NOT in this set is
// completely unaffected — ttlForFeed falls through to the unchanged
// ATTESTATION_TTL_S default (300s) exactly as before this change. Revert by
// emptying the Set (or deleting these two consts + the ttlForFeed branch);
// no other file needs to change on revert (source-only — the running gateway
// still serves the OLD compiled dist/ until rebuilt + restarted, see the
// deploy/revert steps in EVIDENCE_TTL_CHANGE.md).
const EVIDENCE_TTL_S = 315_360_000; // 10 years — far-future finite, never 0
const EVIDENCE_FEED_IDS: ReadonlySet<string> = new Set(["sanctions-screen"]);

/** Resolve the attestation TTL (seconds) for a feed id. Unlisted or absent
 *  feed id → unchanged ATTESTATION_TTL_S default. Exported so the allowlist
 *  is independently testable (diff resolved TTLs before/after per feed). */
export function ttlForFeed(feed?: string): number {
  if (feed && EVIDENCE_FEED_IDS.has(feed)) return EVIDENCE_TTL_S;
  return ATTESTATION_TTL_S;
}

const TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

export interface AttestationDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Hex;
}

export interface ByteAttestation {
  alg: "EIP712-PayloadAttestation";
  domain: AttestationDomain;
  publisher: string;
  payloadHash: string;
  payloadLength: number;
  deadline: number;
  signature: string;
}

function loadAccount(): PrivateKeyAccount | null {
  const raw = (process.env.GATEWAY_ATTESTATION_KEY || "").trim();
  if (!raw) return null;
  const hex = (raw.startsWith("0x") ? raw : `0x${raw}`) as Hex;
  return privateKeyToAccount(hex);
}

const account: PrivateKeyAccount | null = loadAccount();

export function attestationEnabled(): boolean {
  return account !== null;
}

export function attesterAddress(): string | null {
  return account ? account.address : null;
}

export function attestationDomain(): AttestationDomain {
  return { name: DOMAIN_NAME, version: DOMAIN_VERSION, chainId: CHAIN_ID,
           verifyingContract: VERIFYING_CONTRACT };
}

/**
 * Sign an EIP-712 PayloadAttestation over `bodyBytes` (the exact response body).
 * Returns null when no attestation key is configured (attestation disabled).
 */
export async function signCanonicalBytes(
  bodyBytes: Uint8Array,
  opts?: { feed?: string },
): Promise<ByteAttestation | null> {
  if (!account) return null;
  const payloadHash = keccak256(bodyBytes);
  const payloadLength = bodyBytes.length;
  const deadline = Math.floor(Date.now() / 1000) + ttlForFeed(opts?.feed);
  const domain = attestationDomain();
  const signature = await account.signTypedData({
    domain,
    types: TYPES,
    primaryType: "PayloadAttestation",
    message: {
      publisher: account.address,
      payloadHash,
      payloadLength: BigInt(payloadLength),
      deadline: BigInt(deadline),
    },
  });
  return {
    alg: "EIP712-PayloadAttestation",
    domain,
    publisher: account.address,
    payloadHash,
    payloadLength,
    deadline,
    signature,
  };
}

/**
 * Serialize `obj` ONCE, hash + sign those exact bytes, and send the SAME bytes —
 * so the buyer's keccak256(responseBody) matches payloadHash. Drop-in for
 * res.json(). Delegates to sendAttestedRaw, so it inherits the fail-closed
 * no-key refusal documented at the top of this file.
 */
export async function sendAttested(
  res: import("express").Response,
  obj: unknown,
  opts?: { feed?: string },
): Promise<void> {
  const body = JSON.stringify(obj);
  await sendAttestedRaw(res, body, opts);
}

/**
 * Attest and send a pre-serialized JSON body WITHOUT re-serializing it. For
 * proxied upstreams whose payload is already canonically signed (e.g. the
 * address-reputation verdict's embedded attestation over insertion-order
 * minified JSON, which may carry >2^53 integers like balance_wei): a
 * parse/re-stringify round-trip could change the bytes and break the inner
 * attestation, so the gateway signs and forwards the upstream bytes verbatim.
 *
 * FAILS CLOSED with 503 when no attestation key is configured — see the no-key
 * posture note at the top of this file. Callers do nothing after awaiting this,
 * so the refusal is the whole response.
 */
export async function sendAttestedRaw(
  res: import("express").Response,
  body: string,
  opts?: { feed?: string },
): Promise<void> {
  if (!account) {
    // One loud line per refusal: this is an operator misconfiguration, and the
    // 503 is the only symptom a buyer sees. No body/key material is logged.
    console.error(
      "[x402-gateway] FAIL CLOSED: GATEWAY_ATTESTATION_KEY is unset — refusing to " +
        "serve a paid response without its X-BYTE-Attestation receipt",
    );
    res.status(503).json({
      error: "attestation_unavailable",
      detail:
        "This gateway has no attestation key configured, so the response cannot carry the " +
        "X-BYTE-Attestation receipt every paid feed advertises. Refusing to serve it unsigned " +
        "rather than degrade silently. No payment is settled for a refused request.",
    });
    return;
  }
  const att = await signCanonicalBytes(new TextEncoder().encode(body), opts);
  res.type("application/json");
  if (att) res.setHeader("X-BYTE-Attestation", JSON.stringify(att));
  res.send(body);
}
