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
 * If GATEWAY_ATTESTATION_KEY is unset, attestation is disabled and responses are
 * byte-for-byte what they were before — a pure superset.
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
export async function signCanonicalBytes(bodyBytes: Uint8Array): Promise<ByteAttestation | null> {
  if (!account) return null;
  const payloadHash = keccak256(bodyBytes);
  const payloadLength = bodyBytes.length;
  const deadline = Math.floor(Date.now() / 1000) + ATTESTATION_TTL_S;
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
 * so the buyer's keccak256(responseBody) matches payloadHash. Sets the
 * X-BYTE-Attestation header when attestation is enabled. Drop-in for res.json().
 */
export async function sendAttested(res: import("express").Response, obj: unknown): Promise<void> {
  const body = JSON.stringify(obj);
  const att = await signCanonicalBytes(new TextEncoder().encode(body));
  res.type("application/json");
  if (att) res.setHeader("X-BYTE-Attestation", JSON.stringify(att));
  res.send(body);
}
