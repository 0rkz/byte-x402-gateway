/**
 * Proof of the X-BYTE-Attestation receipt: the buyer's verify-before-act flow.
 *
 *   1. recompute keccak256(responseBody) === payloadHash
 *   2. recover the EIP-712 signer === advertised attester (and === publisher field)
 *   3. a tampered body produces a different hash (detection)
 *
 * Emits {body, attestation} to /tmp for the Python cross-tool check (the real
 * buyer SDK is eth_account-based), proving the receipt verifies outside viem.
 *
 * Run:  GATEWAY_ATTESTATION_KEY=0x<32-byte> npx tsx test/attestation.ts
 */
import { keccak256, recoverTypedDataAddress, type Hex } from "viem";
import { writeFileSync } from "node:fs";
import {
  signCanonicalBytes,
  attesterAddress,
  attestationEnabled,
} from "../src/lib/attestation.js";

const TYPES = {
  PayloadAttestation: [
    { name: "publisher", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "payloadLength", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

async function main(): Promise<void> {
  if (!attestationEnabled()) {
    console.error("set GATEWAY_ATTESTATION_KEY to run this test");
    process.exit(2);
  }
  const attester = attesterAddress()!;

  // A representative response body (the shape feeds/generic.ts returns).
  const body = JSON.stringify({
    feed: "perp-funding",
    publisher: "0x533f447c2b82cf903e8189778636ef96c652c892",
    source: "byte-library-broadcast",
    payloadHash: "0x8693974d83c0f39c022cd2a52a0a39f67e0a4c4b41fe07f88ecc6b56d4c2f664",
    data: { asset: "BTC", fundingApr: 0.1095, n: 42 },
  });
  const bytes = new TextEncoder().encode(body);

  const att = await signCanonicalBytes(bytes);
  if (!att) throw new Error("attestation unexpectedly null");

  // 1. hash binds to the exact bytes
  const hashOk = keccak256(bytes) === att.payloadHash;

  // 2. signer recovers to the attester (and the publisher field matches)
  const recovered = await recoverTypedDataAddress({
    domain: att.domain as any,
    types: TYPES,
    primaryType: "PayloadAttestation",
    message: {
      publisher: att.publisher as Hex,
      payloadHash: att.payloadHash as Hex,
      payloadLength: BigInt(att.payloadLength),
      deadline: BigInt(att.deadline),
    },
    signature: att.signature as Hex,
  });
  const signerOk = recovered.toLowerCase() === attester.toLowerCase();
  const pubOk = att.publisher.toLowerCase() === attester.toLowerCase();

  // 3. tamper detection: one flipped byte → different hash
  const tampered = new TextEncoder().encode(body.replace("0.1095", "9.9999"));
  const tamperDetected = keccak256(tampered) !== att.payloadHash;

  const pass = hashOk && signerOk && pubOk && tamperDetected;
  console.log(JSON.stringify({ hashOk, signerOk, pubOk, tamperDetected, attester, recovered }, null, 2));

  writeFileSync("/tmp/byte_attestation_sample.json", JSON.stringify({ body, attestation: att }));
  console.log(pass ? "TS ATTESTATION TEST: PASS" : "TS ATTESTATION TEST: FAIL");
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
