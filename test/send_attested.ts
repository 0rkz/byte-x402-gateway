/**
 * Proves sendAttested() binds the attestation to the EXACT bytes it sends:
 * keccak256(sent body) === header.payloadHash, and the body is unchanged.
 * Mock Express res — no server, no payment.
 *
 * Run: GATEWAY_ATTESTATION_KEY=0x<32-byte> npx tsx test/send_attested.ts
 */
import { keccak256 } from "viem";
import { sendAttested } from "../src/lib/attestation.js";

async function main(): Promise<void> {
  const headers: Record<string, string> = {};
  let sent = "";
  let ctype = "";
  const res: any = {
    setHeader: (k: string, v: string) => { headers[k] = v; },
    type: (t: string) => { ctype = t; return res; },
    send: (b: string) => { sent = b; },
  };

  const obj = { feed: "perp-funding", data: { asset: "BTC", fundingApr: 0.1095 } };
  await sendAttested(res, obj);

  const headerVal = headers["X-BYTE-Attestation"];
  const att = headerVal ? JSON.parse(headerVal) : null;

  const hasHeader = att !== null;
  const bodyUnchanged = sent === JSON.stringify(obj);
  const hashBindsSentBytes = att !== null &&
    keccak256(new TextEncoder().encode(sent)) === att.payloadHash;
  const lengthOk = att !== null && att.payloadLength === new TextEncoder().encode(sent).length;
  const ctypeOk = ctype === "application/json";

  const pass = hasHeader && bodyUnchanged && hashBindsSentBytes && lengthOk && ctypeOk;
  console.log(JSON.stringify({ hasHeader, bodyUnchanged, hashBindsSentBytes, lengthOk, ctypeOk }, null, 2));
  console.log(pass ? "SEND_ATTESTED TEST: PASS" : "SEND_ATTESTED TEST: FAIL");
  process.exit(pass ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
