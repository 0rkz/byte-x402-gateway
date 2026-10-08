/**
 * Pins the x-guidance claim about what each POST oracle's paid 200 carries
 * (src/lib/post-oracles.ts ORACLE_BODY_ATTESTATION) against the code that
 * actually produces it — the gateway handlers here, and the upstream services
 * in the sibling checkouts (data-feeds/, receipts/).
 *
 * The defect (FD HIGH, 2026-10-07): x-guidance said every POST oracle "returns
 * its signed answer" in the 200. regime-signal's 200 is { signal, receipt: null,
 * receipt_reason } — the gateway sends no X-BYTE-PAYMENT-CONTEXT, so the
 * upstream cannot mint in-band — and six upstreams embed `attestation` only
 * behind a default-off <FEED>_SIGN_RESPONSE flag.
 *
 * Upstream checks read source from BYTE_UPSTREAM_ROOT (default: the directory
 * holding this repo, i.e. ~/byte for the main checkout). They SKIP, loudly,
 * when that checkout is absent — a skip is not a pass.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import {
  POST_ORACLES,
  ORACLE_BODY_ATTESTATION,
  RECEIPT_PROOF_ROUTE,
  RECEIPT_ID_DOCS_URL,
} from "../../src/lib/post-oracles.js";
import { buildOpenApiDoc } from "../../src/lib/openapi.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const upstreamRoot = process.env.BYTE_UPSTREAM_ROOT ?? resolve(repoRoot, "..");
const haveUpstream = existsSync(resolve(upstreamRoot, "data-feeds")) && existsSync(resolve(upstreamRoot, "receipts"));
const upstreamSkip = haveUpstream ? false : `upstream checkouts not found under ${upstreamRoot} (set BYTE_UPSTREAM_ROOT)`;

const guidance: string = buildOpenApiDoc().info["x-guidance"];

const read = (p: string) => readFileSync(p, "utf8");
/** Source lines with `//` and block-comment lines dropped. */
const code = (src: string) => src.split("\n").filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l)).join("\n");
const gatewayIndex = code(read(resolve(repoRoot, "src/index.ts")));

/** The source of `app.post("/feeds/<id>", …)` up to the next top-level `});`. */
function postHandler(id: string): string {
  const start = gatewayIndex.indexOf(`app.post("/feeds/${id}"`);
  assert.ok(start !== -1, `no app.post handler for /feeds/${id}`);
  const end = gatewayIndex.indexOf("\n});", start);
  return gatewayIndex.slice(start, end);
}

/** Ids named in the x-guidance sentence that ends with `marker`. */
function idsBefore(marker: string): string[] {
  const at = guidance.indexOf(marker);
  if (at === -1) return [];
  const m = guidance.slice(0, at).match(/([a-z0-9-]+(?:(?:, and |, | and )[a-z0-9-]+)*) $/);
  assert.ok(m, `no id list before "${marker}"`);
  return m[1].split(/, and |, | and /);
}

const sorted = (xs: Iterable<string>) => [...xs].sort();
const ofKind = (k: string) => sorted(Object.keys(ORACLE_BODY_ATTESTATION).filter((id) => ORACLE_BODY_ATTESTATION[id] === k));

// Upstream file per oracle, relative to BYTE_UPSTREAM_ROOT.
const UPSTREAM_FILE: Record<string, string> = {
  "address-reputation": "data-feeds/address-reputation/server.py",
  "merchant-screen": "data-feeds/merchant-screen/server.py",
  "pkg-verdict": "data-feeds/pkg-verdict/server.py",
  "sanctions-screen": "data-feeds/sanctions-screen/server.py",
  "positioning-snapshot": "data-feeds/positioning-snapshot/server.py",
  "cctp-attestation-latency": "data-feeds/cctp-attestation-latency/http_api.py",
  "reasoning-verdict": "data-feeds/reasoning-verdict/server.py",
  "runtime-eol": "data-feeds/runtime-eol/gate.py",
  "threat-intel": "data-feeds/threat-intel/gate.py",
  "regime-signal": "receipts/src/service/index.ts",
};

test("every POST oracle has exactly one body-attestation classification", () => {
  assert.deepEqual(sorted(Object.keys(ORACLE_BODY_ATTESTATION)), sorted(POST_ORACLES));
  assert.deepEqual(sorted(Object.keys(UPSTREAM_FILE)), sorted(POST_ORACLES));
});

test("x-guidance no longer claims every POST oracle returns a signed answer", () => {
  assert.doesNotMatch(guidance, /return their signed answer/);
  assert.match(guidance, /Every paid 200 carries the gateway's signed X-BYTE-Attestation header\./);
});

test("x-guidance groups each oracle under the body claim its classification allows", () => {
  assert.deepEqual(sorted(idsBefore("also embed their own EIP-712 `attestation`")), ofKind("always"));
  assert.deepEqual(sorted(idsBefore("embed one only when that feed's response signing is enabled")), ofKind("when-enabled"));
  assert.deepEqual(sorted(idsBefore("returns no body attestation (receipt: null)")), ofKind("receipt-after-settlement"));
});

test("regime-signal is never named under a body-attestation claim (the FD HIGH)", () => {
  assert.equal(ORACLE_BODY_ATTESTATION["regime-signal"], "receipt-after-settlement");
  assert.ok(!idsBefore("also embed their own EIP-712 `attestation`").includes("regime-signal"));
  assert.ok(!idsBefore("embed one only when that feed's response signing is enabled").includes("regime-signal"));
  assert.ok(guidance.includes(`fetch it via ${RECEIPT_PROOF_ROUTE} (id derivation: ${RECEIPT_ID_DOCS_URL})`));
});

test("gateway: every POST oracle 200 goes through sendAttestedRaw, which fails closed without a key", () => {
  for (const id of POST_ORACLES) assert.match(postHandler(id), /await sendAttestedRaw\(res, text/, `${id} handler`);
  const att = code(read(resolve(repoRoot, "src/lib/attestation.ts")));
  const fn = att.slice(att.indexOf("export async function sendAttestedRaw("));
  assert.match(fn, /if \(!account\) \{[\s\S]*?res\.status\(503\)[\s\S]*?return;/);
  assert.match(fn, /res\.setHeader\("X-BYTE-Attestation"/);
});

test("gateway: regime-signal forwards no payment context; /proof/:id route and receipt emitter are wired", () => {
  assert.doesNotMatch(postHandler("regime-signal"), /X-BYTE-PAYMENT-CONTEXT/i);
  assert.match(gatewayIndex, /app\.get\("\/proof\/:id"/);
  assert.ok(gatewayIndex.includes(RECEIPT_ID_DOCS_URL), "proof route's id-derivation URL");
  assert.match(gatewayIndex, /server\.onAfterSettle\(async \(ctx\) => \{\s*void emitFromSettleContext\(/);
  assert.equal(RECEIPT_PROOF_ROUTE, "GET /proof/{id}");
});

test("upstream: 'always' oracles sign every 200 body unconditionally", { skip: upstreamSkip }, () => {
  for (const id of ofKind("always")) {
    const src = read(resolve(upstreamRoot, UPSTREAM_FILE[id]));
    assert.match(src, /\["attestation"\] = _sign_answer\(/, `${id}: unconditional attestation assignment`);
    assert.doesNotMatch(src, /SIGN_RESPONSE_ENABLED/, `${id}: must have no signing on/off flag`);
  }
});

test("upstream: 'when-enabled' oracles sign only behind a default-off flag and omit the field otherwise", { skip: upstreamSkip }, () => {
  for (const id of ofKind("when-enabled")) {
    const src = read(resolve(upstreamRoot, UPSTREAM_FILE[id]));
    assert.match(src, /_SIGN_RESPONSE", "0"\) == "1"/, `${id}: default-off flag`);
    assert.match(src, /_sign_answer\([^)]*\)\s*if SIGN_RESPONSE_ENABLED\s*else None/, `${id}: conditional sign`);
    assert.match(src, /if attestation is not None:/, `${id}: field omitted when unsigned`);
  }
});

test("upstream: regime-signal answers receipt: null without a verified payment context", { skip: upstreamSkip }, () => {
  const src = read(resolve(upstreamRoot, UPSTREAM_FILE["regime-signal"]));
  assert.match(src, /req\.header\("X-BYTE-PAYMENT-CONTEXT"\)/);
  assert.match(src, /if \(!verification\.ok\) \{\s*res\.json\(\{ signal, receipt: null, receipt_reason: verification\.reason \}\);/);
});
