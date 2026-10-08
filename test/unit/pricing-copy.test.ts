/**
 * Unit tests for the public pricing copy (src/lib/pricing-copy.ts) and every
 * surface that carries it: /openapi.json, the x402 manifest
 * (/.well-known/x402.json + aliases), the A2A agent card, the ERC-8004
 * registration, and the startup log.
 *
 * The defect: these surfaces said "Per-byte" / "$X/KB" while every listed feed
 * is charged its own fixed priceAtomic per call (index.ts buildAccepts). The
 * index.ts surfaces can't be rendered by importing index.ts (it calls
 * app.listen at import), so their strings live in pricing-copy.ts and a
 * source-wiring test pins that index.ts actually uses them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  PER_CALL_PRICING,
  x402ManifestDescription,
  agentCardDescription,
  agentRegistrationDescription,
  pricingLogLine,
} from "../../src/lib/pricing-copy.js";
import { buildOpenApiDoc } from "../../src/lib/openapi.js";
import { config, feedRegistry, networkInfo } from "../../src/lib/config.js";

const STALE = [/per[- ]byte/i, /\/KB/, /per[- ]?KB/i, /computed price/i, /payload size at/i];

function assertNoSizePricing(text: string, where: string) {
  for (const re of STALE) assert.doesNotMatch(text, re, `${where}: stale size-based wording ${re}`);
}

function assertPerCall(text: string, where: string) {
  assert.ok(text.includes(PER_CALL_PRICING), `${where}: missing the shared per-call pricing sentence`);
}

/** Source lines with `//` and block-comment lines dropped — what can reach a response. */
function codeLines(relPath: string): string {
  const src = readFileSync(fileURLToPath(new URL(`../../${relPath}`, import.meta.url)), "utf8");
  return src
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l))
    .join("\n");
}

test("the shared pricing sentence says fixed per-call and points to GET /feeds + the 402", () => {
  assert.match(PER_CALL_PRICING, /fixed per-call price/);
  assert.match(PER_CALL_PRICING, /GET \/feeds/);
  assert.match(PER_CALL_PRICING, /402 payment challenge/);
  assertNoSizePricing(PER_CALL_PRICING, "PER_CALL_PRICING");
});

test("x402 manifest description: per-call, no per-byte, honesty clause kept", () => {
  const d = x402ManifestDescription(networkInfo().label);
  assertNoSizePricing(d, "x402 manifest");
  assertPerCall(d, "x402 manifest");
  assert.ok(d.includes("(authenticity + tamper-evidence, not data correctness); no token."));
  assert.ok(d.includes(`Settlement on ${networkInfo().label}.`));
});

test("agent card description: per-call, no per-byte, honesty clauses kept", () => {
  const d = agentCardDescription(networkInfo().label);
  assertNoSizePricing(d, "agent.json");
  assertPerCall(d, "agent.json");
  assert.ok(d.includes("pay-per-call via x402"));
  assert.ok(d.includes("receipt (X-BYTE-Attestation) you verify before acting"));
  assert.ok(d.includes("anchored on Arbitrum (chainId 421614) regardless of settlement rail."));
});

test("ERC-8004 registration description: per-call, no per-byte, existing facts kept", () => {
  const d = agentRegistrationDescription(feedRegistry.length);
  assertNoSizePricing(d, "agent-registration.json");
  assertPerCall(d, "agent-registration.json");
  assert.ok(d.includes(`${feedRegistry.length} paid x402 resources`));
  assert.ok(d.includes("callers verify before acting."));
});

test("startup log line: per-call first; per-KB printed only as the labelled fallback", () => {
  const line = pricingLogLine(config.pricePerKBAtomic, config.priceFloorAtomic);
  assert.match(line, /Pricing: fixed per-call/);
  assert.doesNotMatch(line, /Pricing: \$/);
  const fallback = line.indexOf("fallback");
  const kb = line.indexOf("/KB");
  assert.ok(fallback !== -1 && kb > fallback, "the /KB figure must sit after the 'fallback' label");
});

test("openapi.json: no per-byte or /KB wording anywhere; description + x-guidance carry per-call", () => {
  const doc = buildOpenApiDoc();
  assertNoSizePricing(JSON.stringify(doc), "openapi.json");
  assertPerCall(doc.info.description, "openapi info.description");
  assertPerCall(doc.info["x-guidance"], "openapi x-guidance");
});

test("index.ts wires every changed surface to pricing-copy and emits no per-byte / $X/KB text", () => {
  const code = codeLines("src/index.ts");
  assert.match(code, /description: x402ManifestDescription\(net\.label\)/);
  assert.match(code, /description: agentCardDescription\(net\.label\)/);
  assert.match(code, /description: agentRegistrationDescription\(feedRegistry\.length\)/);
  assert.match(code, /console\.log\(pricingLogLine\(config\.pricePerKBAtomic, config\.priceFloorAtomic\)\)/);
  assert.doesNotMatch(code, /per[- ]byte/i);
  assert.doesNotMatch(code, /\/KB/);
});

test("openapi.ts code emits no per-byte / $X/KB text", () => {
  const code = codeLines("src/lib/openapi.ts");
  assert.doesNotMatch(code, /per[- ]byte/i);
  assert.doesNotMatch(code, /\/KB/);
});
