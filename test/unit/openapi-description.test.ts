/**
 * Unit tests for the public OpenAPI `info.description` (GET /openapi.json) —
 * the text x402scan and other discovery layers ingest.
 *
 * The defect: the description hardcoded a category list (crypto markets, DeFi
 * yields, news, code-pulse, …) that outlived the feed delists, and closed with
 * a per-KB price sentence that matched no listed feed — every feed is charged
 * its own fixed priceAtomic per call (index.ts buildAccepts). These pin the
 * replacement: feed names come from feedRegistry, pricing is per-call, and the
 * honesty clauses survive verbatim.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildOpenApiDoc } from "../../src/lib/openapi.js";
import { feedRegistry } from "../../src/lib/config.js";

const description: string = buildOpenApiDoc().info.description;
const registryIds = new Set(feedRegistry.map((f) => f.id));

// Feed ids delisted per the comments in lib/config.ts feedRegistry. None may be
// advertised in the description while absent from the registry.
const RETIRED_IDS = [
  "crypto-top100", "defi-yields", "space-weather", "news-feed", "code-pulse",
  "x402-pulse", "stablecoin-rails", "perp-funding", "usc-statute",
  "evidence-pack", "token-safety", "liquidation-stream", "agent-compute",
  "agent-memory", "agent-tools",
];

test("description carries no per-KB pricing text", () => {
  assert.doesNotMatch(description, /\/KB/i);
  assert.doesNotMatch(description, /per[- ]?KB/i);
  assert.doesNotMatch(description, /payload size at/i);
});

test("description says pricing is per call and points to GET /feeds + the 402 challenge", () => {
  assert.match(description, /fixed per-call price/);
  assert.match(description, /listed per feed in GET \/feeds/);
  assert.match(description, /402 payment challenge/);
});

test("every feed the description lists is in feedRegistry, and every registry feed is listed", () => {
  const m = description.match(/currently: (.+?) \(each at \/feeds\/<id>/);
  assert.ok(m, "description has a 'currently: … (each at /feeds/<id>' feed list");
  const listed = m[1].split(", ");
  for (const id of listed) assert.ok(registryIds.has(id), `listed feed ${id} not in feedRegistry`);
  assert.equal(new Set(listed).size, registryIds.size);
});

test("description names no retired feed or stale category", () => {
  for (const id of RETIRED_IDS) {
    if (registryIds.has(id)) continue; // re-listed later: then naming it is correct
    assert.ok(!description.includes(id), `retired feed ${id} still named`);
  }
  for (const phrase of ["crypto markets", "DeFi yields", "news", "supply-chain"]) {
    assert.ok(!description.includes(phrase), `stale category "${phrase}" still named`);
  }
});

test("honesty clauses are intact", () => {
  for (const clause of [
    "Both attest authenticity + tamper-evidence under the BYTE Library domain.",
    "NEITHER asserts the correctness of the underlying data or any verdict",
    "NEITHER claims an independent third-party data source signed it — all keys are first-party PayPerByte.",
  ]) {
    assert.ok(description.includes(clause), `missing honesty clause: ${clause}`);
  }
  const attested = description.match(/on the (\d+) attested feeds \(provenance:eip712-attested in GET \/feeds\)/);
  assert.ok(attested, "attested-feed count clause present");
  assert.equal(
    Number(attested[1]),
    feedRegistry.filter((f) => f.provenance === "eip712-attested").length,
  );
});

test("description makes no certification or poisoning claim", () => {
  assert.doesNotMatch(description, /certif/i);
  assert.doesNotMatch(description, /data poisoning/i);
});
