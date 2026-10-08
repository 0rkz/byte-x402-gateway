/**
 * Unit tests for the POST-oracle list's single source (src/lib/post-oracles.ts)
 * and the openapi x-guidance text derived from it.
 *
 * The defect: x-guidance carried a hand-written oracle list that named the
 * delisted usc-statute and omitted cctp-attestation-latency and regime-signal,
 * while index.ts and openapi.ts each kept their own copy of the Set. The
 * routed set is what index.ts paymentRoutes gates: POST for every feedRegistry
 * entry in POST_ORACLES, plus a gated GET when the feed is publisher-backed.
 * index.ts can't be imported (app.listen at import), so the wiring is pinned
 * from source and the routed set is cross-checked against the operations the
 * OpenAPI doc itself declares.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { POST_ORACLES } from "../../src/lib/post-oracles.js";
import { buildOpenApiDoc } from "../../src/lib/openapi.js";
import { feedRegistry } from "../../src/lib/config.js";

const doc = buildOpenApiDoc();
const guidance: string = doc.info["x-guidance"];

const sorted = (xs: Iterable<string>) => [...xs].sort();

/** Feed ids whose /feeds/<id> path the doc declares with the given methods. */
function docFeedIds(pred: (ops: Record<string, unknown>) => boolean): string[] {
  return Object.entries(doc.paths as Record<string, Record<string, unknown>>)
    .filter(([p, ops]) => /^\/feeds\/[^/]+$/.test(p) && pred(ops))
    .map(([p]) => p.slice("/feeds/".length));
}

/** Source lines with `//` and block-comment lines dropped. */
function codeLines(relPath: string): string {
  const src = readFileSync(fileURLToPath(new URL(`../../${relPath}`, import.meta.url)), "utf8");
  return src.split("\n").filter((l) => !/^\s*(\/\/|\/\*|\*)/.test(l)).join("\n");
}

function guidancePostList(): string[] {
  const m = guidance.match(/POST oracle endpoints \(([^)]+)\)/);
  assert.ok(m, "x-guidance has a 'POST oracle endpoints (…)' list");
  return m[1].split(", ");
}

test("x-guidance POST oracle list equals the routed POST oracle set", () => {
  const listed = guidancePostList();
  const routed = feedRegistry.filter((f) => POST_ORACLES.has(f.id)).map((f) => f.id);
  assert.deepEqual(sorted(listed), sorted(routed));
  // Cross-check against the POST operations the contract itself declares.
  assert.deepEqual(sorted(listed), sorted(docFeedIds((ops) => "post" in ops)));
});

test("x-guidance dual-pattern list equals the publisher-backed POST oracles (gated GET + POST)", () => {
  const m = guidance.match(/([a-z0-9-]+(?:(?:, and |, | and )[a-z0-9-]+)*) ALSO serves? a latest-broadcast GET/);
  assert.ok(m, "x-guidance names the dual-pattern feeds");
  const listed = m[1].split(/, and |, | and /);
  const routed = feedRegistry.filter((f) => POST_ORACLES.has(f.id) && f.publisher).map((f) => f.id);
  assert.deepEqual(sorted(listed), sorted(routed));
  assert.deepEqual(sorted(listed), sorted(docFeedIds((ops) => "post" in ops && "get" in ops)));
});

test("x-guidance names no delisted oracle", () => {
  for (const id of ["usc-statute", "evidence-pack", "liquidation-stream", "token-safety"]) {
    assert.ok(!feedRegistry.some((f) => f.id === id), `${id} re-listed — update this test`);
    assert.ok(!guidance.includes(id), `x-guidance still names delisted ${id}`);
  }
});

test("index.ts and openapi.ts both read POST_ORACLES from lib/post-oracles.ts — no local copy", () => {
  const idx = codeLines("src/index.ts");
  assert.match(idx, /import \{ POST_ORACLES \} from "\.\/lib\/post-oracles\.js";/);
  assert.doesNotMatch(idx, /const POST_ORACLES\s*=/);
  const api = codeLines("src/lib/openapi.ts");
  assert.match(api, /import \{[^}]*\bPOST_ORACLES\b[^}]*\} from "\.\/post-oracles\.js";/);
  assert.match(api, /const POST_ORACLE_IDS = POST_ORACLES;/);
  assert.doesNotMatch(api, /POST_ORACLE_IDS\s*=\s*new Set/);
});
