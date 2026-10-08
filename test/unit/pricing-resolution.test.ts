/**
 * Pins the claim every public surface now makes — "each feed has a fixed
 * per-call price, not metered by payload size" — against the price-resolution
 * path itself rather than against the text.
 *
 * config.ts resolves priceAtomic = PRICE_OVERRIDES[id] ?? computePriceAtomic(size)
 * (bespoke/indexer feeds) or an explicit customPricedFeed price. If any feed fell
 * through to the per-KB formula, its price would move with PRICE_PER_KB_ATOMIC /
 * PRICE_FLOOR_ATOMIC. So: resolve the registry in two fresh processes with
 * wildly different (dummy, non-secret) knob values and require every feed's
 * price to be identical — while proving the knobs did reach the formula.
 *
 * The paid route's amount (index.ts buildAccepts(feed.priceAtomic) →
 * price.amount) is NOT exercised behaviourally: paymentRoutes is built inside
 * index.ts, which calls app.listen() at import. Only a source pin is possible
 * there, and it is labelled as such below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { feedRegistry } from "../../src/lib/config.js";

const fixture = fileURLToPath(new URL("./print-prices.fixture.ts", import.meta.url));

function resolveWith(perKb: string, floor: string): { prices: Record<string, string>; perKbOf1024: string } {
  const r = spawnSync(process.execPath, ["--import", "tsx", fixture], {
    encoding: "utf8",
    env: { ...process.env, PRICE_PER_KB_ATOMIC: perKb, PRICE_FLOOR_ATOMIC: floor },
  });
  assert.equal(r.status, 0, `fixture failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

test("no registry feed's price depends on the per-KB formula", () => {
  const a = resolveWith("1", "1");
  const b = resolveWith("987654321", "123456789");
  // The knobs reached computePriceAtomic in each child (else the comparison is vacuous).
  assert.equal(a.perKbOf1024, "1");
  assert.equal(b.perKbOf1024, "987654321");
  assert.deepEqual(Object.keys(b.prices).sort(), feedRegistry.map((f) => f.id).sort());
  for (const f of feedRegistry) {
    assert.equal(a.prices[f.id], b.prices[f.id], `${f.id} price moved with the per-KB knobs`);
    assert.equal(b.prices[f.id], f.priceAtomic, `${f.id} differs from this process's resolution`);
  }
});

test("SOURCE PIN (not behavioural): each paid route's amount is the feed's priceAtomic", () => {
  const src = readFileSync(fileURLToPath(new URL("../../src/index.ts", import.meta.url)), "utf8");
  assert.match(src, /for \(const feed of feedRegistry\) \{\s*const accepts = buildAccepts\(feed\.priceAtomic\);/);
  assert.match(src, /function buildAccepts\(priceAtomic: string\) \{[\s\S]*?amount: priceAtomic,/);
});
