// Child-process fixture for pricing-resolution.test.ts (not itself a test: the
// suite glob is test/unit/*.test.ts). config.ts resolves every feed's price at
// import time, so the only way to observe the resolution path under different
// PRICE_PER_KB_ATOMIC / PRICE_FLOOR_ATOMIC values is a fresh process.
import { feedRegistry, computePriceAtomic } from "../../src/lib/config.js";

process.stdout.write(
  JSON.stringify({
    prices: Object.fromEntries(feedRegistry.map((f) => [f.id, f.priceAtomic])),
    // Proves the knobs reached the formula in this process: 1 KB at the per-KB rate.
    perKbOf1024: computePriceAtomic(1024),
  }),
);
