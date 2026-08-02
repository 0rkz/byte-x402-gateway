import { config } from "../lib/config.js";

/** Normalized yield pool data from DeFiLlama. */
interface YieldPool {
  pool: string;
  project: string;
  chain: string;
  symbol: string;
  tvlUsd: number;
  apy: number;
  apyBase: number | null;
  apyReward: number | null;
}

/** Response payload for the defi-yields feed. */
interface DeFiFeedPayload {
  feed: string;
  timestamp: string;
  count: number;
  data: YieldPool[];
}

/**
 * Deadline on the DeFiLlama fetch below (same class c8487be bounded for the POST
 * oracle proxies). Node's fetch applies NO response deadline of its own, so an
 * upstream that accepts the connection and then never answers held this call —
 * and its caller — open indefinitely.
 *
 * 15s, matching index.ts's UPSTREAM_FETCH_TIMEOUT_MS for non-probing fetches:
 * this is one external HTTPS GET against a public third-party API, NOT a
 * subject-probing oracle running sequential live probes against a caller-named
 * host, so it deliberately does not get the 30s probing bound.
 *
 * An abort REJECTS (DOMException "TimeoutError") rather than returning a non-ok
 * response, so it takes the same path a refused connection or DNS failure
 * already takes today — past the `!res.ok` stale-cache fallback below and out to
 * the caller. That is not a new error contract; it is the existing one, now
 * reachable in finite time.
 */
const FETCH_TIMEOUT_MS = 15_000;

/** In-memory cache to respect upstream rate limits and reduce latency. */
let cache: { data: DeFiFeedPayload | null; fetchedAt: number } = {
  data: null,
  fetchedAt: 0,
};

/**
 * Fetches the top 50 DeFi yield pools (by TVL) from DeFiLlama.
 * Filters to pools with TVL > $10M and positive APY.
 * Results are cached for {@link config.cacheTtl} milliseconds.
 * Falls back to stale cache data when the upstream API returns an error.
 */
export async function fetchDefiYields(): Promise<DeFiFeedPayload> {
  const now = Date.now();
  if (cache.data && now - cache.fetchedAt < config.cacheTtl) {
    return cache.data;
  }

  const res = await fetch("https://yields.llama.fi/pools", {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    if (cache.data) return cache.data;
    throw new Error(`DeFiLlama API error: ${res.status} ${res.statusText}`);
  }

  const json = (await res.json()) as { data?: any[] };
  const pools: YieldPool[] = (json.data || [])
    .filter((p: any) => p.tvlUsd > 10_000_000 && p.apy > 0)
    .sort((a: any, b: any) => b.tvlUsd - a.tvlUsd)
    .slice(0, 50)
    .map((p: any) => ({
      pool: p.pool,
      project: p.project,
      chain: p.chain,
      symbol: p.symbol,
      tvlUsd: Math.round(p.tvlUsd),
      apy: Math.round(p.apy * 100) / 100,
      apyBase: p.apyBase ? Math.round(p.apyBase * 100) / 100 : null,
      apyReward: p.apyReward ? Math.round(p.apyReward * 100) / 100 : null,
    }));

  const payload: DeFiFeedPayload = {
    feed: "defi-yields",
    timestamp: new Date().toISOString(),
    count: pools.length,
    data: pools,
  };

  cache = { data: payload, fetchedAt: now };
  return payload;
}
