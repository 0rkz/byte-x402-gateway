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

  const res = await fetch("https://yields.llama.fi/pools");
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
