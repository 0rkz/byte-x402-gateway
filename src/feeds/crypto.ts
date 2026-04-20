import { config } from "../lib/config.js";

/** Individual coin data returned by CoinGecko /coins/markets. */
interface CoinData {
  id: string;
  symbol: string;
  name: string;
  current_price: number;
  market_cap: number;
  market_cap_rank: number;
  total_volume: number;
  price_change_percentage_24h: number;
  last_updated: string;
}

/** Response payload for the crypto-top100 feed. */
interface CryptoFeedPayload {
  feed: string;
  timestamp: string;
  count: number;
  data: CoinData[];
}

/** In-memory cache to respect upstream rate limits and reduce latency. */
let cache: { data: CryptoFeedPayload | null; fetchedAt: number } = {
  data: null,
  fetchedAt: 0,
};

/**
 * Fetches the top 25 cryptocurrencies by market cap from CoinGecko.
 * Results are cached for {@link config.cacheTtl} milliseconds.
 * Falls back to stale cache data when the upstream API returns an error.
 */
export async function fetchCryptoTop100(): Promise<CryptoFeedPayload> {
  const now = Date.now();
  if (cache.data && now - cache.fetchedAt < config.cacheTtl) {
    return cache.data;
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (config.coinGeckoApiKey) {
    headers["x-cg-demo-api-key"] = config.coinGeckoApiKey;
  }

  const url =
    "https://api.coingecko.com/api/v3/coins/markets?" +
    new URLSearchParams({
      vs_currency: "usd",
      order: "market_cap_desc",
      per_page: "25",
      page: "1",
      sparkline: "false",
    }).toString();

  const res = await fetch(url, { headers });
  if (!res.ok) {
    if (cache.data) return cache.data;
    throw new Error(`CoinGecko API error: ${res.status} ${res.statusText}`);
  }

  const coins = (await res.json()) as CoinData[];

  const payload: CryptoFeedPayload = {
    feed: "crypto-top100",
    timestamp: new Date().toISOString(),
    count: coins.length,
    data: coins.map((c) => ({
      id: c.id,
      symbol: c.symbol,
      name: c.name,
      current_price: c.current_price,
      market_cap: c.market_cap,
      market_cap_rank: c.market_cap_rank,
      total_volume: c.total_volume,
      price_change_percentage_24h: c.price_change_percentage_24h,
      last_updated: c.last_updated,
    })),
  };

  cache = { data: payload, fetchedAt: now };
  return payload;
}
