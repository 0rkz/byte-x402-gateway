import dotenv from "dotenv";
dotenv.config();

/**
 * Gateway configuration loaded from environment variables.
 * All values have sensible defaults for local development on Arbitrum Sepolia.
 */
export const config = {
  /** HTTP server port */
  port: parseInt(process.env.PORT || "3402", 10),
  /** Wallet address that receives x402 payments (USDC) */
  payTo: process.env.PAY_TO_ADDRESS || "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  /**
   * x402 facilitator URL for payment verification.
   * Default switched from Coinbase's `facilitator.x402.org` to our self-hosted
   * facilitator because Coinbase's primarily supports base-sepolia, Solana
   * Devnet, Stellar Testnet, and Aptos Testnet — NOT Arbitrum Sepolia.
   * Override via env when running against a different facilitator.
   */
  facilitatorUrl: process.env.FACILITATOR_URL || "http://127.0.0.1:3403",
  /** CAIP-2 network identifier (default: Arbitrum Sepolia) */
  network: (process.env.NETWORK || "eip155:421614") as `${string}:${string}`,
  /**
   * Price per request in atomic USDC base units (6 decimals).
   * "1000" = $0.001. Pass via env when pricing changes.
   * (We construct PaymentOption.price as an explicit AssetAmount object —
   * NOT the "$0.001" dollar-string syntax — because dollar-strings require
   * the SDK's default-asset registry which doesn't have Arb-Sepolia mapped.)
   */
  requestAmountAtomic: process.env.REQUEST_AMOUNT_ATOMIC || "1000",
  /**
   * USDC contract address on the configured chain. Must implement EIP-3009
   * `transferWithAuthorization` for the "exact" scheme to settle.
   * v0.6 §1 redeploy (2026-05-20): production MockUSDC3009 on Arbitrum Sepolia.
   */
  usdcAddress: (process.env.USDC_ADDRESS || "0x1c16659aeb3aE28467E90348fAAB8874a0D3A4d3") as `0x${string}`,
  /** EIP-712 domain for the USDC contract — must match Centre USDC + MockUSDC3009. */
  usdcDomainName: process.env.USDC_DOMAIN_NAME || "USD Coin",
  usdcDomainVersion: process.env.USDC_DOMAIN_VERSION || "2",
  /** Solana wallet address (base58 public key) for receiving x402 payments */
  solanaPayTo: process.env.SOLANA_PAY_TO || "",
  /** CAIP-2 Solana network identifier (default: Solana mainnet) */
  solanaNetwork: (process.env.SOLANA_NETWORK || "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp") as `${string}:${string}`,
  /** Data source cache TTL in milliseconds (env value is in seconds) */
  cacheTtl: parseInt(process.env.CACHE_TTL || "60", 10) * 1000,
  /** Optional CoinGecko API key for higher rate limits */
  coinGeckoApiKey: process.env.COINGECKO_API_KEY || "",
  /** Byte Protocol indexer URL for on-chain status data */
  byteIndexerUrl: process.env.BYTE_INDEXER_URL || "http://localhost:4000",
  /** Byte Protocol fact-oracle URL for the /feeds/fact-query proxy */
  factOracleUrl: process.env.FACT_ORACLE_URL || "https://fact-oracle.payperbyte.io",
};

/** Metadata describing a single data feed exposed by the gateway. */
export interface FeedMetadata {
  /** Unique feed identifier used in URL paths */
  id: string;
  /** Human-readable feed name */
  name: string;
  /** What this feed provides */
  description: string;
  /** Price per request (formatted as "$0.001") */
  price: string;
  /** Protocol Quality Score (0-100) reflecting data reliability */
  pqsScore: number;
  /** How often the underlying data refreshes */
  updateFrequency: string;
  /** HTTP endpoint path */
  endpoint: string;
  /**
   * For feeds backed by the generic discovery-api proxy (i.e. served by a
   * BYTE Library publisher rather than a bespoke upstream fetcher), the
   * publisher's on-chain Arbitrum address. Undefined for bespoke feeds
   * (crypto-top100, defi-yields, byte-status, fact-query).
   */
  publisher?: `0x${string}`;
}

/** Format an atomic-units string as "$x.xxx" for human-readable display. */
function fmtUsdc(atomic: string): string {
  const n = Number(atomic) / 1_000_000;
  return `$${n.toFixed(n < 0.01 ? 4 : 2)}`;
}

/** Registry of all available data feeds served by this gateway. */
export const feedRegistry: FeedMetadata[] = [
  {
    id: "crypto-top100",
    name: "Crypto Top 25",
    description: "Top 25 cryptocurrencies by market cap with price, volume, and 24h change",
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore: 92,
    updateFrequency: "60s",
    endpoint: "/feeds/crypto-top100",
  },
  {
    id: "defi-yields",
    name: "DeFi Yields",
    description: "Top DeFi protocol yields across major chains",
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore: 88,
    updateFrequency: "120s",
    endpoint: "/feeds/defi-yields",
  },
  {
    id: "byte-status",
    name: "Byte Protocol Status",
    description: "Live protocol metrics: publishers, streams, staking, fees",
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore: 95,
    updateFrequency: "30s",
    endpoint: "/feeds/byte-status",
  },
  {
    id: "fact-oracle",
    name: "Byte Fact Oracle",
    description: "Slashable factual question/answer via fact-oracle.payperbyte.io — Claude web search + SelfCheckGPT NLI gate, delivered on-chain",
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore: 91,
    updateFrequency: "on-demand",
    endpoint: "/feeds/fact-oracle",
  },
  // ── BYTE Library publisher feeds (served via the generic discovery-api proxy)
  // Each entry's `publisher` is the on-chain Arbitrum address registered on
  // DataRegistry; the gateway proxies the latest BroadcastStreamed payload
  // for that publisher. Adding/removing a publisher = updating this list.
  ...indexerFeed("weather", "Weather (US, multi-city)", "NWS weather forecasts for 5 US cities (NYC, LA, Chicago, Houston, Miami)", 90, "60s", "0xa820763c023a929e83c59e4fd5a623e5a8efe941"),
  ...indexerFeed("earthquakes", "Earthquakes", "USGS recent significant earthquakes worldwide (M4.0+)", 92, "120s", "0xa1a55406de233901257aec7b499a26f040ba3cfa"),
  ...indexerFeed("space-weather", "Space Weather", "NOAA SWPC solar activity, geomagnetic storms, Kp index", 90, "300s", "0x5c3b05e1b6654d96445193d98b39e2aa4ddffdc4"),
  ...indexerFeed("news-feed", "News (LLM-curated)", "LLM-curated news headlines with source citations", 88, "300s", "0x551a4ed7f4a8cf5170a5efc5a5d1266386962e73"),
  ...indexerFeed("code-pulse", "Code Pulse", "Repo / package release tracker — latest releases of high-signal OSS projects", 88, "600s", "0x15bfc9492940ff2620118f4611eaed949a8415db"),
  ...indexerFeed("runtime-eol", "Runtime EOL", "End-of-life dates and status for language runtimes, frameworks, OSes (endoflife.date)", 90, "daily", "0x17a67d0d18f9b93f064a23d2076074ea8802216f"),
  ...indexerFeed("threat-intel", "Threat Intel", "Live IOCs, CVE highlights, exploit signals from public threat-intel feeds", 88, "300s", "0xb90b00f891dc534a5b59c60170661b868f3c26de"),
  ...indexerFeed("btc-metrics", "BTC Metrics", "Bitcoin chain metrics: hashrate, mempool, mining stats", 85, "120s", "0x07b8c1d531958a3193ea527aea52a9f26bcfe91b"),
  ...indexerFeed("pkg-facts", "Package Facts", "Per-package facts for popular npm/PyPI packages (latest versions, deprecations, advisories)", 85, "on-demand", "0x14cf5b197acd9fe42b51570d812142b8eb7ce131"),
  ...indexerFeed("cve-facts", "CVE Facts", "Detailed facts on individual CVEs (NVD scoring, affected versions, fix availability)", 85, "on-demand", "0x2c95b5af64b305034caea44f13a546d1377b32ac"),
  ...indexerFeed("wiki-facts", "Wikipedia Facts", "Sourced answers from Wikipedia + Wikidata for general-knowledge questions", 85, "on-demand", "0x60c349d98c0c4f8e9768a2bb7bddf4f1281231d4"),
  ...indexerFeed("merchant-trust", "Merchant Trust", "Trust-score signals for merchants/sellers — sanctions, scam-report aggregation, age-of-domain", 85, "on-demand", "0xbc219e76d8b04197380baec27118d98f1e438d7a"),
];

/**
 * Build a feed-registry entry for a BYTE Library publisher-backed feed.
 * Returns a single-element array so the spread above stays a one-liner per feed.
 */
function indexerFeed(
  id: string,
  name: string,
  description: string,
  pqsScore: number,
  updateFrequency: string,
  publisher: `0x${string}`,
): [FeedMetadata] {
  return [{
    id,
    name,
    description,
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore,
    updateFrequency,
    endpoint: `/feeds/${id}`,
    publisher,
  }];
}
