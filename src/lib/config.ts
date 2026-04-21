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
  /** x402 facilitator URL for payment verification */
  facilitatorUrl: process.env.FACILITATOR_URL || "https://facilitator.x402.org",
  /** CAIP-2 network identifier (default: Arbitrum Sepolia) */
  network: (process.env.NETWORK || "eip155:421614") as `${string}:${string}`,
  /** Price per request in USD */
  requestPrice: process.env.REQUEST_PRICE || "0.001",
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
}

/** Registry of all available data feeds served by this gateway. */
export const feedRegistry: FeedMetadata[] = [
  {
    id: "crypto-top100",
    name: "Crypto Top 25",
    description: "Top 25 cryptocurrencies by market cap with price, volume, and 24h change",
    price: `$${config.requestPrice}`,
    pqsScore: 92,
    updateFrequency: "60s",
    endpoint: "/feeds/crypto-top100",
  },
  {
    id: "defi-yields",
    name: "DeFi Yields",
    description: "Top DeFi protocol yields across major chains",
    price: `$${config.requestPrice}`,
    pqsScore: 88,
    updateFrequency: "120s",
    endpoint: "/feeds/defi-yields",
  },
  {
    id: "byte-status",
    name: "Byte Protocol Status",
    description: "Live protocol metrics: publishers, streams, staking, fees",
    price: `$${config.requestPrice}`,
    pqsScore: 95,
    updateFrequency: "30s",
    endpoint: "/feeds/byte-status",
  },
];
