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
   * Pre-v0.6 §1 redeploy: point at a temp MockUSDC3009 deployment.
   * Post-v0.6 §1: point at production MockUSDC3009 address.
   */
  usdcAddress: (process.env.USDC_ADDRESS || "0x93BfEbF99AF028ee57B138Fd17a26cAe76a01Fd2") as `0x${string}`,
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
    id: "fact-query",
    name: "Byte Fact Oracle",
    description: "Slashable factual question/answer via fact-oracle.payperbyte.io — Claude web search + SelfCheckGPT NLI gate, delivered on-chain",
    price: fmtUsdc(config.requestAmountAtomic),
    pqsScore: 91,
    updateFrequency: "on-demand",
    endpoint: "/feeds/fact-query",
  },
];
