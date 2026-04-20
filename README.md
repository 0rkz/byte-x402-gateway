# Byte x402 Gateway

HTTP payment gateway that exposes Byte Protocol data feeds using the [x402](https://www.x402.org/) standard. Any x402-compatible agent can discover and purchase live market data by paying per-request in USDC -- no API keys, no subscriptions, no Web3 wallet required on the consumer side.

## How x402 Works

The [x402 protocol](https://www.x402.org/) turns HTTP into a payment layer. When an agent requests a paid resource, the server responds with **HTTP 402 Payment Required** containing machine-readable payment terms. The agent pays (USDC via a facilitator), attaches the receipt, and replays the request to receive the data.

```
1. Agent  -->  GET /feeds/crypto-top100  -->  Gateway
2. Gateway -->  402 { price: $0.001, payTo: 0x..., network: arb-sepolia }
3. Agent  -->  pays USDC via x402 facilitator  -->  receives receipt
4. Agent  -->  GET /feeds/crypto-top100 + X-Payment: <receipt>  -->  Gateway
5. Gateway -->  verifies receipt  -->  200 { data: [...] }
```

No wallet private keys are needed on the agent side. The x402 facilitator handles payment signing and settlement.

## Available Feeds

| Feed | Endpoint | Price | PQS | Update Freq | Source |
|------|----------|-------|-----|-------------|--------|
| Crypto Top 25 | `/feeds/crypto-top100` | $0.001 | 92 | 60s | CoinGecko |
| DeFi Yields | `/feeds/defi-yields` | $0.001 | 88 | 120s | DeFiLlama |
| Byte Protocol Status | `/feeds/byte-status` | $0.001 | 95 | 30s | Byte Indexer |

**PQS** (Protocol Quality Score) is a 0-100 reliability metric assigned by Byte Protocol based on data freshness, uptime, and source reputation.

## Quick Start

```bash
git clone https://github.com/byte-protocol/x402-gateway.git
cd x402-gateway

cp .env.example .env
# Edit .env -- set PAY_TO_ADDRESS to your wallet

npm install
npm run build
npm start
```

The gateway starts on port 3402 by default.

## Development

```bash
npm run dev    # tsx watch mode with hot reload
```

## Docker

```bash
docker build -t byte-x402-gateway .
docker run -p 3402:3402 --env-file .env byte-x402-gateway
```

## API Endpoints

### Free Endpoints

#### `GET /feeds` -- Feed Discovery

Returns all available feeds with pricing, PQS scores, and endpoint paths. This is the entry point for agent discovery.

```json
{
  "protocol": "Byte Protocol x402 Gateway",
  "version": "0.1.0",
  "network": "eip155:421614",
  "facilitator": "https://facilitator.x402.org",
  "feeds": [
    {
      "id": "crypto-top100",
      "name": "Crypto Top 25",
      "description": "Top 25 cryptocurrencies by market cap with price, volume, and 24h change",
      "price": "$0.001",
      "pqsScore": 92,
      "updateFrequency": "60s",
      "endpoint": "/feeds/crypto-top100"
    }
  ]
}
```

#### `GET /health` -- Health Check

```json
{ "status": "ok", "timestamp": "2025-01-01T00:00:00.000Z", "uptime": 3600 }
```

### Paid Endpoints

All paid endpoints return **HTTP 402** with payment instructions when accessed without a valid `X-Payment` header.

#### `GET /feeds/crypto-top100`

Top 25 cryptocurrencies by market cap. Data sourced from CoinGecko.

```json
{
  "feed": "crypto-top100",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "count": 25,
  "data": [
    {
      "id": "bitcoin",
      "symbol": "btc",
      "name": "Bitcoin",
      "current_price": 97000,
      "market_cap": 1920000000000,
      "market_cap_rank": 1,
      "total_volume": 42000000000,
      "price_change_percentage_24h": 2.5,
      "last_updated": "2025-01-01T00:00:00.000Z"
    }
  ]
}
```

#### `GET /feeds/defi-yields`

Top 50 DeFi yield pools (TVL > $10M, positive APY) across all chains. Data sourced from DeFiLlama.

```json
{
  "feed": "defi-yields",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "count": 50,
  "data": [
    {
      "pool": "pool-id",
      "project": "aave-v3",
      "chain": "Ethereum",
      "symbol": "USDC",
      "tvlUsd": 500000000,
      "apy": 4.52,
      "apyBase": 3.12,
      "apyReward": 1.40
    }
  ]
}
```

#### `GET /feeds/byte-status`

Live Byte Protocol on-chain metrics from the indexer. Falls back to cached/placeholder data when the indexer is unreachable.

```json
{
  "feed": "byte-status",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "data": {
    "protocol": "Byte Protocol",
    "network": "Arbitrum Sepolia",
    "publishers": 3,
    "activeStreams": 5,
    "totalStaked": "50000000000000000000000",
    "totalFeesCollected": "1250000000000000000",
    "recentPublications": 142,
    "uptime": "99.7%"
  }
}
```

## How Agents Discover and Pay for Feeds

1. **Discover** -- Agent sends `GET /feeds` to list available data feeds with pricing
2. **Request** -- Agent sends `GET /feeds/<id>` and receives HTTP 402 with payment terms
3. **Pay** -- Agent sends payment terms to the x402 facilitator, which handles USDC transfer and returns a signed receipt
4. **Access** -- Agent replays the original request with `X-Payment: <receipt>` header and receives the data

The x402 facilitator acts as a trusted intermediary -- the agent never needs to hold crypto or manage private keys directly. Payment settlement happens on-chain (Arbitrum Sepolia for testnet, Arbitrum One for production).

```bash
# Example: full agent flow using curl

# Step 1: Discover feeds
curl http://localhost:3402/feeds

# Step 2: Request paid feed (returns 402 with payment terms)
curl -v http://localhost:3402/feeds/crypto-top100

# Step 3: Pay via facilitator (agent SDK handles this automatically)
# Step 4: Access with receipt
curl -H "X-Payment: <receipt>" http://localhost:3402/feeds/crypto-top100
```

## Architecture

```
                         Byte x402 Gateway (this repo)
                        +------------------------------+
                        |                              |
  Agent (HTTP)  ------> |  Express + x402 Middleware   |
                        |                              |
                        |  /feeds          (free)      |
                        |  /health         (free)      |
                        |  /feeds/*        (paid)      |
                        |                              |
                        +--------+------+---------+----+
                                 |      |         |
                        +--------+  +---+---+  +--+----------+
                        |           |       |  |             |
                   CoinGecko   DeFiLlama   Byte Indexer
                   (crypto)    (defi)      (on-chain status)
                        |           |       |
                        v           v       v
                   Public APIs         Arbitrum Sepolia

  Payment Flow:
  +-------+     402 + terms     +----------+     verify      +-----------+
  | Agent | <------------------ | Gateway  | <-------------- | x402      |
  |       | --- pay via ------> |          | --- settle ---> | Facilitator|
  |       | --- X-Payment ----> |          |                 +-----------+
  +-------+     200 + data      +----------+
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3402` | HTTP server port |
| `PAY_TO_ADDRESS` | Hardhat #0 | Wallet address that receives USDC payments |
| `FACILITATOR_URL` | `https://facilitator.x402.org` | x402 facilitator for payment verification |
| `NETWORK` | `eip155:421614` | CAIP-2 network identifier (Arbitrum Sepolia) |
| `REQUEST_PRICE` | `0.001` | Price per request in USD |
| `CACHE_TTL` | `60` | Data source cache duration in seconds |
| `COINGECKO_API_KEY` | -- | Optional CoinGecko API key for higher rate limits |
| `BYTE_INDEXER_URL` | `http://localhost:4000` | Byte Protocol indexer URL for status feed |

## Project Structure

```
src/
  index.ts          # Express server, x402 middleware, route handlers
  lib/
    config.ts       # Environment config, feed registry, types
  feeds/
    crypto.ts       # CoinGecko top-25 crypto feed
    defi.ts         # DeFiLlama DeFi yields feed
    status.ts       # Byte Protocol on-chain status feed
```

## License

[MIT](LICENSE)
