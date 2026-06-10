# FIRST PAYING AGENT — BYTE x402 on Base

**Goal:** take a real USDC payment from an autonomous agent, on Base, through the
existing BYTE x402 gateway — with zero changes to `src/`. The whole switch from
"Arbitrum testnet" to "real money on Base" is a **config change**, because the
gateway is fully ENV-driven via `src/lib/config.ts`.

> **Decouple note (read this first):** the audit gates **DECENTRALIZATION** — the
> BYTE Library on Arbitrum (on-chain registry, slashing, the L3). It does **NOT**
> gate revenue. The x402 settlement path below runs on Base and is independent of
> the Arbitrum contracts — so it is **revenue-capable now, without the audit**. It
> earns nothing until it is deployed with a real `PAY_TO`, a settlement is proven
> (Steps 2–3), and real agents actually pay (Steps 4–5). "Capable," not "earning."

Everything in this runbook short of the steps that move real funds has been
validated offline (see `## What was validated` at the bottom). The remaining
steps — fund a wallet, set `PAY_TO`, run the first paid request — are **founder
actions**, flagged inline as `FOUNDER:`.

---

## How the payment flow works (30-second version)

1. Agent does `GET https://<gateway>/feeds/x402-pulse`.
2. Gateway replies **HTTP 402** with payment requirements: pay `N` atomic USDC
   on Base to `PAY_TO_ADDRESS`, asset = Base USDC, scheme = `exact` (EIP-3009).
3. Agent's x402 client **signs** an EIP-3009 `transferWithAuthorization` (a
   signature, not a transaction — **no gas needed on the agent side**).
4. Agent retries with the signed payment header.
5. Gateway hands the header to the **facilitator** (xpay), which broadcasts the
   transfer and pays the gas. USDC moves from agent → `PAY_TO_ADDRESS`.
6. Gateway returns **200 + the feed data**, plus a `PAYMENT-RESPONSE` header
   carrying the **settlement tx hash**.

The gateway **fails closed**: paid routes return **503** until the facilitator
is reachable and confirms it supports `exact` on the configured network. It
never serves paid data for free.

---

## Step 0 — Wallets (FOUNDER)

You need **two** Base addresses:

- **`PAY_TO` (receiver):** `FOUNDER:` the BYTEDev Inc Base wallet that should
  receive revenue. Put its address in `deploy/base/.env.base-mainnet`
  (`PAY_TO_ADDRESS=`). This is where real USDC lands — get it right.
- **Agent test wallet (payer):** a throwaway wallet whose **private key** the
  demo client reads from `AGENT_PRIVATE_KEY`. It needs **USDC** (no ETH — the
  facilitator sponsors gas).

Fund the agent wallet:
- **Base Sepolia (dry run):** get free test USDC from Circle's faucet
  (<https://faucet.circle.com>, select Base Sepolia). Get a little test ETH too
  if you want to send any normal txs, though the x402 path itself needs none.
- **Base mainnet (real run):** send a **small** amount of real USDC (e.g. \$1)
  to the agent wallet on Base. A single `x402-pulse` call costs ~\$0.015.

> **Security:** `AGENT_PRIVATE_KEY` is read from the environment and **never
> hardcoded**. Use a dedicated low-balance wallet. Do not reuse your `PAY_TO`
> key as the agent key.

---

## Step 1 — Build the gateway

```bash
cd /home/orkz/byte/x402-gateway
npm install            # if node_modules isn't already present
npm run build          # tsc -> dist/   (VALIDATED: clean build)
```

---

## Step 2 — DRY RUN on Base Sepolia (free, no real money)

Prove the full `402 → sign → settle → data` loop with faucet USDC.

**2a. Point the gateway at Base Sepolia.** The profile is pre-filled with the
verified values; `dotenv` loads it (it parses `USD Coin`'s space correctly):

```bash
cd /home/orkz/byte/x402-gateway
cp deploy/base/.env.base-sepolia .env
# FOUNDER: edit .env -> set PAY_TO_ADDRESS to an address you control.
# VERIFY-BEFORE-USE: confirm USDC_ADDRESS (Base Sepolia test USDC) against
#   https://developers.circle.com/stablecoins/usdc-contract-addresses
#   (testnet token addresses get rotated). If signature verification fails on
#   the dry run, re-read name()/version() of the deployed test USDC on Basescan
#   and update USDC_DOMAIN_NAME / USDC_DOMAIN_VERSION.
npm start
```

You should see (VALIDATED — this is real output from this profile):

```
[x402-gateway] EVM Network: eip155:84532
[x402-gateway] USDC asset: 0x036CbD53842c5426634e7929541eC2318f3dCF7e (domain="USD Coin" v2)
[x402-gateway] Facilitator: https://facilitator.xpay.sh/
[x402-gateway]   /feeds/x402-pulse              $0.015 (3000B)
[x402-gateway] Payment middleware active (attempt 1)   <-- xpay supports exact on Base Sepolia
```

`Payment middleware active` (not `FAIL CLOSED`) means the facilitator is live for
this network. Leave the gateway running.

**2b. Run the agent-pays client.** TypeScript is primary:

```bash
cd /home/orkz/byte/x402-gateway/examples/agent-client/ts
npm install
AGENT_PRIVATE_KEY=0x<your funded Base-Sepolia test key> \
  GATEWAY_URL=http://127.0.0.1:3402 \
  FEED_PATH=/feeds/x402-pulse \
  NETWORK=base-sepolia \
  npm start
```

Or the Python client (secondary):

```bash
cd /home/orkz/byte/x402-gateway/examples/agent-client/python
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
AGENT_PRIVATE_KEY=0x<your funded Base-Sepolia test key> \
  GATEWAY_URL=http://127.0.0.1:3402 \
  FEED_PATH=/feeds/x402-pulse \
  NETWORK=base-sepolia \
  python pay_and_fetch.py
```

**Expected client output:**

```
[agent] wallet      : 0x...
[agent] network     : base-sepolia
[agent] buying      : GET http://127.0.0.1:3402/feeds/x402-pulse
[agent] PAID + SETTLED
[agent] settlement  : success=True payer=0x...
[agent] tx hash     : 0x<settlement hash>
[agent] basescan    : https://sepolia.basescan.org/tx/0x<settlement hash>
[agent] feed data   : { ...the x402-pulse payload... }
```

Open the Basescan link → you should see a USDC `transfer` from the agent wallet
to your `PAY_TO`. **That's a settled x402 payment on Base Sepolia.** If you get a
503, the facilitator wasn't reachable yet — wait and retry. If settlement fails,
re-check the `VERIFY-BEFORE-USE` note in 2a (token address / EIP-712 domain).

---

## Step 3 — FLIP to Base mainnet — FIRST REAL SETTLEMENT (FOUNDER)

Same code, same client. Only the network + asset + receiver change.

**3a. Point the gateway at Base mainnet via xpay:**

```bash
cd /home/orkz/byte/x402-gateway
cp deploy/base/.env.base-mainnet .env
# FOUNDER (required): set PAY_TO_ADDRESS to the BYTEDev Inc Base wallet.
# Keep PRICE_FLOOR_ATOMIC small for the first real run (default $0.001 floor;
# x402-pulse lands ~$0.015). Small blast radius on the first real dollar.
npm start
```

Expected output from a **LOCAL boot** of this profile (this is NOT a deployed
endpoint and **no real tx has settled** — the gateway not failing closed only
means the xpay URL was reachable, not that a Base-mainnet settlement is proven):

```
[x402-gateway] EVM Network: eip155:8453
[x402-gateway] USDC asset: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 (domain="USD Coin" v2)
[x402-gateway] Facilitator: https://facilitator.xpay.sh/
[x402-gateway] Payment middleware active (attempt 1)   <-- xpay supports exact on Base MAINNET
```

**3b. Run the client against mainnet** (agent wallet must hold a little real
USDC on Base):

```bash
cd /home/orkz/byte/x402-gateway/examples/agent-client/ts
AGENT_PRIVATE_KEY=0x<funded Base-MAINNET key> \
  GATEWAY_URL=http://127.0.0.1:3402 \
  FEED_PATH=/feeds/x402-pulse \
  NETWORK=base-mainnet \
  npm start
```

The client prints the tx hash and a `https://basescan.org/tx/...` link. Open it:
real USDC moved from the agent wallet to BYTEDev's `PAY_TO`. **That is BYTE's
first paying agent.** Verify the inbound USDC on Basescan under the `PAY_TO`
address.

> **CDP alternative (production, fee-free + compliance):** to use Coinbase's CDP
> facilitator instead of xpay (fee-free USDC on Base mainnet, with KYT/OFAC
> screening), swap `FACILITATOR_URL` in `.env.base-mainnet` to the CDP endpoint
> and supply CDP API keys per Coinbase docs (mainnet requires keys; testnet is
> open). xpay needs **no key**, which is why it's the fastest path to the first
> settlement. The gateway code is facilitator-agnostic — only the URL changes.

---

## Step 4 — Point a real agent builder at it (design partner)

Once mainnet is live, the entire integration a customer needs is: hit the
endpoint with an x402-capable client and a funded wallet. Hand them this.

**Endpoint:** `https://x402.payperbyte.io/feeds/x402-pulse` (and the full catalog
at `GET /feeds`, OpenAPI at `/openapi.json`, machine manifest at
`/.well-known/x402.json`). Price advertised per-feed in the 402.

**Drop-in client snippet (TypeScript, matches `examples/agent-client/ts/`):**

```ts
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

const account = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY as `0x${string}`);
const pub = createPublicClient({ chain: base, transport: http() });
const core = registerExactEvmScheme(new x402Client(), { signer: toClientEvmSigner(account, pub) });
const x402 = new x402HTTPClient(core);

const url = "https://x402.payperbyte.io/feeds/x402-pulse";
let resp = await fetch(url);
if (resp.status === 402) {
  const pr = x402.getPaymentRequiredResponse((n) => resp.headers.get(n));
  const payload = await x402.createPaymentPayload(pr);
  resp = await fetch(url, { headers: x402.encodePaymentSignatureHeader(payload) });
}
const result = await x402.processResponse(resp);
if (result.kind === "success") {
  console.log("tx:", result.settleResponse.transaction, result.body);
}
```

Python builders: point them at `examples/agent-client/python/` (`x402[evm,requests]`).

Good first design partners: any team running LLM agents that already pay for
data/tools, MCP-tool builders, and x402 ecosystem teams (xpay/CDP) looking for
real merchant feeds to list.

---

## OFF-CHAIN BILLING ALTERNATIVE (customers who can't do x402)

Some enterprise/legacy customers can't hold a crypto wallet or sign EIP-3009.
Offer them a **monthly API-access subscription billed in fiat to BYTEDev Inc** —
no on-chain payment on their side. **(Describe-only — do not build Stripe now.)**

Minimal setup:
1. **Stripe** account under BYTEDev Inc. Create a metered or flat **monthly
   Product/Price** ("BYTE Library API — Pro, \$X/mo").
2. **API keys, not wallets.** Issue each subscriber an API key. A thin auth
   shim in front of the gateway (or a separate keyed route) checks the key and
   **bypasses the x402 402** for active subscribers — they get the same feed
   data, no per-call signature. (The x402 middleware already keys off whether a
   valid payment header is present; a subscriber-key check that short-circuits
   to the handler is the only addition.)
3. **Billing.** Stripe Checkout / Billing handles the monthly charge, dunning,
   invoices. Map `stripe_customer_id → api_key`. Optionally report usage to a
   Stripe metered price for usage-based tiers.
4. **Revenue lands in BYTEDev Inc's bank** (via Stripe payout), same legal
   entity as the on-chain `PAY_TO`. Two rails (x402 USDC + Stripe fiat), one
   P&L.

This gives a fiat on-ramp for non-crypto customers while the x402 rail serves
agents — neither depends on the Arbitrum audit.

---

## What was validated (offline, no funds moved)

Done in this environment, no real payment:

- **Both env profiles carry the exact verified values.**
  - `base-mainnet`: `NETWORK=eip155:8453`,
    `USDC_ADDRESS=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`,
    `USDC_DOMAIN_NAME="USD Coin"`, `USDC_DOMAIN_VERSION="2"`,
    `FACILITATOR_URL=https://facilitator.xpay.sh/` (+ commented CDP alt).
  - `base-sepolia`: `NETWORK=eip155:84532`, sepolia USDC marked
    `VERIFY-BEFORE-USE`, xpay facilitator.
  - Confirmed **every var the profiles set is read by `config.ts`**
    (`generic.ts` reads `DISCOVERY_API_URL`).
- **Gateway builds clean:** `npm run build` (tsc) → `dist/` with no errors.
- **Gateway boots on both profiles** (via dotenv) and logs the profile values:
  - Sepolia boot → `EVM Network: eip155:84532`, USDC `0x036C…CF7e`, and
    **`Payment middleware active (attempt 1)`** → xpay supports `exact` on Base
    Sepolia.
  - Mainnet boot (**LOCAL only**) → `EVM Network: eip155:8453`, USDC `0x8335…2913`,
    and `Payment middleware active (attempt 1)` → the middleware initialized and the
    gateway did **not** fail closed against the xpay URL. This is **NOT** proof that
    xpay settles a real Base-mainnet `exact` payment — only the first **actual
    settled tx** (Step 3b, not yet done) proves that. Treat Base-mainnet facilitator
    support as **UNVERIFIED** until the dry run + a real settlement confirm it.
  - `/feeds/x402-pulse` priced `$0.015 (3000B)` on both — the demo's default
    endpoint exists.
- **TS client typechecks** against the real `@x402/core` + `@x402/evm` **v2.13.0**
  and `viem`: `npx tsc --noEmit` → 0 errors.
- **Python client** imports all resolve against `x402==2.12.0` (`[evm,requests]`),
  byte-compiles, and **constructs the auto-paying `requests.Session`** end-to-end
  (only the live `session.get()` was skipped).

**Needs the founder (cannot be done here):** fund a Base wallet with USDC, set
`PAY_TO_ADDRESS`, run the client to produce the first **actual** settled tx, and
verify the inbound USDC on Basescan. Those are Steps 0, 2b, 3a–3b.
```
