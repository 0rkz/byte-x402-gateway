#!/usr/bin/env python3
"""
BYTE x402 - agent-pays demo (Python, SECONDARY)
===============================================
An autonomous agent that GETs a paid BYTE feed, lets the x402 requests client
auto-handle the HTTP 402 by signing a gasless USDC payment on Base, retries,
and prints the feed data + the on-chain settlement tx hash + a Basescan link.

Matches the gateway's protocol exactly: x402 v2 "exact" EVM scheme, EIP-3009.
The wallet only SIGNS an authorization; the facilitator broadcasts and pays gas,
so the agent needs USDC but no ETH.

Built on the official x402 python package (== the gateway's @x402 v2 line):
    x402.client.x402ClientSync
    x402.mechanisms.evm.exact.register.register_exact_evm_client
    x402.mechanisms.evm.signers.EthAccountSigner  (eth_account / web3)
    x402.http.clients.requests.x402_requests       (auto-paying requests.Session)

Install:
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt

Run:
    AGENT_PRIVATE_KEY=0x... python pay_and_fetch.py            # x402-pulse, Base Sepolia
    AGENT_PRIVATE_KEY=0x... GATEWAY_URL=https://x402.payperbyte.io \
        FEED_PATH=/feeds/x402-pulse NETWORK=base-mainnet python pay_and_fetch.py

Env:
    AGENT_PRIVATE_KEY  (REQUIRED) funded test/agent wallet private key. NEVER hardcode.
    GATEWAY_URL        gateway base URL (default http://127.0.0.1:3402)
    FEED_PATH          feed endpoint to buy (default /feeds/x402-pulse)
    NETWORK            "base-sepolia" (default) | "base-mainnet" (picks Basescan host)
    RPC_URL            optional Base RPC (enables on-chain nonce/allowance reads)
"""
import json
import os
import re
import sys

import requests
from eth_account import Account

from x402.client import x402ClientSync
from x402.http.clients.requests import x402_requests
from x402.http.constants import PAYMENT_RESPONSE_HEADER, X_PAYMENT_RESPONSE_HEADER
from x402.http.utils import decode_payment_response_header
from x402.mechanisms.evm.exact.register import register_exact_evm_client
from x402.mechanisms.evm.signers import EthAccountSigner, EthAccountSignerWithRPC

# -- Config from env ---------------------------------------------------------
PRIVATE_KEY = os.environ.get("AGENT_PRIVATE_KEY")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://127.0.0.1:3402").rstrip("/")
FEED_PATH = os.environ.get("FEED_PATH", "/feeds/x402-pulse")
NETWORK = os.environ.get("NETWORK", "base-sepolia")
RPC_URL = os.environ.get("RPC_URL")

if not PRIVATE_KEY:
    sys.exit("ERROR: set AGENT_PRIVATE_KEY (a funded Base test wallet). Never hardcode it.")
if not re.fullmatch(r"0x[0-9a-fA-F]{64}", PRIVATE_KEY):
    sys.exit("ERROR: AGENT_PRIVATE_KEY must be a 0x-prefixed 32-byte hex private key.")

is_mainnet = NETWORK == "base-mainnet"
basescan = "https://basescan.org" if is_mainnet else "https://sepolia.basescan.org"

# -- Wallet + signer ---------------------------------------------------------
# EthAccountSigner is sign-only (sufficient: gasless EIP-3009, facilitator
# broadcasts). EthAccountSignerWithRPC adds nonce/allowance reads when RPC_URL
# is set - harmless either way for the "exact" USDC path.
account = Account.from_key(PRIVATE_KEY)
signer = EthAccountSignerWithRPC(account, RPC_URL) if RPC_URL else EthAccountSigner(account)

# -- x402 client: exact-EVM scheme, wrapped into an auto-paying Session -------
client = x402ClientSync()
# No `networks=` arg -> registers the eip155:* wildcard, which covers Base
# mainnet (eip155:8453) and Base Sepolia (eip155:84532). The gateway's 402
# names the concrete network + USDC asset; the client pays whatever it asks.
register_exact_evm_client(client, signer)
session = x402_requests(client)


def extract_settlement(resp: requests.Response):
    """Decode the settlement SettleResponse from the response headers (v2 then v1)."""
    raw = resp.headers.get(PAYMENT_RESPONSE_HEADER) or resp.headers.get(X_PAYMENT_RESPONSE_HEADER)
    if not raw:
        return None
    try:
        return decode_payment_response_header(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"[agent] warning: could not decode settlement header: {exc}", file=sys.stderr)
        return None


def main() -> None:
    url = f"{GATEWAY_URL}{FEED_PATH}"
    print(f"[agent] wallet      : {account.address}")
    print(f"[agent] network     : {NETWORK}")
    print(f"[agent] buying      : GET {url}")

    # The wrapped session transparently does: GET -> 402 -> sign USDC payment ->
    # retry with payment header -> return the final (paid) response.
    resp = session.get(url, timeout=60)

    if resp.status_code != 200:
        print(f"[agent] gateway returned {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(2)

    settle = extract_settlement(resp)
    if settle is not None:
        print("\n[agent] PAID + SETTLED")
        print(f"[agent] settlement  : success={settle.success} payer={settle.payer or account.address}")
        print(f"[agent] tx hash     : {settle.transaction}")
        print(f"[agent] basescan    : {basescan}/tx/{settle.transaction}")
    else:
        print("\n[agent] response had no settlement header (free route or already paid).")

    try:
        body = resp.json()
        print(f"\n[agent] feed data   :\n{json.dumps(body, indent=2)}")
    except ValueError:
        print(f"\n[agent] feed data (raw):\n{resp.text}")


if __name__ == "__main__":
    main()
