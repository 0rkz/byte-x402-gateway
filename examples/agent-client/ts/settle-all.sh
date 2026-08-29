#!/usr/bin/env bash
# One-shot Bazaar row refresh: settle all 5 POST-oracle feeds at $0.10 each.
# Prompts for the key at run time — it lives only in this script's process
# environment and dies with it; nothing lands in shell history or files.
set -euo pipefail
cd "$(dirname "$0")"

export EXPECTED_SIGNER=0x91B1690b95F4e70c4DAB60f63068E8C34ef9A6Db
read -r -s -p "key for 9A6Db (input hidden): " AGENT_PRIVATE_KEY
echo
export AGENT_PRIVATE_KEY

# set -e stops the run on the first failed settle (fail-closed sequence).
# address-reputation re-armed 2026-08-17 after the concurrent-verify deploy
# (oracle now bounded by one ~25s Wayback ceiling, inside the gateway's 30s
# budget; live probes 7.1s / 20.2s). Kept LAST: it is still the slowest, so
# a slow-Wayback abort cannot block the other four settles.
# Pass feed names as args to settle a subset (e.g. after a partial run);
# no args = all five.
FEEDS=("$@")
if [ ${#FEEDS[@]} -eq 0 ]; then
  FEEDS=(sanctions-screen pkg-verdict merchant-screen reasoning-verdict address-reputation)
fi
for f in "${FEEDS[@]}"; do
  echo "=== settling $f ==="
  npx tsx pay-and-post.ts --feed "$f" --settle
done

echo "=== all 5 settles completed ==="
