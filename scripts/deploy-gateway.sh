#!/usr/bin/env sh
# Enforced gateway deploy — the pre-ship gate-engagement check MUST pass before
# the service is (re)started, so a deploy literally cannot go out with a leak.
#
#   ./scripts/deploy-gateway.sh
#
# `set -e` aborts the deploy if `npm run preship` (build + gate-engagement check)
# exits non-zero — a real leak (exit 1) or an infra error (exit 2) both stop the
# restart. Use this instead of a bare `systemctl --user restart byte-x402`.
set -e
cd "$(dirname "$0")/.."

echo "[deploy] running pre-ship gate-engagement check…"
npm run preship

echo "[deploy] gate passed — restarting byte-x402"
systemctl --user restart byte-x402
sleep 1
systemctl --user --no-pager status byte-x402 | head -5
echo "✅ gateway deployed (pre-ship gate-engagement check passed)"
