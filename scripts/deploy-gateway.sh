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

# ── dist/ must be buildable ONLY from committed source — fail closed, BEFORE
# the build. `npm run preship` below BUILDS, so a check placed after it would
# abort the restart while leaving a poisoned dist/ on disk for Restart=always
# to deploy on the next crash or reboot. That is exactly how uncommitted code
# reached production on 2026-09-01 17:12.
#
# TWO checks: `git diff` sees MODIFIED tracked files but is BLIND to UNTRACKED
# ones, and a new source file compiles into dist/ while diff stays silent.
#
# Pathspec widened 2026-09-02 to match the four ported guards, which were
# stronger than this original: tsconfig.json (outDir/rootDir/include),
# package.json (the build script), package-lock.json (the dependency tree the
# build compiles against) and .gitignore (an uncommitted edit to which silences
# the untracked half of this very check) all change what lands in dist/ without
# touching src/. Leaving the source snippet weaker than its copies is how the
# advisory and enforcing halves of this control drifted apart in the first place.
#
# Unconditional here, unlike the advisory copy in gate-engagement-check.mjs —
# that gate also runs against --url and dev checkouts where a dirty tree is
# normal. This script has exactly one job and it ends in a restart, so it is
# the right place to be absolute. If git cannot run at all, that is also an
# abort: an unverifiable provenance claim is not a passing one.
echo "[deploy] verifying dist/ can only be built from committed source…"
# Establish that git can answer AT ALL first. Without this, a missing git or a
# non-repo checkout makes `git diff` fail, the || branch fires, and the deploy
# aborts claiming "uncommitted MODIFIED source" — a true halt for a false
# reason, buried under git's usage text. Fail closed, but say why.
git rev-parse --git-dir >/dev/null 2>&1 || { echo "[deploy] ABORT: cannot verify provenance (not a git repo or git unavailable)"; exit 1; }
git diff --quiet HEAD -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore 2>/dev/null || { echo "[deploy] ABORT: uncommitted MODIFIED source under src/ or scripts/ — commit or stash before deploying"; exit 1; }
# Capture separately so "git failed" and "git says clean" cannot be conflated.
# Inline as `[ -z "$(git ls-files …)" ]` this check is FAIL-OPEN: if git errors,
# stdout is empty, the test is true, and the deploy proceeds believing there is
# nothing untracked — the exact blindness this check exists to close.
UNTRACKED=$(git ls-files --others --exclude-standard -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore) || { echo "[deploy] ABORT: cannot enumerate untracked source (git failed)"; exit 1; }
[ -z "$UNTRACKED" ] || { echo "[deploy] ABORT: uncommitted UNTRACKED source under src/ or scripts/ — it would compile into dist/ invisibly to \`git diff\`"; exit 1; }

echo "[deploy] running pre-ship gate-engagement check…"
npm run preship

echo "[deploy] gate passed — restarting byte-x402"
systemctl --user restart byte-x402
sleep 1
systemctl --user --no-pager status byte-x402 | head -5
echo "✅ gateway deployed (pre-ship gate-engagement check passed)"
