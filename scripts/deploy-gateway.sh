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
# `readlink -f` resolves a SYMLINKED entry point to its target before taking the
# parent. Without it this resolves the LINK's parent — and ~/byte/scripts is an
# established farm of 9 committed symlinks, while ~/byte is itself a git repo
# whose .gitignore:6 is `/*`, i.e. it ignores every service directory. A farm
# symlink to this script therefore guarded ~/byte, where the gateway tree is
# gitignored, so every check below passed while an arbitrarily dirty gateway
# shipped. FD reproduced it 2026-09-02; on that date the bypass was stopped only
# by one incidental untracked file under ~/byte/scripts. All four sibling guards
# had this; the gateway they were ported FROM did not.
cd "$(dirname "$(readlink -f "$0")")/.."
# An exported GIT_DIR/GIT_WORK_TREE makes every git call below answer about a
# FOREIGN repository while `--show-toplevel` still equals `pwd -P` — the guard
# passes against someone else's index. Fail-open; unset before asking git anything.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

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
# Back-ported 2026-09-02 from the four ported guards, which had it and this one
# did not. Every check below is relative to the CURRENT directory, so if git
# resolves to a different repository than the one we are about to build and
# restart, the provenance we prove and the artifact we ship belong to different
# trees — clean-looking, and wrong. That happens whenever this script is invoked
# from an unexpected cwd or through a symlink/worktree that lands elsewhere.
# `cd "$(dirname "$0")/.."` above makes it *likely* correct; this makes it *checked*.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "[deploy] ABORT: cannot resolve the repository root"; exit 1; }
[ "$ROOT" = "$(pwd -P)" ] || { echo "[deploy] ABORT: git resolved to $ROOT, not $(pwd -P) — refusing to guard a different repo"; exit 1; }
git diff --quiet HEAD -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore 2>/dev/null || { echo "[deploy] ABORT: uncommitted MODIFIED source under src/ or scripts/ — commit or stash before deploying"; exit 1; }
# Capture separately so "git failed" and "git says clean" cannot be conflated.
# Inline as `[ -z "$(git ls-files …)" ]` this check is FAIL-OPEN: if git errors,
# stdout is empty, the test is true, and the deploy proceeds believing there is
# nothing untracked — the exact blindness this check exists to close.
UNTRACKED=$(git ls-files --others --exclude-standard -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore) || { echo "[deploy] ABORT: cannot enumerate untracked source (git failed)"; exit 1; }
[ -z "$UNTRACKED" ] || { echo "[deploy] ABORT: uncommitted UNTRACKED source under src/ or scripts/ — it would compile into dist/ invisibly to \`git diff\`"; exit 1; }

echo "[deploy] running pre-ship gate-engagement check…"
npm run preship

# Back-ported 2026-09-02 from the four ported guards. `tsc` can exit 0 having
# emitted nothing useful — a partial write, a full disk — and `set -e` sees
# success. Without this assert the script would go straight to
# `systemctl restart` and publish whatever was already on disk.
#
# ⚠️ WHAT THIS DOES NOT CATCH (FD, 2026-09-02 — do not read more into it):
# `-s` proves the file is non-empty, NOT that this build produced it. `npm run
# build` is bare `tsc` with no prebuild and no clean, so dist/ is NEVER emptied:
# a wrong outDir or a no-emit build leaves YESTERDAY's dist/ in place and every
# assert below passes on it. FD demonstrated exactly that. The siblings close it
# with `STAMP=$(mktemp)` before the build and `[ "$a" -nt "$STAMP" ]` here;
# that freshness check is a tracked follow-up (HIGH-3), not present yet.
# Likewise only 2 of the 8 modules src/index.ts loads are asserted — attestation
# (EIP-712 signer) and receipt-emitter (HMAC) are not (MEDIUM-5).
#
# Both files are named deliberately. dist/index.js alone is NOT sufficient: on
# 2026-09-02 a discovery-api deploy changed live pricing on four public feeds
# while its dist/index.js stayed BYTE-IDENTICAL, because the change compiled to
# dist/lib/feeds.js. This gateway's routes happening to live in src/index.ts is
# luck, not design; src/lib/config.ts carries the feed catalogue and the
# regime-signal upstream pin, and it compiles here.
for a in dist/index.js dist/lib/config.js; do
  [ -s "$a" ] || { echo "[deploy] ABORT: build did not produce a non-empty $a — refusing to restart onto a stale artifact"; exit 1; }
done

echo "[deploy] gate passed — restarting byte-x402"
systemctl --user restart byte-x402
sleep 1
systemctl --user --no-pager status byte-x402 | head -5
echo "✅ gateway deployed (pre-ship gate-engagement check passed)"
