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
git diff --quiet HEAD -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore .npmrc 2>/dev/null || { echo "[deploy] ABORT: uncommitted MODIFIED source under src/ or scripts/ — commit or stash before deploying"; exit 1; }
# Capture separately so "git failed" and "git says clean" cannot be conflated.
# Inline as `[ -z "$(git ls-files …)" ]` this check is FAIL-OPEN: if git errors,
# stdout is empty, the test is true, and the deploy proceeds believing there is
# nothing untracked — the exact blindness this check exists to close.
UNTRACKED=$(git ls-files --others --exclude-standard -- src/ scripts/ tsconfig.json package.json package-lock.json .gitignore .npmrc) || { echo "[deploy] ABORT: cannot enumerate untracked source (git failed)"; exit 1; }
[ -z "$UNTRACKED" ] || { echo "[deploy] ABORT: uncommitted UNTRACKED source under src/ or scripts/ — it would compile into dist/ invisibly to \`git diff\`"; exit 1; }

# ── DEPENDENCY GUARD ─────────────────────────────────────────────────────────
# WHY (measured 2026-09-09, LOCAL c314e5): this script never installed anything.
# `npm run preship` builds, but it compiles against whatever node_modules already
# holds. A commit that changes ONLY package.json + package-lock.json — the shape
# of every Dependabot bump — passed every guard above, built, restarted, printed
# the banner, and shipped the OLD tree. On that date this gateway was still
# running axios 1.16.0 after the 1.18.0 override had been committed and pushed.
# The HIGH advisory it was meant to close stayed open while the deploy said ✅.
#
# `npm ci`, never `npm install`: ci refuses to run when package.json and the lock
# disagree and never rewrites the lock mid-deploy.
#
# ⚠️ Reinstalls node_modules while byte-x402 is still serving. ~1s window;
# founder-accepted 2026-09-09 over stop-first.
[ -f package-lock.json ] || { echo "[deploy] ABORT: no package-lock.json — npm ci cannot pin a dependency tree"; exit 1; }
if [ -n "${DEPLOY_DRY_RUN:-}" ]; then
  echo "[deploy] DRY RUN: dependency changes npm ci would apply —"
  npm ci --dry-run --no-audit --no-fund --include=dev 2>&1 | sed 's/^/  /'
  echo "[deploy] DRY RUN: would then run preship, restart byte-x402, and assert installed == lock."
  echo "[deploy] DRY RUN: nothing was installed, built or restarted."
  exit 0
fi
echo "[deploy] installing dependencies from package-lock.json…"
npm ci --no-audit --no-fund --include=dev || {
  echo "[deploy] ABORT: npm ci failed — nothing was built or restarted."
  echo "[deploy]   Most often package.json and package-lock.json disagree."
  echo "[deploy]   Fix on a dev checkout with 'npm install', COMMIT the lock, then redeploy."
  echo "[deploy]   Do NOT run 'npm install' here: it rewrites the lock during a deploy."
  exit 1
}

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
sleep 3

# ── LIVENESS ASSERTION ───────────────────────────────────────────────────────
# Back-ported 2026-09-09 from the four sibling guards, which have had it since
# 2026-09-05 while this one — the script the others were PORTED FROM — did not.
# It printed `status | head -5` and then echoed success unconditionally, so a
# unit that came back FAILED still produced a green banner. Printing state is not
# asserting it. `sleep 1` also raised to 3 to match the siblings: a unit can be
# `activating` a second after restart and read as neither active nor failed.
systemctl --user is-active --quiet byte-x402 || {
  echo "[deploy] ABORT: byte-x402 did not come back active after restart"
  systemctl --user --no-pager status byte-x402 | head -20
  exit 1
}
systemctl --user --no-pager status byte-x402 | head -5

# ── RUNNING-TREE ASSERTION (Ndev HIGH-1 + LOW-3, 2026-09-09; MEDIUM-1 2026-09-11) ─
# assert-deps.mjs below reads ./node_modules — THIS tree. Nothing so far proves
# the unit runs from here: its WorkingDirectory is set in the unit file, which
# this script never reads, so "installed == lock in the RUNNING tree" held only
# by convention. Read the PROCESS instead of the unit file — /proc is what the
# kernel says, and it sidesteps the 2026-09-03 objection to parsing ExecStart
# syntax. Placed AFTER the restart on purpose: the PID here is the new process.
#
# TWO facts are needed; CWD ALONE IS NOT ENOUGH (VER 3 MEDIUM-1, 2026-09-10).
# Node resolves node_modules from the SCRIPT's directory, not from cwd, so an
# absolute ExecStart pointing outside this repo passes a cwd-only check while
# assert-deps certifies a tree the service never loaded — the exact false-green
# this guard exists to prevent. Not hypothetical: on 2026-09-11 the pre-fix
# check returned 0 against a fixture whose cwd was this tree and whose script
# lived in a different one. Hence both of:
#   1. /proc/PID/cwd is this tree          — pins where the process RUNS.
#   2. the argv script path, IF ABSOLUTE, is under this tree — pins where it
#      LOADS from. A relative path resolves against cwd, which (1) already
#      pinned, so it needs no further proof.
# LIMIT, stated rather than papered over: "first argv token not starting with -"
# is a heuristic, not a node argument parser. `node -r ./boot.js dist/index.js`
# would mistake the preload for the script. No unit here uses that form, and an
# absent or unreadable script path ABORTS rather than passing quietly — wrong in
# the safe direction. This pins the LOAD PATH only; whether the bytes in that
# tree match the lock is what assert-deps below checks.
DEPLOY_PID=$(systemctl --user show -p MainPID --value byte-x402 2>/dev/null || echo 0)
if [ -z "$DEPLOY_PID" ] || [ "$DEPLOY_PID" = "0" ]; then
  echo "[deploy] ABORT: byte-x402 reports no MainPID after restart — cannot prove which tree it runs from"
  exit 1
fi
DEPLOY_TREE=$(pwd -P)
DEPLOY_CWD=$(readlink -f "/proc/$DEPLOY_PID/cwd" 2>/dev/null) || { echo "[deploy] ABORT: cannot read /proc/$DEPLOY_PID/cwd — cannot prove which tree byte-x402 runs from"; exit 1; }
[ "$DEPLOY_CWD" = "$DEPLOY_TREE" ] || { echo "[deploy] ABORT: byte-x402 runs from $DEPLOY_CWD, not $DEPLOY_TREE — this deploy guarded a different tree"; exit 1; }

DEPLOY_ARGV=$(tr '\0' '\n' < "/proc/$DEPLOY_PID/cmdline" 2>/dev/null) || { echo "[deploy] ABORT: cannot read /proc/$DEPLOY_PID/cmdline — cannot prove which tree byte-x402 loaded from"; exit 1; }
DEPLOY_SCRIPT=$(printf '%s\n' "$DEPLOY_ARGV" | awk 'NR > 1 && $0 != "" && $0 !~ /^-/ { print; exit }')
if [ -z "$DEPLOY_SCRIPT" ]; then
  echo "[deploy] ABORT: byte-x402 argv carries no script path — cannot prove which tree it loaded from"
  exit 1
fi
case "$DEPLOY_SCRIPT" in
  /*)
    DEPLOY_ROOT=$(readlink -f "$(dirname "$DEPLOY_SCRIPT")" 2>/dev/null) || DEPLOY_ROOT=""
    case "$DEPLOY_ROOT" in
      "$DEPLOY_TREE" | "$DEPLOY_TREE"/*) : ;;
      *)
        echo "[deploy] ABORT: byte-x402 loaded $DEPLOY_SCRIPT, which is outside $DEPLOY_TREE."
        echo "[deploy]   Node resolves node_modules from the script's directory, so the"
        echo "[deploy]   assertion below would certify a tree this service never loaded."
        exit 1
        ;;
    esac
    ;;
esac
# `is-active` one moment after a restart also passes a unit that is crash-LOOPING
# under Restart=always: it dies, systemd revives it, and each snapshot looks
# active. Re-read MainPID after a pause — a changed PID means it restarted again.
sleep 2
DEPLOY_PID2=$(systemctl --user show -p MainPID --value byte-x402 2>/dev/null || echo 0)
[ "$DEPLOY_PID2" = "$DEPLOY_PID" ] || { echo "[deploy] ABORT: byte-x402 restarted again (PID $DEPLOY_PID -> $DEPLOY_PID2) — it is crash-looping, not running"; exit 1; }

# ── INSTALLED-vs-LOCK ASSERTION ──────────────────────────────────────────────
# `npm ci` exiting 0 is necessary but not sufficient: a partial write, a
# postinstall that mutates node_modules, or a directory left by an interrupted
# run all survive a zero exit. Assert what is actually on disk, after the restart,
# so the claim covers the tree the running process loaded from. Exit 2 (cannot
# verify) is treated like exit 1 — "I could not check" must never reach the banner.
node scripts/assert-deps.mjs --quiet || {
  echo "[deploy] ABORT: the installed dependency tree does not match package-lock.json."
  echo "[deploy]   byte-x402 has already restarted and is serving the artifact above."
  echo "[deploy]   Investigate before declaring this deploy done."
  exit 1
}
echo "✅ gateway deployed (pre-ship gate passed, unit active, deps match lock)"
