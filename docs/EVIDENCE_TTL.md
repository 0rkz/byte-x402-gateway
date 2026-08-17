# Evidence-grade per-feed attestation TTL — sanctions-screen only

Staged 2026-08-17. **Uncommitted, undeployed.** Repo: `/home/orkz/byte/x402-gateway`
(branch `main`, up to date with `origin/main`). Live gateway process is untouched —
this is source-only; the running `dist/index.js` still mints the old 300s deadline
for every feed, sanctions-screen included, until rebuilt + restarted (see Deploy
steps).

Design basis: `EVIDENCE_TTL_DESIGN.md` (2026-08-15 grounded findings, this
scratchpad dir). Verdict there: `deadline = 0` ("never expires") is UNSAFE — it
hard-reverts the on-chain verifier (`contracts/src/library/DataStreamLib.sol:514`,
`AttestationExpired`) and is rejected as already-expired by 4 of the estate's 5
downstream verifiers (mcp-server, sdk, both conformance verifiers). Recommendation
followed exactly: **far-future FINITE deadline**, `EVIDENCE_TTL_S = 315_360_000`
(10 years), zero verifier changes required.

## What changed (file:line)

Three files, `x402-gateway` repo. Exact diff: `evidence_ttl.diff` in this
scratchpad dir (also reproduced in full in my report to the orchestrator).

1. **`src/lib/attestation.ts`** — the seam.
   - New consts after `ATTESTATION_TTL_S` (~line 51):
     `EVIDENCE_TTL_S = 315_360_000` and
     `EVIDENCE_FEED_IDS: ReadonlySet<string> = new Set(["sanctions-screen"])`
     — **this Set is the entire allowlist.** Add/remove a feed id here and
     nothing else needs to change.
   - New exported `ttlForFeed(feed?: string): number` — returns `EVIDENCE_TTL_S`
     if `feed` is in the Set, else the unchanged `ATTESTATION_TTL_S` default.
     Exported so the allowlist is independently testable (see Verification).
   - `signCanonicalBytes(bodyBytes, opts?: { feed?: string })` — deadline now
     computed via `ttlForFeed(opts?.feed)` instead of the bare
     `ATTESTATION_TTL_S` constant.
   - `sendAttested(res, obj, opts?)` and `sendAttestedRaw(res, body, opts?)` —
     both gained an **optional** trailing `opts` param, threaded through to
     `signCanonicalBytes`. Optional means every existing call site that does
     NOT pass `opts` is byte-for-byte unaffected — `opts?.feed` is `undefined`,
     `ttlForFeed(undefined)` returns the old 300s default.

2. **`src/index.ts`** — the one call site.
   - `/feeds/sanctions-screen` POST handler (~line 1810, inside the
     `if (upstream.ok)` branch): `sendAttestedRaw(res, text)` →
     `sendAttestedRaw(res, text, { feed: "sanctions-screen" })`.
   - This is the **only** call site anywhere in the file that passes `opts`.
     Verified by reading all 10 `sendAttested`/`sendAttestedRaw` call sites in
     `src/index.ts` (address-reputation, pkg-verdict, merchant-screen,
     sanctions-screen, reasoning-verdict, runtime-eol POST, threat-intel POST,
     positioning-snapshot, plus the generic publisher-backed GET loop) — every
     other one is untouched.

3. **`src/lib/config.ts`** — the disclosure.
   - `feedRegistry`'s `sanctions-screen` entry (~line 503): appended a
     "Receipt deadline:" sentence to the feed's `description` field. This
     field is the one that fans out to `/feeds`, `/openapi.json`,
     `/.well-known/x402.json` and `agent.json` (established pattern in this
     file — see the merchant-screen TRUST-BOUNDARY comment at the same
     location). Exact added text:

     > Receipt deadline: this feed's EIP-712 receipt is minted with a 10-year
     > freshness window (not the platform's usual 300s), by design —
     > evidence-grade compliance records need to stay independently
     > verifiable long after the screening decision itself has aged. This is
     > a durability choice, not a licence to act on stale data: the receipt
     > still proves only who signed which bytes when, never that the
     > screening result is still current — re-screen before relying on an
     > old answer for a new decision.

   - **Deliberately NOT touched**: the compact 402-challenge description for
     sanctions-screen (`PAYMENT_CHALLENGE_DESCRIPTION["sanctions-screen"]` in
     `src/index.ts`, ~line 331) is already at 298/300 of the hard challenge-echo
     budget documented in this file (exceeding it silently breaks paid replay
     — the 2026-07-29 `'paymentPayload' is invalid` bug class). It already ends
     with a pointer, `Full scope: https://x402.payperbyte.io/feeds`, which now
     carries the deadline disclosure. Widening the compact text was rejected
     as unsafe rather than skipped for convenience.

## What did NOT change (confirm before trusting this doc)

- No other feed's TTL. Verified empirically for all 10 live feeds — see
  Verification below.
- No verifier anywhere (middleware, contract, mcp-server, sdk, conformance).
  None needed to change under the far-future-finite design.
- `contracts/`, `mcp-server/`, `sdk/`, `ops/plans/mp-conformance/` — zero
  files touched. Zero npm republishes needed.
- `data-feeds/sanctions-screen/server.py`'s own `SANCTIONS_SCREEN_ATTEST_TTL_S`
  (the second, embedded-attestation leg on the broadcast path) — **not**
  touched. Per the design report, this gateway-leg change alone is internally
  inconsistent if the embedded leg still expires the provenance signature in
  1h while the delivery receipt is valid 10y. Out of scope for this task
  (scoped to `x402-gateway` only) — flagging so it isn't forgotten before
  this ships for real.
- Pre-existing, unrelated uncommitted changes already sitting in this same
  working tree (NOT mine, NOT part of this diff, untouched by this task):
  `FREE_BREADTH_FEED_IDS` in `src/lib/config.ts` and the corresponding
  `if (feed.publisher && FREE_BREADTH_FEED_IDS.has(feed.id))` branch +
  import in `src/index.ts` (comments date them "staged 2026-08-16,
  uncommitted"), plus modified `examples/agent-client/ts/package.json` /
  `tsconfig.json` and several untracked files under `examples/agent-client/ts/`
  and a `dist.pre-fixa-2026-07-28.CONTAINS-P1-BUG.bak/` directory. All
  pre-existed before this task started; `git status --short` in the repo
  shows them alongside mine. Do not attribute them to this change or bundle
  them into a future commit of this work without separately reviewing them.

## Verification (resolved TTL per feed, before vs after)

Ran via `npx tsx -e '...'` importing the real `ttlForFeed` + `feedRegistry`
from source (not reasoned about — executed):

```
feed_id,before_s,after_s,changed
weather,300,300,false
earthquakes,300,300,false
runtime-eol,300,300,false
threat-intel,300,300,false
address-reputation,300,300,false
pkg-verdict,300,300,false
sanctions-screen,300,315360000,true
reasoning-verdict,300,300,false
merchant-screen,300,300,false
positioning-snapshot,300,300,false
total feeds: 10
```

`before_s = 300` for every feed is not assumed — it's what the pre-edit file
computed for every call site (`Math.floor(Date.now()/1000) + ATTESTATION_TTL_S`,
no per-feed branch existed at all before this change; confirmed by reading the
file prior to editing). Exactly one of ten live feeds changed.

## Deploy steps (NOT run — founder-gated; documented for when authorized)

1. `cd /home/orkz/byte/x402-gateway`
2. Review `git diff -- src/index.ts src/lib/attestation.ts src/lib/config.ts`
   one more time immediately before building.
3. `npm run build` (`tsc`, writes `dist/`) — **this is the step that would
   overwrite the artifact the live process loads.** Do NOT run this against
   the live `dist/` without the WSQ pre-deploy check passing and founder
   go-ahead; the `wsq-deploy` skill wraps exactly this.
4. Restart the gateway process (systemd unit or whatever supervises the 4
   running `node dist/index.js` PIDs observed at task start — PIDs 310817,
   856254, 1226542, 3080629; re-verify live PIDs at deploy time, don't trust
   this list). **A source-only change does nothing until this restart** — the
   live process has the old compiled `dist/` loaded in memory.
5. Post-restart smoke: `POST /feeds/sanctions-screen` with a real payment,
   decode the `X-BYTE-Attestation` header, confirm `deadline` is
   `now + 315_360_000` (not `now + 300`). Confirm every other paid feed's
   receipt is still `now + 300` (spot-check at least address-reputation and
   one publisher-backed GET feed).
6. `npx tsx test/wsq_smoke.ts` free-surface leg at minimum
   (`GATEWAY_URL=http://127.0.0.1:<port>`); paid leg if a payer key is
   available and founder wants the real settlement checked.

## Revert steps

**Source-only revert (staging fix, not yet built/deployed):**
- `git checkout -- src/index.ts src/lib/attestation.ts src/lib/config.ts` in
  `x402-gateway` (or hand-revert the three hunks in `evidence_ttl.diff` if
  other uncommitted work has since landed in those same files and a blanket
  checkout would clobber it — check `git status` first).

**Revert AFTER this has been built + deployed (the real case that matters):**
1. Emptying `EVIDENCE_FEED_IDS` in `src/lib/attestation.ts` (`new Set([])`)
   is sufficient to fully restore old behavior for every feed — no other file
   needs to change. This is the single-line "trivially revertible" seam.
2. **Rebuild + restart are mandatory** — `npm run build && ` restart the
   gateway process. A source-only revert with no rebuild+restart does
   nothing: the live process keeps running whatever `dist/index.js` it last
   loaded into memory.
3. Confirm via the same smoke check as step 5 above: sanctions-screen's
   receipt `deadline` should be back to `now + 300`.
4. Optionally also revert the config.ts disclosure sentence and the index.ts
   comment/opts argument — cosmetic, not required for the behavior revert,
   but keeps the source clean if the feature is fully abandoned rather than
   paused.

## What to watch after a real deploy

- `X-BYTE-Attestation.deadline` on sanctions-screen responses — should jump
  to `~now + 315_360_000`, not silently stay at `now + 300` (would mean the
  build didn't pick up the change or the wrong process restarted).
- Every other feed's `deadline` — should NOT move. If any other feed's
  deadline changes, `EVIDENCE_FEED_IDS` grew unexpectedly or a call site
  gained an `opts` it shouldn't have; check `git diff` before shipping
  further.
- `mcp-server`/`sdk` consumers of this feed specifically — the design report
  found `deadline=0` breaks them; a far-future finite deadline should NOT
  (their expiry rule is `now > deadline`, and `now` will never exceed
  `now + 315_360_000` in any realistic session), but this has not been
  re-verified against a live `byte-mcp-server` buy call in this task — spot
  check once deployed.
- `data-feeds/sanctions-screen/server.py`'s embedded attestation leg —
  untouched, still expires in ~1h by default. Confirm this doesn't produce a
  visibly inconsistent receipt (delivery valid 10y, embedded provenance
  signature stale in 1h) before calling this feature complete end-to-end.
- Bazaar/agent.json/`/feeds` copy — confirm the new disclosure sentence
  actually renders where buyers see it (it rides the existing
  `feed.description` fan-out; not independently re-tested end-to-end here
  beyond the source edit + typecheck).
