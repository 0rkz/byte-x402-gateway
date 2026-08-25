# viem pinned to exact 2.54.2 (not a `^` range)

`package.json` pins `"viem": "2.54.2"` instead of a caret range. Do not
`npm update viem` back onto a floating range without re-reading this.

## Why not `^2.21.0` (or any range that admits 2.55.x)

`npm audit`'s advisory for viem in this dependency tree flags the vulnerable
range as `0.2.2 - 2.54.1` (HIGH, via `ws`) — patched starting at **2.54.2**,
which bumps `ws` from `8.20.1` to `8.21.0` (verified directly:
`npm view viem@2.54.1 dependencies.ws` → `8.20.1`;
`npm view viem@2.54.2 dependencies.ws` → `8.21.0`). That `ws` bump is what
closes GHSA-96hv-2xvq-fx4p.

A plain `npm update viem` lands on the newest version satisfying the range —
today that's **2.55.19**, which also carries the fix. But 2.55.19 ships a new
`_types/package.json` containing `{"type":"module"}` that 2.54.2 (and
2.51.0, the version before this fix) does not have. Under this repo's
`tsconfig.json` (`"module"`/`"moduleResolution": "node16"`), that marker
makes TypeScript treat `viem`'s type declarations as ESM and refuse to let
`src/lib/attestation.ts` (a CommonJS file — no `"type": "module"` in this
`package.json`) statically `import` from it:

```
error TS1479: The current file is a CommonJS module whose imports will
produce 'require' calls; however, the referenced file is an ECMAScript
module and cannot be imported with 'require'.
```

Confirmed by bisection (`npm pack` + diff across 2.51.0 / 2.54.1 / 2.54.2 /
2.54.5 / 2.55.0 / 2.55.19): the `_types/package.json` marker is absent
through 2.55.0 and present at 2.55.19 — the exact version boundary wasn't
narrowed further than that. `x402-facilitator` and `mcp-server` don't hit
this because their tsconfigs use `"moduleResolution": "bundler"`, which
doesn't enforce the same CJS/ESM interop check.

**2.54.2 is the oldest version that is both patched and known to typecheck
clean here** — hence the exact pin.

## When to unpin

Either of:
- This repo's `tsconfig.json` moves off `"moduleResolution": "node16"`
  (e.g. to `"bundler"`, matching the other two repos) — the TS1479 class of
  error goes away regardless of viem's packaging.
- A future viem release removes or fixes the `_types/package.json` ESM
  marker so it resolves correctly under `node16` again.

Either way: re-run `npx tsc --noEmit` after bumping before trusting a wider
range again.

## Remaining `npm audit` findings (3, as of 2026-08-25) — not fixable here

`npm audit fix` (no `--force`) cannot close these; `npm audit` currently
reports 3 (1 high, 1 moderate, 1 low), all needing a semver-major bump in a
dependency this repo doesn't control directly:

- **axios** (HIGH, range `1.0.0 - 1.17.0`, multiple GHSAs — DoS via
  recursion, prototype pollution, `maxBodyLength` bypass, etc.) — pulled in
  transitively via `@coinbase/cdp-sdk >=1.46.1`.
- **@coinbase/cdp-sdk** (MODERATE, range `>=1.46.1`) — npm audit's own node
  for "depends on vulnerable versions of axios"; same root cause as above,
  not a separate issue.
- **esbuild** (LOW, range `0.27.3 - 0.28.0`, dev-time-only — arbitrary file
  read via the esbuild dev server, Windows-specific) — a build-tool
  devDependency, not part of the shipped runtime.

axios and @coinbase/cdp-sdk are blocked on `@coinbase/cdp-sdk` shipping an
axios `>=1.18.0` (or later patched) dependency; not actionable from this repo
alone. esbuild is independent: it comes via `tsx` (devDependency) and closes
with a `tsx` bump once it carries esbuild `>=0.28.1`.

Re-check with `npm audit` after any `@coinbase/cdp-sdk` or `tsx` bump.
