#!/usr/bin/env node
/**
 * PRE-SHIP GATE-ENGAGEMENT CHECK  (the durable fix for the crypto-top100-class leak)
 *
 * The systemic root of every gate leak this project has hit: a payment/verification
 * gate that ISN'T ACTUALLY ENGAGED serves data free. This check makes that class of
 * regression un-shippable. It:
 *
 *   1. Spins up the gateway against an UNREACHABLE facilitator — the worst-case
 *      boot race. In that state EVERY paid route MUST fail closed (503) and NEVER
 *      serve data. (A route that isn't wired into the payment gate falls through to
 *      its handler instead of 503 — exactly the leak — and is caught here.)
 *   2. Enumerates the advertised payable surface from the gateway's OWN
 *      /openapi.json + /feeds + /.well-known/x402.json and asserts each fails closed
 *      unpaid: status ∈ {402, 503}, never 200, never an X-BYTE-Attestation header —
 *      AND probes trailing-slash / case / double-slash / %2F path VARIANTS, since
 *      Express loose routing routes those to the paid handler (the variant-bypass
 *      leak class).
 *   3. Probes a DENYLIST of delisted / no-resale slugs (crypto-top100, token-safety,
 *      …) on BOTH GET and POST (+ variants) and asserts they are GONE (404/410) —
 *      never a live handler (200 = leak; other = dangling handler that WOULD leak
 *      if its upstream came up — the token-safety class). Requires at least one
 *      explicit 410 stub so the delist mechanism is proven wired (not default-404).
 *   4. Sanity-checks the free/meta routes still return 200 (the gate must not
 *      over-block) and that every served feed is declared payable (no undeclared
 *      data route).
 *   5. Flags catalog drift between the live /feeds list and the published catalog
 *      snapshot (and WARNS loudly — never silently skips — if the catalog isn't
 *      reachable, e.g. a standalone gateway checkout without the monorepo sibling).
 *
 * SCOPE / KNOWN LIMITS (stated honestly — see ops/preship/PRESHIP_GATE.md):
 *   - Money-gate scope = the x402-gateway (the only HTTP x402-billed surface; MCP
 *     is stdio, Kit/Gate are libraries covered by the provenance fail-closed suites).
 *   - Only the facilitator-DOWN pass runs, so this asserts FAIL-CLOSED, not that a
 *     live 402 challenge is well-formed or that a forged receipt is rejected (the
 *     verify-path fail-closed suites + @x402 cover that).
 *   - It probes the self-declared surface (/openapi.json + /feeds) + a known
 *     DENYLIST; a brand-new ungated handler at a path absent from BOTH is not
 *     auto-discovered — add such slugs to DENYLIST when delisting.
 *
 * Exit: 0 = SHIP, 1 = DEPLOY BLOCKED (a leak), 2 = INFRA (couldn't run the check).
 *
 * Usage:
 *   node scripts/gate-engagement-check.mjs            # spawn dist/index.js locally (build first)
 *   node scripts/gate-engagement-check.mjs --url URL  # probe a live/remote gateway (read-only)
 *   node scripts/gate-engagement-check.mjs --json      # machine-readable summary
 */

import { spawn } from "node:child_process";
import net from "node:net";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GATEWAY_DIR = path.resolve(__dirname, "..");
const CATALOG_PATH = path.resolve(GATEWAY_DIR, "../distribution-agent/catalog/feeds.json");

// Slugs that must NEVER be served (delisted / no-resale license / dangling). A
// live handler for any of these — even one that 5xx's because its upstream is
// down — is the leak class: flip the upstream up and it serves paid data free.
const DENYLIST = ["crypto-top100", "btc-metrics", "token-safety", "fact-oracle", "liquidation-stream", "evidence-pack"];

// Free/meta routes the gate must NOT block (over-blocking is its own failure).
const FREE_ROUTES = ["/health", "/feeds", "/openapi.json", "/.well-known/x402.json"];

const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const urlIdx = args.indexOf("--url");
const LIVE_URL = urlIdx >= 0 ? args[urlIdx + 1] : null;

const failures = []; // a real leak / wrong status → exit 1
const infraErrors = []; // network/timeout couldn't run the check → exit 2
const warnings = [];
const passes = [];
let sawExplicit410 = false;
const fail = (m) => failures.push(m);
const infra = (m) => infraErrors.push(m);
const warn = (m) => warnings.push(m);
const pass = (m) => passes.push(m);

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function waitForHealth(base, ms = 20000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try {
      const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(1500) });
      if (r.status === 200) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

/** One unpaid probe with a small retry. Returns { status, hasReceipt, bodySample }
 *  or { netError } after retries — callers treat netError as INFRA (exit 2), never
 *  a leak, so a flaky CI runner / remote hiccup can't masquerade as a gate failure. */
async function probe(base, method, p, withBody = false) {
  const init = { method, redirect: "manual" };
  if (withBody || method === "POST") {
    init.headers = { "content-type": "application/json" };
    init.body = JSON.stringify({ probe: "gate-engagement-unpaid" });
  }
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(`${base}${p}`, { ...init, signal: AbortSignal.timeout(8000) });
      const hasReceipt = r.headers.has("x-byte-attestation");
      let bodySample = "";
      try {
        bodySample = (await r.text()).slice(0, 200);
      } catch {
        /* ignore body read errors */
      }
      return { status: r.status, hasReceipt, bodySample };
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, 200 * (attempt + 1)));
    }
  }
  return { netError: lastErr?.message ?? String(lastErr) };
}

/** Path variants Express loose routing routes to the SAME paid handler. The gate
 *  must treat all of these exactly like the canonical path. */
function pathVariants(p) {
  return [
    { label: "trailing-slash", path: `${p}/` },
    { label: "uppercase", path: p.toUpperCase() },
    { label: "double-slash", path: p.replace(/\/([^/]+)$/, "//$1") },
    { label: "%2F-encoded", path: p.replace(/\/([^/]+)$/, "%2F$1") },
  ];
}

/** Assert one paid request failed closed. Returns true if it was a clean PASS. */
function assertPaidClosed(label, res) {
  if (res.netError) {
    infra(`could not probe ${label}: ${res.netError}`);
    return false;
  }
  const { status, hasReceipt, bodySample } = res;
  if (status === 200 || hasReceipt) {
    fail(`LEAK: ${label} returned ${status} UNPAID${hasReceipt ? " WITH X-BYTE-Attestation" : ""} — body: ${bodySample}`);
    return false;
  }
  if (status === 402 || status === 503 || status === 404) {
    pass(`gate engaged: ${label} → ${status} unpaid`);
    return true;
  }
  // Reached the handler/upstream (e.g. 400/5xx) instead of the fail-closed gate.
  fail(`${label} returned ${status} unpaid — it reached the handler instead of the gate (expected 402/503/404, never 200) — body: ${bodySample}`);
  return false;
}

async function enumeratePayable(base) {
  const ops = [];
  try {
    const r = await fetch(`${base}/openapi.json`, { signal: AbortSignal.timeout(8000) });
    const doc = await r.json();
    for (const [p, methods] of Object.entries(doc.paths ?? {})) {
      for (const [method, op] of Object.entries(methods)) {
        if (!op || typeof op !== "object") continue;
        const payable =
          op["x-payment-info"] !== undefined ||
          (op.responses && (op.responses["402"] || op.responses[402]));
        if (payable) ops.push({ method: method.toUpperCase(), path: p });
      }
    }
  } catch (e) {
    infra(`could not read /openapi.json to enumerate the payable surface: ${e.message}`);
  }
  return ops;
}

async function liveFeedSlugs(base) {
  try {
    const r = await fetch(`${base}/feeds`, { signal: AbortSignal.timeout(8000) });
    const doc = await r.json();
    const feeds = doc.feeds ?? doc ?? [];
    return feeds.map((f) => f.id ?? f.slug ?? f.topic).filter(Boolean);
  } catch (e) {
    infra(`could not read /feeds: ${e.message}`);
    return [];
  }
}

function catalogSlugs() {
  if (!existsSync(CATALOG_PATH)) return undefined; // distinguish "absent" from "empty"
  try {
    const doc = JSON.parse(readFileSync(CATALOG_PATH, "utf8"));
    return (doc.feeds ?? []).map((f) => f.topic ?? f.id ?? f.slug).filter(Boolean);
  } catch (e) {
    warn(`could not parse catalog ${CATALOG_PATH}: ${e.message}`);
    return undefined;
  }
}

async function runChecks(base) {
  // ── 1. free/meta routes must be reachable (gate must not over-block) ──
  for (const p of FREE_ROUTES) {
    const res = await probe(base, "GET", p);
    if (res.netError) infra(`free route GET ${p}: ${res.netError}`);
    else if (res.status === 200) pass(`free route reachable: GET ${p} → 200`);
    else fail(`free route GET ${p} returned ${res.status} (gate over-blocking a meta route?)`);
  }

  // ── 2. every advertised payable op must FAIL CLOSED unpaid — canonical + variants ──
  const payable = await enumeratePayable(base);
  if (payable.length === 0 && infraErrors.length === 0) {
    fail("no payable ops found in /openapi.json — cannot verify the gate");
  }
  for (const { method, path: p } of payable) {
    assertPaidClosed(`${method} ${p}`, await probe(base, method, p, method === "POST"));
    for (const v of pathVariants(p)) {
      assertPaidClosed(`${method} ${v.path} [variant:${v.label}]`, await probe(base, method, v.path, method === "POST"));
    }
  }

  // ── 3. denylist slugs must be GONE on both verbs (+ trailing-slash variant) ──
  for (const slug of DENYLIST) {
    for (const method of ["GET", "POST"]) {
      for (const p of [`/feeds/${slug}`, `/feeds/${slug}/`]) {
        const res = await probe(base, method, p, method === "POST");
        if (res.netError) {
          infra(`could not probe delisted ${method} ${p}: ${res.netError}`);
          continue;
        }
        const { status, hasReceipt, bodySample } = res;
        if (status === 410) sawExplicit410 = true;
        if (status === 200 || hasReceipt) {
          fail(`LEAK: delisted ${method} ${p} returned ${status}${hasReceipt ? " WITH receipt" : ""} — must be 404/410. body: ${bodySample}`);
        } else if (status === 404 || status === 410) {
          pass(`delisted route gone: ${method} ${p} → ${status}`);
        } else if (status === 402 || status === 503) {
          warn(`delisted ${method} ${p} returned ${status} — it appears RE-GATED/re-listed; confirm that's intended`);
        } else {
          fail(`DANGLING: delisted ${method} ${p} returned ${status} — a live handler still exists (serves data if its upstream comes up). Must be 404/410.`);
        }
      }
    }
  }
  if (!sawExplicit410 && DENYLIST.length) {
    warn("no delisted route returned an explicit 410 — the delist-stub mechanism may not be exercised (a typo'd DENYLIST slug 404s the same as a real delist). Keep at least one 410 stub.");
  }

  // ── 4. coverage: every served feed must be declared payable in /openapi.json ──
  const live = await liveFeedSlugs(base);
  const payablePaths = new Set(payable.map((o) => o.path));
  for (const slug of live) {
    if (!payablePaths.has(`/feeds/${slug}`)) {
      fail(`feed '${slug}' is advertised in /feeds but NOT declared payable in /openapi.json (undeclared data route)`);
    }
  }
  if (live.length) pass(`/feeds advertises ${live.length} feeds; all cross-checked against /openapi.json`);

  // ── 5. catalog drift — WARN loudly if the catalog isn't reachable (never silent) ──
  const cat = catalogSlugs();
  if (cat === undefined) {
    warn(`catalog drift check SKIPPED — ${path.relative(GATEWAY_DIR, CATALOG_PATH)} not found. Run from the monorepo (the catalog lives in the sibling distribution-agent repo); in a standalone gateway checkout (e.g. CI) this check does not run.`);
  } else {
    const liveSet = new Set(live);
    const extra = cat.filter((s) => !liveSet.has(s));
    const missing = live.filter((s) => !cat.includes(s));
    if (extra.length) fail(`catalog DRIFT: ${path.relative(GATEWAY_DIR, CATALOG_PATH)} lists ${extra.length} feed(s) the gateway no longer serves: ${extra.join(", ")}`);
    if (missing.length) warn(`catalog drift: ${missing.length} live feed(s) missing from the catalog snapshot: ${missing.join(", ")}`);
    if (!extra.length && !missing.length) pass(`catalog snapshot is in sync with the live /feeds list (${live.length} feeds)`);
  }
}

async function main() {
  let child = null;
  let base = LIVE_URL;

  if (!LIVE_URL) {
    const distEntry = path.join(GATEWAY_DIR, "dist", "index.js");
    if (!existsSync(distEntry)) {
      console.error(`[gate-check] ${distEntry} not found — run \`npm run build\` first (or use --url).`);
      process.exit(2);
    }
    const port = await getFreePort();
    base = `http://127.0.0.1:${port}`;
    const logs = [];
    child = spawn(process.execPath, [distEntry], {
      cwd: GATEWAY_DIR,
      env: {
        ...process.env,
        PORT: String(port),
        // UNREACHABLE facilitator → worst-case boot race → paid routes MUST 503.
        FACILITATOR_URL: "http://127.0.0.1:1",
        // No attestation key → no receipt header could ride any response.
        GATEWAY_ATTESTATION_KEY: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (d) => logs.push(d.toString()));
    child.stderr.on("data", (d) => logs.push(d.toString()));

    const healthy = await waitForHealth(base);
    if (!healthy) {
      console.error("[gate-check] gateway did not become healthy in time. Logs:\n" + logs.join(""));
      child.kill("SIGKILL");
      process.exit(2);
    }
  }

  try {
    await runChecks(base);
  } finally {
    if (child) child.kill("SIGKILL");
  }

  // A real leak (exit 1) outranks an infra error (exit 2); infra outranks ship.
  const code = failures.length > 0 ? 1 : infraErrors.length > 0 ? 2 : 0;
  const summary = {
    ship: code === 0,
    code,
    failures,
    infraErrors,
    warnings,
    passed: passes.length,
    mode: LIVE_URL ? `live:${LIVE_URL}` : "local-spawn (facilitator unreachable)",
  };

  if (JSON_OUT) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.log(`\n══ Pre-ship gate-engagement check (${summary.mode}) ══`);
    for (const p of passes) console.log(`  ✓ ${p}`);
    for (const w of warnings) console.log(`  ⚠ ${w}`);
    for (const e of infraErrors) console.log(`  ⚙ INFRA: ${e}`);
    for (const f of failures) console.log(`  ✗ ${f}`);
    const verdict = code === 0 ? "SHIP ✅" : code === 1 ? "DEPLOY BLOCKED ❌ (leak)" : "CANNOT RUN ⚙ (infra)";
    console.log(`\n${verdict} — ${passes.length} passed, ${warnings.length} warnings, ${infraErrors.length} infra, ${failures.length} failures\n`);
  }
  process.exit(code);
}

main().catch((e) => {
  console.error("[gate-check] fatal:", e);
  process.exit(2);
});
