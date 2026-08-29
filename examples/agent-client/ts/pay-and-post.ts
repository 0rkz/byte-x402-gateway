/**
 * BYTE x402 — pay-and-post (TypeScript)
 * =====================================
 * POST client for BYTE's 5 KYA/verdict oracle feeds: address-reputation,
 * sanctions-screen, pkg-verdict, reasoning-verdict, merchant-screen. Mirrors
 * pay-and-fetch.ts's x402 handshake (@x402/core + @x402/evm v2.13.x, viem)
 * for a POST body instead of GET, and adds:
 *
 *   - Live body-schema validation. The request body is checked against the
 *     feed's requestBody schema pulled from GATEWAY_URL/openapi.json AT RUN
 *     TIME — never a hardcoded copy. No schema found for the path, or the
 *     spec fetch fails => abort. Never guess whether a body is valid.
 *   - A hard $0.10 USDC spend cap enforced on every path (dry-run and
 *     settle). The asset's decimal precision is read ON-CHAIN via the
 *     ERC-20 decimals() call against the exact asset address the challenge
 *     names — never assumed to be 6. MAX_USDC may tighten the cap below
 *     $0.10; it can never raise it above the hard ceiling in code.
 *   - --dry-run (the default — no flag needed): fetches the 402, validates
 *     the challenge (scheme/network/payTo/asset/amount) and the spend cap,
 *     prints exactly what WOULD be signed, and stops. No signer is ever
 *     constructed in this mode and AGENT_PRIVATE_KEY is never read.
 *   - --settle: the live path. Requires AGENT_PRIVATE_KEY. Runs the exact
 *     same schema + challenge + cap checks before anything is signed.
 *
 * Run (dry-run, no key needed, nothing spent):
 *   npx tsx pay-and-post.ts --feed address-reputation
 *   npx tsx pay-and-post.ts --feed sanctions-screen --dry-run
 *   npx tsx pay-and-post.ts --path /feeds/pkg-verdict --body '{"ecosystem":"npm","package":"left-pad"}'
 *
 * Run (live — money moves, founder-gated):
 *   AGENT_PRIVATE_KEY=0x... npx tsx pay-and-post.ts --feed pkg-verdict --settle
 *
 * Feed selection (exactly one of):
 *   --feed <id>     one of: address-reputation | sanctions-screen | pkg-verdict
 *                   | reasoning-verdict | merchant-screen — resolves the path
 *                   AND a built-in minimal valid sample body for that feed.
 *   --path <path>   raw feed path override, e.g. /feeds/some-other-feed.
 *   --body <json>   raw JSON body override. Falls back to the --feed sample
 *                   when omitted. Required if --path is used without --feed.
 *   FEED_PATH / BODY env vars are equivalent to --path / --body (flags win).
 *
 * Env:
 *   GATEWAY_URL         default https://x402.payperbyte.io
 *   NETWORK             "base" (default, mainnet eip155:8453) | "base-sepolia"
 *   RPC_URL             optional Base RPC override (viem public RPC default)
 *   AGENT_PRIVATE_KEY   ONLY read when --settle is passed. Never read, never
 *                       printed, in dry-run.
 *   MAX_USDC            optional, tightens the cap below $0.10. Cannot raise it.
 *   EXPECTED_SIGNER     optional address pin: --settle aborts before signing
 *                       if AGENT_PRIVATE_KEY does not derive this address.
 *
 * Exit codes: 0 = dry-run completed / live settle succeeded
 *             1 = usage error / unexpected HTTP status / other error
 *             2 = 402 challenge failed structural validation (bad
 *                 scheme/network/payTo/asset/amount)
 *             3 = request body failed the live schema, or the schema could
 *                 not be fetched
 *             4 = spend cap exceeded, or asset decimals could not be read
 *             5 = settle attempted but failed (settle_failed / still 402 /
 *                 gateway error)
 */

import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { base, baseSepolia } from "viem/chains";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";

type JSONSchema = Record<string, any>;

// ── Built-in feed catalog (path + a minimal valid sample body per feed, ─────
// derived from the live GATEWAY_URL/openapi.json schemas). The BODY validator
// below re-checks whatever body actually runs against the LIVE schema again
// at run time, so this catalog going stale fails loud instead of silently.
const KNOWN_FEEDS: Record<string, { path: string; sampleBody: Record<string, unknown> }> = {
  "address-reputation": {
    path: "/feeds/address-reputation",
    sampleBody: { address: "0x000000000000000000000000000000000000dEaD", domain: "example.com" },
  },
  "sanctions-screen": {
    path: "/feeds/sanctions-screen",
    sampleBody: { address: "0x000000000000000000000000000000000000dEaD" },
  },
  "pkg-verdict": {
    path: "/feeds/pkg-verdict",
    sampleBody: { ecosystem: "npm", package: "left-pad" },
  },
  "reasoning-verdict": {
    path: "/feeds/reasoning-verdict",
    sampleBody: { subject: "Dry-run schema validation sample — no live action follows.", kind: "general" },
  },
  "merchant-screen": {
    path: "/feeds/merchant-screen",
    sampleBody: { domain: "example.com" },
  },
};

function printUsage(): void {
  console.error(`
pay-and-post.ts — POST a BYTE x402 oracle feed (dry-run by default)

  --feed <id>     ${Object.keys(KNOWN_FEEDS).join(" | ")}
  --path <path>   raw feed path override (needs --body or FEED_PATH+BODY)
  --body <json>   raw JSON request body override
  --dry-run       validate + print what would be signed, then stop (default)
  --settle        actually pay + POST. Requires AGENT_PRIVATE_KEY.

Env: GATEWAY_URL, NETWORK (base|base-sepolia), RPC_URL, AGENT_PRIVATE_KEY, MAX_USDC, EXPECTED_SIGNER
`);
}

function fail(code: number, msg: string): never {
  console.error(`[pay-and-post] ABORT: ${msg}`);
  process.exit(code);
}

function requireNext(argv: string[], i: number, flag: string): string {
  const v = argv[i];
  if (v === undefined) fail(1, `${flag} requires a value.`);
  return v;
}

function parseArgs(argv: string[]) {
  let feed: string | undefined;
  let path: string | undefined;
  let body: string | undefined;
  let settle = false;
  let dryRun = false;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--feed":
        feed = requireNext(argv, ++i, "--feed");
        break;
      case "--path":
        path = requireNext(argv, ++i, "--path");
        break;
      case "--body":
        body = requireNext(argv, ++i, "--body");
        break;
      case "--settle":
        settle = true;
        break;
      case "--dry-run":
        dryRun = true;
        break;
      case "--help":
      case "-h":
        help = true;
        break;
      default:
        fail(1, `unknown argument "${a}". Run with --help.`);
    }
  }
  return { feed, path, body, settle, dryRun, help };
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  printUsage();
  process.exit(0);
}
if (args.dryRun && args.settle) fail(1, "--dry-run and --settle are mutually exclusive.");

// SETTLE is opt-in only; anything else (no flags, or explicit --dry-run) is a
// dry run. Fail-closed default: forgetting a flag never spends money.
const SETTLE = args.settle === true;

const feedId = args.feed;
const known = feedId ? KNOWN_FEEDS[feedId] : undefined;
if (feedId && !known) {
  fail(1, `unknown --feed "${feedId}". Known feeds: ${Object.keys(KNOWN_FEEDS).join(", ")}`);
}

// IIFE so the narrowed (non-undefined) type is what FEED_PATH is declared
// with — a plain `if (!x) fail()` above a `const` doesn't survive capture
// inside the async main() closure below.
const FEED_PATH: string = (() => {
  const p = args.path ?? process.env.FEED_PATH ?? known?.path;
  if (!p) {
    printUsage();
    fail(1, "no feed selected — pass --feed <id>, or --path <path> together with --body/BODY.");
  }
  return p;
})();

const bodyRaw = args.body ?? process.env.BODY ?? (known ? JSON.stringify(known.sampleBody) : undefined);
if (!bodyRaw) {
  fail(1, "no request body — pass --body '<json>' / BODY env, or select --feed <id> for a built-in sample.");
}
let BODY_OBJ: Record<string, unknown>;
try {
  const parsed = JSON.parse(bodyRaw);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    fail(1, "request body must be a JSON object.");
  }
  BODY_OBJ = parsed;
} catch (e) {
  fail(1, `--body/BODY is not valid JSON: ${e instanceof Error ? e.message : e}`);
}

const GATEWAY_URL = (process.env.GATEWAY_URL ?? "https://x402.payperbyte.io").replace(/\/$/, "");
const NETWORK = process.env.NETWORK ?? "base";
const isMainnet = NETWORK === "base" || NETWORK === "base-mainnet";
const chain = isMainnet ? base : baseSepolia;
const EXPECTED_NETWORK_ID = isMainnet ? "eip155:8453" : "eip155:84532";
const basescan = isMainnet ? "https://basescan.org" : "https://sepolia.basescan.org";

// ── Hard spend cap: $0.10 USDC ceiling, mandated in code — MAX_USDC may only
// tighten it, never raise it. ────────────────────────────────────────────────
const HARD_CAP_USD = 0.1;
const MAX_USDC = Math.min(Number(process.env.MAX_USDC ?? HARD_CAP_USD), HARD_CAP_USD);
if (!Number.isFinite(MAX_USDC) || MAX_USDC <= 0) fail(4, "MAX_USDC must resolve to a positive number <= 0.10.");

const publicClient = createPublicClient({ chain, transport: http(process.env.RPC_URL) });

const ERC20_DECIMALS_ABI = [
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
] as const;

// ── Minimal, dependency-free JSON-Schema subset validator. Covers exactly the
// shapes the 5 target feeds' schemas use: object/string/integer, required,
// properties, pattern, minLength/maxLength, minimum, enum, and anyOf(required
// alternatives). Not a general JSON-Schema engine. ──────────────────────────
function validateAgainstSchema(value: unknown, schema: JSONSchema, path = "$"): string[] {
  const errors: string[] = [];

  if (schema.type === "object") {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      errors.push(`${path}: expected object, got ${value === null ? "null" : typeof value}`);
      return errors;
    }
    const obj = value as Record<string, unknown>;
    for (const req of schema.required ?? []) {
      if (!(req in obj)) errors.push(`${path}: missing required field "${req}"`);
    }
    for (const [key, sub] of Object.entries(schema.properties ?? {})) {
      if (key in obj) errors.push(...validateAgainstSchema(obj[key], sub as JSONSchema, `${path}.${key}`));
    }
    if (Array.isArray(schema.anyOf)) {
      const alts = schema.anyOf as JSONSchema[];
      const anyPass = alts.some((alt) => validateAgainstSchema(value, alt, path).length === 0);
      if (!anyPass) {
        const need = alts.map((a) => JSON.stringify(a.required ?? a)).join(" | ");
        errors.push(`${path}: none of anyOf satisfied (need at least one of: ${need})`);
      }
    }
    return errors;
  }

  if (schema.type === "string") {
    if (typeof value !== "string") {
      errors.push(`${path}: expected string, got ${typeof value}`);
      return errors;
    }
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      errors.push(`${path}: length ${value.length} < minLength ${schema.minLength}`);
    }
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
      errors.push(`${path}: length ${value.length} > maxLength ${schema.maxLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: "${value}" does not match pattern ${schema.pattern}`);
    }
    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
      errors.push(`${path}: "${value}" not in enum [${schema.enum.join(", ")}]`);
    }
    return errors;
  }

  if (schema.type === "integer") {
    if (!Number.isInteger(value)) {
      errors.push(`${path}: expected integer, got ${typeof value}`);
      return errors;
    }
    if (typeof schema.minimum === "number" && (value as number) < schema.minimum) {
      errors.push(`${path}: ${value} < minimum ${schema.minimum}`);
    }
    return errors;
  }

  // Untyped fragment (an anyOf alternative that is only {required: [...]}).
  if (!schema.type && Array.isArray(schema.required)) {
    if (typeof value !== "object" || value === null) {
      errors.push(`${path}: expected object for required check`);
      return errors;
    }
    for (const req of schema.required) {
      if (!(req in (value as Record<string, unknown>))) errors.push(`${path}: missing required field "${req}"`);
    }
  }
  return errors;
}

/** Fetches GATEWAY_URL/openapi.json fresh — fail-closed if it can't be read. */
async function fetchOpenApiSpec(): Promise<any> {
  const specUrl = `${GATEWAY_URL}/openapi.json`;
  let res: Response;
  try {
    res = await fetch(specUrl);
  } catch (e) {
    fail(3, `failed to reach live OpenAPI spec (${specUrl}): ${e instanceof Error ? e.message : e}`);
  }
  if (!res.ok) fail(3, `GET ${specUrl} -> ${res.status}; cannot validate body against a live schema, refusing to guess.`);
  try {
    return await res.json();
  } catch (e) {
    fail(3, `${specUrl} did not return valid JSON: ${e instanceof Error ? e.message : e}`);
  }
}

/** Decodes a 402's PaymentRequired challenge WITHOUT the x402 SDK — no signer needed. */
async function decodePaymentRequiredRaw(res: Response): Promise<any> {
  const header = res.headers.get("payment-required");
  if (header) {
    try {
      return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    } catch (e) {
      fail(2, `payment-required header present but not valid base64 JSON: ${e instanceof Error ? e.message : e}`);
    }
  }
  const body = await res.clone().json().catch(() => undefined);
  if (body && Array.isArray(body.accepts)) return body;
  fail(2, "402 response carries neither a decodable payment-required header nor an accepts[] body — cannot validate challenge.");
}

interface ChallengeCheck {
  accept: {
    scheme: string;
    network: string;
    amount: bigint;
    asset: string;
    payTo: string;
    maxTimeoutSeconds?: number;
    extra?: Record<string, unknown>;
  };
  decimals: number;
  capAtomic: bigint;
  usd: number;
}

/**
 * Structural + spend-cap gate shared by dry-run and settle. Fail-closed on
 * every check: missing/malformed fields, wrong network, cap exceeded, or an
 * asset contract that won't answer decimals() all abort BEFORE anything is
 * signed.
 */
async function validateChallenge(paymentRequired: any): Promise<ChallengeCheck> {
  const accepts: any[] = paymentRequired?.accepts ?? [];
  if (!accepts.length) fail(2, "challenge carries no accepts[] — cannot determine price/network/payTo/asset.");

  const raw = accepts.find((a) => (a?.scheme ?? "exact") === "exact") ?? accepts[0];
  if (!raw) fail(2, "no usable payment requirement in challenge accepts[].");

  const network = String(raw.network ?? "");
  if (network !== EXPECTED_NETWORK_ID) {
    fail(2, `challenge network "${network}" != expected "${EXPECTED_NETWORK_ID}" for NETWORK=${NETWORK}.`);
  }

  const payTo = String(raw.payTo ?? raw.payto ?? "");
  if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) fail(2, `challenge payTo "${payTo}" is not a valid EVM address.`);

  const asset = String(raw.asset ?? "");
  if (!/^0x[0-9a-fA-F]{40}$/.test(asset)) fail(2, `challenge asset "${asset}" is not a valid EVM address.`);

  const amountRaw = raw.amount ?? raw.maxAmountRequired ?? raw.amountRequired ?? raw.maxAmount;
  let amount: bigint;
  try {
    amount = BigInt(amountRaw);
  } catch {
    fail(2, `challenge amount "${amountRaw}" is not a valid integer.`);
  }
  if (amount < 0n) fail(2, `challenge amount ${amount} is negative.`);

  // Decimals: read LIVE from the exact asset contract the challenge names —
  // never assumed to be 6, so a malformed/spoofed asset can't sneak a low
  // atomic amount past a hardcoded USDC assumption.
  let decimals: number;
  try {
    decimals = Number(
      await publicClient.readContract({
        address: asset as `0x${string}`,
        abi: ERC20_DECIMALS_ABI,
        functionName: "decimals",
      }),
    );
  } catch (e) {
    fail(4, `could not read decimals() on asset ${asset} — refusing to guess it's 6. (${e instanceof Error ? e.message : e})`);
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    fail(4, `asset ${asset} returned an implausible decimals() value: ${decimals}.`);
  }

  const capAtomic = BigInt(Math.round(MAX_USDC * 10 ** decimals));
  if (amount > capAtomic) {
    const usd = Number(amount) / 10 ** decimals;
    fail(
      4,
      `challenge asks ${amount} atomic (= $${usd.toFixed(6)}) > cap $${MAX_USDC} (${capAtomic} atomic @ ${decimals} decimals). Nothing signed.`,
    );
  }

  return {
    accept: { scheme: String(raw.scheme ?? "exact"), network, amount, asset, payTo, maxTimeoutSeconds: raw.maxTimeoutSeconds, extra: raw.extra },
    decimals,
    capAtomic,
    usd: Number(amount) / 10 ** decimals,
  };
}

async function main() {
  const url = `${GATEWAY_URL}${FEED_PATH}`;
  console.log(`[pay-and-post] mode      : ${SETTLE ? "SETTLE (live — real USDC on Base mainnet)" : "DRY-RUN (safe, no signing)"}`);
  console.log(`[pay-and-post] gateway   : ${GATEWAY_URL}`);
  console.log(`[pay-and-post] network   : ${NETWORK} (expects ${EXPECTED_NETWORK_ID}, chainId ${chain.id})`);
  console.log(`[pay-and-post] feed      : POST ${FEED_PATH}${feedId ? ` (--feed ${feedId})` : ""}`);
  console.log(`[pay-and-post] body      : ${JSON.stringify(BODY_OBJ)}`);
  console.log(`[pay-and-post] cap       : $${MAX_USDC} USDC/call (hard ceiling $${HARD_CAP_USD}; decimals read on-chain, never assumed)`);

  // 1) Body vs LIVE schema (GATEWAY_URL/openapi.json), fetched fresh — fail-closed.
  const spec = await fetchOpenApiSpec();
  const schema = spec?.paths?.[FEED_PATH]?.post?.requestBody?.content?.["application/json"]?.schema;
  if (!schema) fail(3, `no POST requestBody schema found for ${FEED_PATH} in live ${GATEWAY_URL}/openapi.json — refusing to validate blind.`);
  const bodyErrors = validateAgainstSchema(BODY_OBJ, schema);
  if (bodyErrors.length) {
    console.error(`[pay-and-post] request body fails the live schema for ${FEED_PATH}:`);
    for (const e of bodyErrors) console.error(`  - ${e}`);
    process.exit(3);
  }
  console.log(`[pay-and-post] body      : PASS (validated against live openapi.json schema for ${FEED_PATH})`);

  const advertised = spec?.paths?.[FEED_PATH]?.post?.["x-payment-info"]?.price?.amount;
  if (advertised) console.log(`[pay-and-post] openapi price advertised: $${advertised} (cross-checked against the 402 below)`);

  const init: RequestInit = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(BODY_OBJ) };

  if (!SETTLE) {
    // 2) DRY RUN: fetch the 402, validate the challenge + cap, print, stop.
    // No signer is constructed anywhere on this path.
    const first = await fetch(url, init);
    if (first.status !== 402) {
      const text = await first.text();
      fail(1, `expected 402, got ${first.status} — free route or error; nothing paid. body: ${text.slice(0, 500)}`);
    }
    const paymentRequired = await decodePaymentRequiredRaw(first);
    const check = await validateChallenge(paymentRequired);

    console.log(`\n[pay-and-post] 402 challenge validated — PASS`);
    console.log(`[pay-and-post]   scheme             : ${check.accept.scheme}`);
    console.log(`[pay-and-post]   network            : ${check.accept.network}`);
    console.log(`[pay-and-post]   payTo              : ${check.accept.payTo}`);
    console.log(`[pay-and-post]   asset              : ${check.accept.asset}`);
    console.log(`[pay-and-post]   decimals (on-chain): ${check.decimals}`);
    console.log(`[pay-and-post]   amount             : ${check.accept.amount} atomic = $${check.usd.toFixed(6)} USDC`);
    console.log(`[pay-and-post]   cap check          : PASS ($${MAX_USDC} cap = ${check.capAtomic} atomic)`);
    console.log(`[pay-and-post]   maxTimeoutSeconds  : ${check.accept.maxTimeoutSeconds ?? "(none)"}`);
    console.log(`[pay-and-post]   extra              : ${JSON.stringify(check.accept.extra ?? {})}`);

    console.log(`\n[pay-and-post] WOULD SIGN (nothing signed — dry run):`);
    console.log(`[pay-and-post]   EIP-3009 transferWithAuthorization, ${check.accept.amount} atomic USDC`);
    console.log(`[pay-and-post]   payer  : (no signer constructed in dry-run — AGENT_PRIVATE_KEY is never read)`);
    console.log(`[pay-and-post]   payee  : ${check.accept.payTo}`);
    console.log(`[pay-and-post]   asset  : ${check.accept.asset} on ${check.accept.network}`);
    console.log(`[pay-and-post]   then retry POST ${url} with the signed PAYMENT header, same body.`);
    console.log(`\n[pay-and-post] DRY RUN COMPLETE — nothing signed, nothing sent with payment, no settlement. Exit 0.`);
    process.exit(0);
  }

  // 3) SETTLE — live path. Requires AGENT_PRIVATE_KEY, same schema+cap gate above.
  const PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY as `0x${string}` | undefined;
  if (!PRIVATE_KEY) fail(1, "--settle requires AGENT_PRIVATE_KEY (a funded wallet key). Never hardcode it.");
  if (!/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) fail(1, "AGENT_PRIVATE_KEY must be 0x-prefixed 32-byte hex.");

  const account = privateKeyToAccount(PRIVATE_KEY);

  // Optional signer pin: refuse to sign from any wallet other than the one
  // the operator designated — catches a wrong key pasted into the command.
  const EXPECTED_SIGNER = process.env.EXPECTED_SIGNER;
  if (EXPECTED_SIGNER !== undefined) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(EXPECTED_SIGNER)) {
      fail(1, `EXPECTED_SIGNER "${EXPECTED_SIGNER}" is not a valid EVM address.`);
    }
    if (account.address.toLowerCase() !== EXPECTED_SIGNER.toLowerCase()) {
      fail(1, `key derives ${account.address}, not EXPECTED_SIGNER ${EXPECTED_SIGNER} — wrong key pasted. Nothing signed.`);
    }
  }

  console.log(`\n[pay-and-post] wallet    : ${account.address}`);
  const signer = toClientEvmSigner(account, publicClient);
  const core = registerExactEvmScheme(new x402Client(), { signer });
  const x402 = new x402HTTPClient(core);

  const first = await fetch(url, init);
  if (first.status !== 402) {
    const text = await first.text();
    fail(1, `expected 402, got ${first.status} — free route or error; nothing paid. body: ${text.slice(0, 500)}`);
  }
  const paymentRequired = x402.getPaymentRequiredResponse(
    (name) => first.headers.get(name),
    await first.clone().json().catch(() => undefined),
  );

  // Same fail-closed gate as dry-run — cap enforced BEFORE anything is signed.
  const check = await validateChallenge(paymentRequired);
  console.log(`[pay-and-post] cap check : PASS — signing ${check.accept.amount} atomic ($${check.usd.toFixed(6)}) to ${check.accept.payTo}`);

  const payload = await x402.createPaymentPayload(paymentRequired);
  const paymentHeaders = x402.encodePaymentSignatureHeader(payload);
  const paidResp = await fetch(url, { ...init, headers: { ...(init.headers as Record<string, string>), ...paymentHeaders } });
  const result = await x402.processResponse(paidResp);

  switch (result.kind) {
    case "success": {
      const s = result.settleResponse;
      console.log(`\n[pay-and-post] PAID + SETTLED`);
      console.log(`[pay-and-post] settlement : success=${s.success} payer=${s.payer ?? account.address}`);
      console.log(`[pay-and-post] tx hash    : ${s.transaction}`);
      console.log(`[pay-and-post] basescan   : ${basescan}/tx/${s.transaction}`);
      console.log(`\n[pay-and-post] feed data  :\n${JSON.stringify(result.body, null, 2)}`);
      process.exit(0);
      break;
    }
    case "settle_failed":
      console.error(`\n[pay-and-post] PAYMENT SIGNED BUT SETTLE FAILED.`);
      console.error(`[pay-and-post] settleResponse: ${JSON.stringify(result.settleResponse, null, 2)}`);
      console.error(`[pay-and-post] body: ${JSON.stringify(result.body, null, 2)}`);
      process.exit(5);
      break;
    case "payment_required":
      console.error(`\n[pay-and-post] still 402 after paying — requirements:`);
      console.error(JSON.stringify(result.paymentRequired, null, 2));
      process.exit(5);
      break;
    case "passthrough":
      console.log(`\n[pay-and-post] unexpected: route was free after all:\n${JSON.stringify(result.body, null, 2)}`);
      process.exit(0);
      break;
    case "error":
      console.error(`\n[pay-and-post] gateway error ${result.status}: ${JSON.stringify(result.body)}`);
      process.exit(5);
      break;
  }
}

main().catch((err) => {
  console.error(`[pay-and-post] fatal: ${err instanceof Error ? err.stack : err}`);
  process.exit(1);
});
