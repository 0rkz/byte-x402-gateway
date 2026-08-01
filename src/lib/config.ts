import dotenv from "dotenv";
dotenv.config();

/**
 * Gateway configuration loaded from environment variables.
 * All values have sensible defaults for local development on Arbitrum Sepolia.
 */
export const config = {
  /** HTTP server port */
  port: parseInt(process.env.PORT || "3402", 10),
  /** Wallet address that receives x402 payments (USDC) */
  payTo: process.env.PAY_TO_ADDRESS || "0x07B8C1D531958A3193eA527aea52A9f26bcfE91B",
  /**
   * x402 facilitator URL for payment verification.
   * Default switched from Coinbase's `facilitator.x402.org` to our self-hosted
   * facilitator because Coinbase's primarily supports base-sepolia, Solana
   * Devnet, Stellar Testnet, and Aptos Testnet — NOT Arbitrum Sepolia.
   * Override via env when running against a different facilitator.
   */
  facilitatorUrl: process.env.FACILITATOR_URL || "http://127.0.0.1:3403",
  /**
   * Facilitator request-auth mode. "" (default) = no auth headers — xpay's
   * self-hosted facilitator needs none, so the default path is unchanged.
   * "cdp" = attach Coinbase CDP request-auth (via @coinbase/x402, which reads
   * CDP_API_KEY_ID / CDP_API_KEY_SECRET from the env — keep those in the
   * gitignored .env.attestation, NOT the tracked deploy env). Flip this to "cdp"
   * together with FACILITATOR_URL to unblock §3 CDP/Bazaar indexing.
   */
  facilitatorAuth: (process.env.FACILITATOR_AUTH || "").toLowerCase(),
  /** CAIP-2 network identifier (default: Arbitrum Sepolia) */
  network: (process.env.NETWORK || "eip155:421614") as `${string}:${string}`,
  /**
   * One-off pay-per-call rate, in atomic USDC base units per KB
   * (6-decimal USDC). Default "5000" = $0.005 / KB.
   *
   * Per-feed prices are computed as
   *   priceAtomic = max(priceFloorAtomic, ceil(expectedSizeBytes/1024 * pricePerKBAtomic))
   * so larger payloads cost proportionally more. Matches the per-byte
   * branding ("BYTE Library") and sits at a ~67% premium over the
   * publisher's subscription rate ($0.003/KB), which signals subscribe-
   * for-volume as the cheaper path while keeping one-off accessible.
   *
   * (We construct PaymentOption.price as an explicit AssetAmount object —
   * NOT the "$0.001" dollar-string syntax — because dollar-strings require
   * the SDK's default-asset registry which doesn't have Arb-Sepolia mapped.)
   */
  pricePerKBAtomic: process.env.PRICE_PER_KB_ATOMIC || "5000",
  /** Minimum price per request — tiny-payload feeds floor here. */
  priceFloorAtomic: process.env.PRICE_FLOOR_ATOMIC || "1000",
  /**
   * USDC contract address on the configured chain. Must implement EIP-3009
   * `transferWithAuthorization` for the "exact" scheme to settle.
   * v0.6 §1 redeploy (2026-05-20): production MockUSDC3009 on Arbitrum Sepolia.
   */
  usdcAddress: (process.env.USDC_ADDRESS || "0x1c16659aeb3aE28467E90348fAAB8874a0D3A4d3") as `0x${string}`,
  /** EIP-712 domain for the USDC contract — must match Centre USDC + MockUSDC3009. */
  usdcDomainName: process.env.USDC_DOMAIN_NAME || "USD Coin",
  usdcDomainVersion: process.env.USDC_DOMAIN_VERSION || "2",
  /** Solana wallet address (base58 public key) for receiving x402 payments */
  solanaPayTo: process.env.SOLANA_PAY_TO || "",
  /** CAIP-2 Solana network identifier (default: Solana mainnet) */
  solanaNetwork: (process.env.SOLANA_NETWORK || "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp") as `${string}:${string}`,
  /** Data source cache TTL in milliseconds (env value is in seconds) */
  cacheTtl: parseInt(process.env.CACHE_TTL || "60", 10) * 1000,
  /** Optional CoinGecko API key for higher rate limits */
  coinGeckoApiKey: process.env.COINGECKO_API_KEY || "",
  /** evidence-pack oracle URL — Tier 1 bespoke proxy. */
  evidencePackUrl: process.env.EVIDENCE_PACK_URL || "https://evidence-pack.payperbyte.io",
  /** usc-statute oracle URL — Tier 1 bespoke proxy. */
  uscStatuteUrl: process.env.USC_STATUTE_URL || "https://usc-statute.payperbyte.io",
  /**
   * address-reputation oracle URL — the agentic-payments go/no-go verdict
   * (FEED_ROADMAP #1). Defaults to the local loopback bind: the feed runs on
   * the same host (byte-address-reputation.service, port 8088) and is NOT
   * exposed via cloudflared — this paywalled gateway route is its only public
   * surface, by design.
   */
  addressReputationUrl: process.env.ADDRESS_REPUTATION_URL || "http://127.0.0.1:8088",
  /**
   * pkg-verdict oracle URL — supply-chain install gate (FEED_ROADMAP).
   * Runs on the same host (byte-pkg-verdict.service, port 8091); NOT exposed
   * via cloudflared — this paywalled gateway route is its only public surface.
   */
  pkgVerdictUrl: process.env.PKG_VERDICT_URL || "http://127.0.0.1:8091",
  /**
   * sanctions-screen oracle URL — OFAC SDN + Consolidated screening.
   * Runs on the same host (byte-sanctions-screen.service, port 8092); NOT
   * exposed via cloudflared — this paywalled gateway route is its only public
   * surface.
   */
  sanctionsScreenUrl: process.env.SANCTIONS_SCREEN_URL || "http://127.0.0.1:8092",
  /**
   * merchant-screen oracle URL — pre-settlement merchant/storefront screen
   * (responds to the coinbase/x402 #225 fact-attestation ask). Runs on the
   * same host (byte-merchant-screen.service, port 8098); NOT exposed via
   * cloudflared — this paywalled gateway route is its only public surface.
   */
  merchantScreenUrl: process.env.MERCHANT_SCREEN_URL || "http://127.0.0.1:8098",
  /**
   * liquidation-stream oracle URL — Hawkes cascade-risk regime oracle.
   * Runs on the same host (byte-liquidation-stream-api.service, port 8089);
   * NOT exposed via cloudflared — this paywalled gateway route is its only
   * public surface.
   */
  liquidationStreamUrl: process.env.LIQUIDATION_STREAM_URL || "http://127.0.0.1:8089",
  /**
   * positioning-snapshot oracle URL — cross-venue perp positioning snapshot.
   * Runs on the same host (byte-positioning-snapshot-api.service, port 8090);
   * NOT exposed via cloudflared — this paywalled gateway route is its only
   * public surface.
   */
  positioningSnapshotUrl: process.env.POSITIONING_SNAPSHOT_URL || "http://127.0.0.1:8090",
  /**
   * token-safety oracle URL — signed honeypot/rug/mint go/no-go on a token
   * (completes the safety triad with address-reputation + pkg-verdict). Runs on
   * the same host (byte-token-safety.service, port 8093); NOT exposed via
   * cloudflared — this paywalled gateway route is its only public surface.
   */
  tokenSafetyUrl: process.env.TOKEN_SAFETY_URL || "http://127.0.0.1:8093",
  /**
   * reasoning-verdict oracle URL — local-LLM verify-before-act risk verdict
   * (GPU-backed). Runs on the same host (byte-reasoning-verdict.service, port
   * 8094, Ollama on 11434); NOT exposed via cloudflared — this paywalled gateway
   * route is its only public surface. The verdict is advisory; the embedded
   * EIP-712 receipt proves provenance/integrity, not correctness.
   */
  reasoningVerdictUrl: process.env.REASONING_VERDICT_URL || "http://127.0.0.1:8094",
  /**
   * runtime-eol GATE URL — deterministic signed EOL verdict for a {product,
   * version} (the decision tier of the runtime-eol broadcast feed). Runs on the
   * same host (byte-runtime-eol-gate.service, port 8095); NOT exposed via
   * cloudflared — the paywalled POST /feeds/runtime-eol route is its only public
   * surface. GET /feeds/runtime-eol still serves the publisher broadcast.
   */
  runtimeEolGateUrl: process.env.RUNTIME_EOL_GATE_URL || "http://127.0.0.1:8095",
  /**
   * threat-intel GATE URL — signed CISA-KEV exploit-exposure verdict ("are any of
   * MY components actively exploited?"). The decision tier of the threat-intel
   * digest feed. Runs on the same host (byte-threat-intel-gate.service, port 8096);
   * NOT exposed via cloudflared — the paywalled POST /feeds/threat-intel is its only
   * public surface. GET /feeds/threat-intel still serves the publisher digest.
   */
  threatIntelGateUrl: process.env.THREAT_INTEL_GATE_URL || "http://127.0.0.1:8096",
  // (Removed `byteIndexerUrl` 2026-05-25 — was dead code; the actual data
  // path uses DISCOVERY_API_URL read in feeds/generic.ts, defaulting to
  // https://api.payperbyte.io. The historical BYTE_INDEXER_URL env was a
  // misleading no-op.)
  /**
   * weather live-query URL — P1 fix (2026-07-28, direction (a)). GET
   * /feeds/weather previously served ONLY the discovery-api broadcast
   * archive (feeds/generic.ts), which goes stale/null whenever
   * byte-weather.service prunes to zero solvent subscribers and skips its
   * on-chain broadcast (broadcast_helper.publish_broadcast never archives a
   * 0-subscriber cycle) — confirmed root cause of the 2026-07-28 paid-GET
   * `data: null` incident (weather, earthquakes, runtime-eol GET all hit
   * this; threat-intel did not, because its publisher still had solvent
   * subscribers — this is per-publisher, not broadcast-class-wide).
   * When set, fetchFeedPayload() (feeds/generic.ts) tries this endpoint
   * FIRST — it serves the feed service's current computed payload
   * independent of subscriber economics — and falls back to the broadcast
   * archive only if unreachable. Runs on the same host
   * (byte-weather-live.service, port 8101 — moved off the originally-picked
   * 8097 after M2's port audit found it contested by
   * data-feeds/market-regime/server.py's own default; 8101 confirmed clean
   * against every PORT default in data-feeds/ and every currently-listening
   * socket, NOT installed by default — see
   * data-feeds/weather/byte-weather-live.service); NOT exposed via
   * cloudflared. Unset by default so this is opt-in per feed, not
   * class-wide surgery.
   */
  weatherLiveUrl: process.env.WEATHER_LIVE_URL || "",
  /** earthquakes live-query URL — same P1 fix, see weatherLiveUrl above.
   *  byte-earthquakes-live.service, port 8099 (NOT installed by default). */
  earthquakesLiveUrl: process.env.EARTHQUAKES_LIVE_URL || "",
  /**
   * runtime-eol live-query URL for the GET table path — same P1 fix, see
   * weatherLiveUrl above. Distinct from runtimeEolGateUrl (the POST
   * decision-tier oracle, already unaffected — it never reads the broadcast
   * archive). byte-runtime-eol-live.service, port 8100 (NOT installed by
   * default).
   */
  runtimeEolLiveUrl: process.env.RUNTIME_EOL_LIVE_URL || "",
};

/**
 * Per-feed live-query URL lookup for fetchFeedPayload() (feeds/generic.ts).
 * Deliberately a separate map, not a FeedMetadata field — these are internal
 * loopback addresses (like *GateUrl / *Url above) and must never leak into
 * the public /feeds or x402 manifest JSON. Empty/unset entries are treated
 * as "no live source configured" (pure fallback to the broadcast archive,
 * byte-for-byte the pre-fix behavior) — so wiring this up is opt-in and
 * per-feed-safe: a feed absent from this map (e.g. threat-intel, which is
 * not currently broken) is completely unaffected by the live-fetch path.
 */
export const FEED_LIVE_URL: Record<string, string> = {
  weather: config.weatherLiveUrl,
  earthquakes: config.earthquakesLiveUrl,
  "runtime-eol": config.runtimeEolLiveUrl,
};

/**
 * Per-feed broadcast-archive staleness tolerance, in seconds, for
 * fetchFeedPayload(). If the archived broadcast is the ONLY source available
 * (no live URL configured/reachable) and its age exceeds this, the gateway
 * fails closed (502, never charged) rather than serve a payload old enough
 * that "current" is no longer an honest description — this is the backstop
 * for when a live companion service is itself down. Roughly 3x each feed's
 * own updateFrequency (see feedRegistry below): generous enough to tolerate
 * a slow-but-not-frozen cycle, tight enough to catch genuine multi-day
 * staleness. Feeds absent from this map get NO staleness check — only the
 * universal null-data check in fetchFeedPayload applies — so this is
 * additive, not class-wide surgery. (All four broadcast-backed paid feeds
 * are now covered; threat-intel added 2026-07-29.)
 */
export const FEED_STALE_AFTER_S: Record<string, number> = {
  weather: 3 * 3600,        // 3h (updateFrequency 3600s)
  earthquakes: 3 * 900,     // 45min (updateFrequency 900s)
  // FD 2026-07-29: threat-intel was the ONLY archive-served paid feed with no
  // staleness gate anywhere — the last feed still exposed to the original P1
  // (frozen broadcaster ⇒ indefinitely-stale 200s). Margin verified live before
  // adding: archive cadence 3604-3614s, age 1983s vs this 10800s tolerance.
  "threat-intel": 3 * 3600, // 3h (updateFrequency 3600s)
  // FD 2026-07-28, L3: the catalog's updateFrequency for this feed said
  // "daily" (86400s), but data-feeds/runtime-eol/feed.py's actual broadcast
  // loop is INTERVAL = 21600 (6h) — the catalog string was corrected (see
  // feedRegistry below) and this tolerance now derives from the true
  // cadence, not the wrong one (was 3 days, 4x too lenient).
  "runtime-eol": 3 * 21600, // 18h (updateFrequency corrected to "21600s")
};

/**
 * Human label + status per CAIP-2 settlement network. Every discovery surface
 * (x402 manifest, agent card, OpenAPI) derives its network wording from here
 * via networkInfo() instead of hardcoding "Arbitrum Sepolia" — so repointing
 * NETWORK (e.g. the Base mainnet cutover) updates every surface atomically.
 *
 * NOTE: this is the SETTLEMENT rail only. The EIP-712 "BYTE Library"
 * attestation domain stays anchored on chainId 421614 (ATTESTATION_CHAIN_ID,
 * see attestation.ts) regardless of where payment settles — flipping it would
 * fork the consensus domain.
 */
const NETWORK_INFO: Record<string, { label: string; chain: string; status: "mainnet" | "testnet" }> = {
  "eip155:421614": { label: "Arbitrum Sepolia (testnet)", chain: "arbitrum", status: "testnet" },
  "eip155:42161": { label: "Arbitrum One", chain: "arbitrum", status: "mainnet" },
  "eip155:8453": { label: "Base", chain: "base", status: "mainnet" },
  "eip155:84532": { label: "Base Sepolia (testnet)", chain: "base", status: "testnet" },
};

/** Settlement-network display info for the configured NETWORK. Unknown CAIP-2
 *  ids fall back to the raw id + testnet status (never overclaim mainnet). */
export function networkInfo(): { label: string; chain: string; status: "mainnet" | "testnet" } {
  return NETWORK_INFO[config.network] ?? { label: config.network, chain: config.network, status: "testnet" };
}

/**
 * Universal disclaimer taxonomy. Every feed declares one.
 * The gateway emits `X-BYTE-Disclaimer-Category: <category>` on every response
 * so clients can render the right legal language without parsing the payload.
 *
 * Pending Ari Good legal review. The signed in-payload disclaimer-text
 * upgrade for existing 15 publishers lands as a batch op after he signs off
 * on final wording; the new Tier 1 publishers ship with in-payload signing
 * from day one. Header coverage is universal.
 */
export type DisclaimerCategory =
  | "financial"
  | "legal"
  | "medical"
  | "commerce"
  | "civic"
  | "scientific"
  | "general";

/** Metadata describing a single data feed exposed by the gateway. */
export interface FeedMetadata {
  /** Unique feed identifier used in URL paths */
  id: string;
  /** Human-readable feed name */
  name: string;
  /** What this feed provides */
  description: string;
  /** Human-readable price per request (e.g. "$0.022"), derived from expectedSizeBytes. */
  price: string;
  /** Atomic-USDC price per request (string for x402's AssetAmount). */
  priceAtomic: string;
  /** Expected payload size in bytes — drives the per-feed price. */
  expectedSizeBytes: number;
  /** Provenance basis — NOT a quality score. "eip712-attested" = on-chain
   *  EIP-712 PayloadAttestation publisher feed; "first-party" = bespoke upstream
   *  relay. (A real computed quality score lives in the indexer, not here.) */
  provenance: "eip712-attested" | "first-party";
  /** How often the underlying data refreshes */
  updateFrequency: string;
  /** HTTP endpoint path */
  endpoint: string;
  /**
   * Disclaimer category (universal disclaimer schema). The gateway
   * surfaces this on the `X-BYTE-Disclaimer-Category` response header AND in
   * the /feeds catalog metadata so buyers can preview liability framing
   * before purchase.
   */
  disclaimerCategory: DisclaimerCategory;
  /**
   * For feeds backed by the generic discovery-api proxy (i.e. served by a
   * BYTE Library publisher rather than a bespoke upstream fetcher), the
   * publisher's on-chain Arbitrum address. Undefined for bespoke feeds
   * (crypto-top100, defi-yields).
   */
  publisher?: `0x${string}`;
}

/** Canonical disclaimer text per category. Kept here for the gateway's
 *  /feeds metadata response so clients can render an unsigned preview before
 *  purchase. The in-payload signed disclaimer is emitted by the publisher
 *  itself (new Tier 1 feeds do this; existing 15 inherit via the gateway
 *  header until the post-Ari batch upgrade). */
export const DISCLAIMER_TEXT: Record<DisclaimerCategory, string> = {
  financial:
    "Not financial advice. For informational and educational purposes only. " +
    "Do not rely on this data for trading or investment decisions without independent verification.",
  legal:
    "Not legal advice. For informational and educational purposes only. " +
    "Consult a qualified attorney for legal questions in your jurisdiction.",
  medical:
    "Not medical advice. For informational and educational purposes only. " +
    "Consult a qualified healthcare provider for medical questions.",
  commerce:
    "For informational purposes. Settlement and merchant data reflects observed activity; " +
    "trust signals are advisory, not guarantees.",
  civic:
    "For informational purposes. Public-safety data is advisory; " +
    "consult official local authorities in active emergencies.",
  scientific:
    "For research and educational purposes. Data sourced from cited references; " +
    "consult primary sources for authoritative versions.",
  general:
    "For informational and educational purposes only. " +
    "No warranty of accuracy, completeness, or fitness for any purpose.",
};

/**
 * Compute the atomic-USDC price for a feed from its expected payload size.
 * Rule: max(floor, ceil(KB × pricePerKBAtomic)). Default rate $0.005/KB,
 * default floor $0.001 — tunable via PRICE_PER_KB_ATOMIC / PRICE_FLOOR_ATOMIC.
 */
export function computePriceAtomic(expectedSizeBytes: number): string {
  const perKB = BigInt(config.pricePerKBAtomic);
  const floor = BigInt(config.priceFloorAtomic);
  // ceil(bytes / 1024 * perKB) without floating point
  const computed = (BigInt(expectedSizeBytes) * perKB + 1023n) / 1024n;
  return (computed < floor ? floor : computed).toString();
}

/** Format an atomic-units string as "$x.xxx…" for human-readable display. */
function fmtUsdc(atomic: string): string {
  const n = Number(atomic) / 1_000_000;
  // 4 decimals under a cent, 2 above — keeps "$0.0015" readable but "$0.07" tidy.
  return `$${n.toFixed(n < 0.01 ? 4 : n < 1 ? 3 : 2)}`;
}

/**
 * Registry of all data feeds served by this gateway.
 *
 * `expectedSizeBytes` is measured from recent broadcasts (publisher feeds) or
 * estimated from the upstream API response (bespoke feeds). It drives the
 * per-feed price via computePriceAtomic. Update it when the payload schema
 * meaningfully changes.
 *
 * Note: byte-status was dropped on 2026-05-23 — it was a placeholder when the
 * gateway only had three endpoints, and now that 12 real publisher-backed
 * feeds exist, agents should hit the indexer directly for protocol metrics
 * (free, no settlement layer).
 */
// Placeholder for new Tier 1 publishers — the founder fills these in after
// running register_oracles.py for the Tier 1 cohort. Until populated, leaving
// these as 0x0...0 makes the gateway proxy refuse to serve them (correct
// behavior — better than serving a wrong publisher's broadcasts).
const TIER1_PLACEHOLDER = "0x0000000000000000000000000000000000000000" as const;

/**
 * Value-based per-call price overrides (2026-06-17), keyed by feed id, in atomic
 * USDC (6 decimals). Replaces the per-byte-of-size formula for these feeds: a feed
 * is priced by what its data is worth, not how many bytes it returns. Feeds not
 * listed fall back to the per-KB formula; the decision oracles
 * (evidence-pack/address-reputation/pkg-verdict/sanctions-screen) keep their own
 * explicit price via customPricedFeed.
 */
// VALUE-TIERED schedule (2026-06-22 reprice): price signals exclusivity + data
// prowess, not payload size. Tiers, top→bottom:
//   T1 $0.05 — EXCLUSIVE verifiable decision oracles: signed ALLOW/WARN/BLOCK
//              verdicts that prevent irreversible loss; no competitor ships
//              verifiable (EIP-712) verdicts. (Also: the customPriced decision
//              oracles address-reputation/pkg-verdict/sanctions-screen/
//              reasoning-verdict, set in feedRegistry.)
//   T1 $0.05 — EXCLUSIVE first-party compounding indices (byte-scored research
//              nobody else publishes).
//   T2 $0.03 — first-party SIGNED market data (provenance + DQI) — above
//              commodity data-API pricing because it's first-party + verifiable.
//   T3 $0.02 — signed compliance/dev gates + LLM-curated.
//   T4 $0.01 — low-baseline / pre-launch.
//   T5 $0.003-0.005 — commodity public-data relays: deliberately cheap +
//              competitive (NOT exclusive — raw public bytes).
const PRICE_OVERRIDES: Record<string, string> = {
  // T1 — exclusive verifiable decision oracles
  "usc-statute": "50000",          // $0.05 — signed legal verdict
  "threat-intel": "50000",         // $0.05 — signed CISA-KEV exploit-exposure gate (decision-grade)
  // T1 — exclusive first-party compounding indices
  "agent-compute": "50000",        // $0.05
  "agent-memory": "50000",         // $0.05
  "agent-tools": "50000",          // $0.05
  // T2 — first-party SIGNED market data (provenance + DQI)
  "defi-yields": "30000",          // $0.03
  "liquidation-stream": "30000",   // $0.03
  "positioning-snapshot": "30000", // $0.03
  "stablecoin-rails": "30000",     // $0.03
  // T3 — signed compliance/dev gates + LLM-curated
  "runtime-eol": "20000",          // $0.02 — signed EOL compliance gate
  "code-pulse": "20000",           // $0.02 — release/upgrade-risk tracker
  "perp-funding": "20000",         // $0.02 (deprecation candidate — see FEED_ENHANCEMENT_ROADMAP)
  // T4 — low-baseline / pre-launch
  "news-feed": "10000",            // $0.01 — LLM-curated (competes w/ buyer's own LLM; keep modest)
  "x402-pulse": "10000",           // $0.01 — zero-baseline until live facilitator traffic
  // T5 — commodity public-data relays (cheap + competitive; not exclusive)
  "weather": "5000",               // $0.005
  "earthquakes": "3000",           // $0.003
  "space-weather": "3000",         // $0.003
};

export const feedRegistry: FeedMetadata[] = [
  // crypto-top100 delisted 2026-06-12 — commodity feed, cut from priced catalog.
  // crypto-top100 route + fetcher REMOVED 2026-06-14 (CoinGecko no-resale; it served data UNPAID).
  // defi-yields delisted 2026-07-03 (concentration cut)
  // ── BYTE Library publisher feeds (served via the generic discovery-api proxy)
  // Each entry's `publisher` is the on-chain Arbitrum address registered on
  // DataRegistry; the gateway proxies the latest BroadcastStreamed payload
  // for that publisher. `expectedSizeBytes` is sampled from recent broadcasts.
  indexerFeed("weather", "Weather (US, multi-city)", "NWS weather forecasts for 5 US cities (NYC, LA, Chicago, Houston, Miami)", "3600s", 4400, "0xa820763c023a929e83c59e4fd5a623e5a8efe941", "general"),
  indexerFeed("earthquakes", "Earthquakes", "USGS recent earthquakes worldwide (M2.5+)", "900s", 300, "0xa1a55406de233901257aec7b499a26f040ba3cfa", "general"),
  // space-weather, news-feed, code-pulse delisted 2026-07-03 (concentration cut)
  // updateFrequency corrected 2026-07-28 (FD L3): "daily" (86400s) did not
  // match data-feeds/runtime-eol/feed.py's actual broadcast loop, INTERVAL =
  // 21600 (6h). See FEED_STALE_AFTER_S above for the dependent tolerance fix.
  indexerFeed("runtime-eol", "Runtime EOL", "End-of-life dates and status for language runtimes, frameworks, OSes (endoflife.date)", "21600s", 14200, "0x17a67d0d18f9b93f064a23d2076074ea8802216f", "general"),
  // Copy fixed 2026-06-11 (FEED_ROADMAP integrity item): the feed relays public
  // CISA/NVD data — it does not produce first-party IOC detection. Don't overclaim.
  indexerFeed("threat-intel", "Security Advisories Digest", "Recent CVE highlights + CISA known-exploited-vulnerability entries, relayed from public sources (NVD, CISA KEV)", "3600s", 5300, "0xb90b00f891dc534a5b59c60170661b868f3c26de", "general"),
  // ── BYTE Library Tier 1 publisher feeds (Mainnet 50-feed plan, 2026-05-25)
  // The Tier 1 cohort ships 6 new items. Replace TIER1_PLACEHOLDER with the
  // on-chain publisher address from the registerPublisher tx. expectedSizeBytes
  // estimates per the launch-plan-review §8 size-class table; resample once
  // a representative payload is broadcast.
  // x402-pulse, stablecoin-rails, perp-funding, usc-statute delisted 2026-07-03 (concentration cut)
  // evidence-pack DELISTED 2026-07-28 (founder-approved, in-session): serves
  // off-description output (catalog says "retrieve from PayPerByte factual
  // feeds"; TASK A found it actually retrieves from Wikipedia) with an
  // undisclosed third-party egress path, and marked a temporally bogus
  // citation (2008 Sichuan earthquake) as "supporting" a "last 24h" claim.
  // Its route in index.ts is now a 410-Gone stub. NOT in this registry — no
  // payment gate — until the grounding-source/egress-disclosure gap is fixed.
  // address-reputation is decision-priced, not size-priced (a wrong ALLOW on a
  // drainer address = irreversible USDC loss) — same $0.10 tier as evidence-pack.
  customPricedFeed("address-reputation", "Address Reputation Oracle", "Agentic-payments go/no-go verdict: synchronous signed ALLOW/WARN/BLOCK for (domain, receiving address, amount, chain) BEFORE releasing USDC. ar-v1 ruleset over RDAP/TLS/DNS/Wayback domain signals + on-chain receiving-address signals + curated known-bad blocklist. The verdict carries an embedded EIP-712 PayloadAttestation — recompute keccak256(answer) and recover the signer before acting.", "on-demand", 2500, "commerce", "100000"),
  // pkg-verdict: decision-priced $0.10 — install-gate verdict, same tier as address-reputation.
  customPricedFeed("pkg-verdict", "Package Verdict Oracle", "Signed ALLOW/WARN/BLOCK on installing a package@version: OSV.dev malicious-corpus + typosquat distance + registry signals. Verify before you install.", "on-demand", 2500, "general", "100000"),
  // sanctions-screen: decision-priced $0.10 — compliance go/no-go, same tier as address-reputation.
  customPricedFeed("sanctions-screen", "Sanctions Screen Oracle", "Signed, version-pinned OFAC SDN + Consolidated screening on an address or name; every answer embeds the pinned list-state (date + sha256) it was judged against.", "on-demand", 2500, "legal", "100000"),
  // reasoning-verdict: GPU-backed local-LLM verify-before-act oracle. Compute-priced
  // $0.10 (decision-oracle tier) — an agent about to act on a message/payload/proposal
  // gets a signed ALLOW/WARN/BLOCK/ABSTAIN + reasons it verifies before acting. The
  // verdict is ADVISORY; the embedded EIP-712 receipt proves provenance, not correctness.
  customPricedFeed("reasoning-verdict", "Reasoning Verdict Oracle (local LLM)", "Verify-before-act risk oracle: POST an action context (message, payload, proposal, payee, tool-call) and get a signed ALLOW/WARN/BLOCK/ABSTAIN verdict + 0-100 safe-to-proceed score + reasons from a LOCAL model (no data egress). The verdict carries an embedded EIP-712 PayloadAttestation — recompute keccak256(answer) and recover the signer before acting. Advisory: the receipt proves provenance/integrity, not correctness.", "on-demand", 2200, "general", "100000"),
  // merchant-screen: decision-priced $0.10, same tier as address-reputation/
  // pkg-verdict/sanctions-screen/reasoning-verdict. Registered here 2026-07-28
  // per GATEWAY_INTEGRATION.md step (b); the upstream service
  // (byte-merchant-screen.service) is founder-gated on a provisioned
  // MERCHANT_SCREEN_PUB_KEY — see the deploy runbook for the required
  // pre-restart ordering (unit must show healthz ok:true BEFORE the gateway
  // is restarted onto this registry entry, else every /query is a signed-
  // refusal 503 by design — the service's own fail-closed contract).
  // TRUST-BOUNDARY sentence added 2026-08-01 (hardening plan §2.1). The payTo
  // composition gap is real: the verdict cryptographically commits to the payTo
  // (it is inside the keccak'd canonical bytes as answer.query.address), but
  // NOTHING ties that string to the address that actually receives settlement —
  // the caller supplies whatever address it wants screened and then settles
  // against whatever the merchant's own 402 says. The only cross-check
  // (payto_match) is against the merchant's /.well-known/x402 manifest at screen
  // time, is advisory, and costs zero score when it comes back None. Until ms-v2
  // closes that, it is DISCLOSED here. The casing caveat is load-bearing, not
  // pedantry: merchant-screen/resolvers.py normalize_address() lowercases the
  // address while real 402 challenges carry EIP-55 checksummed payTo, so the
  // naive `verdict.query.address === challenge.payTo` check a careful integrator
  // would write fails SILENTLY. Scope stays authenticity/provenance, never
  // correctness. NOTE: this one field fans out to /feeds, /openapi.json,
  // agent.json, .well-known and the GET payment-challenge description — edit it
  // here only. The POST 402 challenge uses the separate, founder-approved
  // PAYMENT_CHALLENGE_DESCRIPTION["merchant-screen"] in index.ts (not touched).
  customPricedFeed("merchant-screen", "Merchant Screen Oracle",
    "Pre-settlement merchant screen: signed ALLOW/WARN/BLOCK on a (domain, payTo, observed price) BEFORE an agent settles an x402 payment. ms-v1 ruleset over first-party signals measured at query time — RDAP domain age, live TLS handshake (cert age, issuer, SAN match), off-domain redirect probe, brand-similarity distance vs a committed known-brand corpus, and the merchant's own advertised x402 manifest price. Method disclosed per field; unmeasurable signals report unverified and only lower confidence. The verdict carries an embedded EIP-712 PayloadAttestation — recompute keccak256(answer) and recover the signer before acting. Trust boundary: the payTo and price are values you assert, not values we observe on your payment — the verdict is a point-in-time snapshot of the exact tuple you supplied, and it neither sees nor constrains the address you ultimately settle to. Before releasing funds compare answer.query against the 402 challenge you are about to pay (answer.query.address is lowercased — compare case-insensitively). The receipt proves provenance and integrity, not correctness. Every query is logged and retained: the domain, the payTo address and price you supplied, the verdict, and a summary of the signals behind it. Producing a verdict requires live outbound requests against the screened domain itself — the merchant may observe this traffic; screening is not covert.",
    "on-demand", 3200, "commerce", "100000"),
  // token-safety delisted 2026-06-12 — NOT in this registry (so it has no payment
  // gate). Its route in index.ts is a 410-Gone stub (fails closed, serves no data)
  // until the ts-v1 provider contract is finalized and it is re-added here WITH a gate.
  // liquidation-stream DELISTED 2026-07-28 (founder-approved, in-session): the
  // realized-liquidation collector has been dead since 2026-06-12 (no live
  // venue legs — see byte-liquidation-stream-api.service healthz
  // archive_days=[2026-06-09,2026-06-12]), so a paid query can only answer
  // INSUFFICIENT_DATA off a 7-week-stale archive. Its route in index.ts is now
  // a 410-Gone stub. NOT in this registry — no payment gate — until the
  // collector is restored with a live venue feed.
  // positioning-snapshot: per-KB priced on expectedSizeBytes=7480 (~$0.037) — market data.
  bespokeFeed("positioning-snapshot", "Positioning Snapshot Oracle", "Cross-venue perp positioning (funding + open interest) from Hyperliquid, dYdX v4, Aevo; raw fields, abstains honestly where a venue lacks data.", "on-demand", 7480, "financial"),
  // agent-compute, agent-memory, agent-tools (Agent-Infrastructure Index) delisted 2026-07-03 (concentration cut)
];

/** Build a bespoke (upstream-API-backed) feed entry. */
function bespokeFeed(
  id: string,
  name: string,
  description: string,
  updateFrequency: string,
  expectedSizeBytes: number,
  disclaimerCategory: DisclaimerCategory,
): FeedMetadata {
  const priceAtomic = PRICE_OVERRIDES[id] ?? computePriceAtomic(expectedSizeBytes);
  return {
    id, name, description, updateFrequency,
    provenance: "first-party",
    endpoint: `/feeds/${id}`,
    expectedSizeBytes,
    priceAtomic,
    price: fmtUsdc(priceAtomic),
    disclaimerCategory,
  };
}

/** Build a BYTE Library publisher-backed feed entry. */
function indexerFeed(
  id: string,
  name: string,
  description: string,
  updateFrequency: string,
  expectedSizeBytes: number,
  publisher: `0x${string}`,
  disclaimerCategory: DisclaimerCategory,
): FeedMetadata {
  const priceAtomic = PRICE_OVERRIDES[id] ?? computePriceAtomic(expectedSizeBytes);
  return {
    id, name, description, updateFrequency,
    provenance: "eip712-attested",
    endpoint: `/feeds/${id}`,
    expectedSizeBytes,
    priceAtomic,
    price: fmtUsdc(priceAtomic),
    publisher,
    disclaimerCategory,
  };
}

/**
 * Build a feed entry with a hardcoded atomic price (bypassing the per-KB
 * formula). Used by evidence-pack today; reusable for any future feed whose
 * cost is dominated by compute (LLM, retrieval, signing) rather than payload
 * size.
 */
function customPricedFeed(
  id: string,
  name: string,
  description: string,
  updateFrequency: string,
  expectedSizeBytes: number,
  disclaimerCategory: DisclaimerCategory,
  priceAtomicOverride: string,
): FeedMetadata {
  return {
    id, name, description, updateFrequency,
    provenance: "first-party",
    endpoint: `/feeds/${id}`,
    expectedSizeBytes,
    priceAtomic: priceAtomicOverride,
    price: fmtUsdc(priceAtomicOverride),
    disclaimerCategory,
  };
}
