import { config } from "../lib/config.js";

/**
 * Generic feed fetcher backed by the BYTE Library discovery-api.
 *
 * Every BYTE Library publisher broadcasts JSON payloads via
 * DataStream.broadcastStreamed; the discovery-api archives them and exposes
 * the most recent under /payloads/publisher/{address}. For the 12 feeds whose
 * data source IS a BYTE Library publisher (i.e. anything beyond
 * crypto-top100, defi-yields, byte-status which have their own bespoke
 * upstream fetchers), this generic handler proxies the latest broadcast.
 *
 * Returns the payload exactly as the publisher broadcast it — same hash, same
 * shape — so an x402 buyer gets the same bytes that on-chain subscribers
 * received. If the publisher has never broadcast (silent publisher, e.g.
 * pkg-facts at handover) the discovery-api returns {count:0, payloads:[]}
 * and we surface that as a 204-like "no data yet" payload rather than an
 * error, so agents can distinguish "publisher not yet active" from "feed
 * doesn't exist".
 */

const DISCOVERY_BASE =
  process.env.DISCOVERY_API_URL || "https://api.payperbyte.io";

interface DiscoveryPayloadRow {
  payload_hash: string;
  payload_length: number;
  subscriber_count?: number;
  tx_hash: string;
  archived_at: string;
  feed: string;
  payload?: unknown;
}

interface DiscoveryResponse {
  count: number;
  payloads: DiscoveryPayloadRow[];
}

interface GenericFeedPayload {
  feed: string;
  publisher: string;
  timestamp: string;
  // "byte-library-broadcast" = served from the discovery-api archive (the
  // on-chain-anchored path — recover the publisher's PayloadAttestation from
  // the BroadcastStreamed event at txHash). "live" = served directly from the
  // feed's live-query companion (P1 fix 2026-07-28) — no on-chain event this
  // cycle; payloadHash, when present, is the live service's own off-chain
  // EIP-712 PayloadAttestation over `data`, verifiable the same way the POST
  // oracles' embedded attestations are (see attestationReceiptBlock() in
  // index.ts, embedded.verify.oracle).
  source: "byte-library-broadcast" | "live";
  txHash?: string;
  payloadHash?: string;
  payloadBytes?: number;
  data: unknown;
  /**
   * ONLY set when source === "live": the EXACT response bytes the live-query
   * companion returned (its `{"answer":...,"attestation":...}` body),
   * unparsed. `data` above is a PARSED COPY of the same content — used for
   * validation only (staleness, attestation-presence) — and must NEVER be
   * the thing sent to a buyer for a live-sourced response. The route handler
   * (index.ts) MUST splice `rawDataBytes` verbatim into the outer envelope
   * and send via sendAttestedRaw, never JSON.stringify(data).
   *
   * FD 2026-07-28, BLOCKER 3: a parse -> re-stringify round trip can
   * silently change bytes (Python's json.dumps renders a float as "10.0";
   * after JSON.parse -> JSON.stringify in Node the same value renders as
   * "10") — verified against a real archived payload (9709 -> 9705 bytes).
   * That would break the `live` verify recipe's keccak256 recompute over
   * responseBody.data.answer, which — unlike the `broadcast` recipe — has no
   * on-chain fallback to fall back on for a live-sourced response.
   */
  rawDataBytes?: string;
}

const cache = new Map<string, { payload: GenericFeedPayload; fetchedAt: number }>();

export async function fetchLatestPublisherPayload(opts: {
  slug: string;
  publisher: string;
}): Promise<GenericFeedPayload> {
  const now = Date.now();
  const cached = cache.get(opts.publisher);
  if (cached && now - cached.fetchedAt < config.cacheTtl) {
    return cached.payload;
  }

  const url = `${DISCOVERY_BASE}/payloads/publisher/${opts.publisher}?limit=1`;
  const res = await fetch(url);
  if (!res.ok) {
    if (cached) return cached.payload;
    throw new Error(
      `discovery-api ${res.status} ${res.statusText} for publisher ${opts.publisher}`
    );
  }
  const body = (await res.json()) as DiscoveryResponse;

  if (!body.payloads?.length) {
    const empty: GenericFeedPayload = {
      feed: opts.slug,
      publisher: opts.publisher,
      timestamp: new Date().toISOString(),
      source: "byte-library-broadcast",
      data: null,
    };
    cache.set(opts.publisher, { payload: empty, fetchedAt: now });
    return empty;
  }

  const row = body.payloads[0]!;
  const out: GenericFeedPayload = {
    feed: opts.slug,
    publisher: opts.publisher,
    timestamp: row.archived_at,
    source: "byte-library-broadcast",
    txHash: row.tx_hash,
    payloadHash: row.payload_hash,
    payloadBytes: row.payload_length,
    data: row.payload ?? null,
  };
  cache.set(opts.publisher, { payload: out, fetchedAt: now });
  return out;
}

// ---------------------------------------------------------------------------
// Live-query path — P1 fix (2026-07-28, direction (a))
// ---------------------------------------------------------------------------
//
// Root cause (confirmed by reading broadcast_helper.py + the affected feed
// services): a publisher's feed.py computes fresh data every cycle, but
// publish_broadcast() returns early — WITHOUT calling _archive_payload — when
// there are zero solvent subscribers ("no-subs" / "all-insolvent"). The
// discovery-api archive fetchLatestPublisherPayload() reads from is only ever
// written on a successful on-chain broadcast, so a publisher that has been
// pruned to zero paying subscribers stops updating the archive even though
// the underlying data is fine. The 2026-07-28 sweep found this hit weather,
// earthquakes, and runtime-eol (GET) — each served `data: null` to a PAYING
// caller who was still charged, because fetchLatestPublisherPayload()
// resolves successfully (not throws) on an empty archive, so the route
// handler returned 200 and the x402 middleware never cancelled settlement.
// threat-intel (also broadcast-backed) was unaffected because its publisher
// still had solvent subscribers — this is per-publisher, not a broadcast-
// class-wide failure, so the fix below is opt-in per feed via FEED_LIVE_URL /
// FEED_STALE_AFTER_S (lib/config.ts), not a blanket behavior change.

const liveCache = new Map<string, { payload: GenericFeedPayload; fetchedAt: number }>();

interface LiveOracleResponse {
  answer?: { ts?: string; [k: string]: unknown };
  attestation?: { payloadHash?: string; [k: string]: unknown };
  note?: string;
  error?: string;
}

/**
 * Try the feed's live-query companion (data-feeds/<slug>/live.py — see its
 * docstring). Returns null on ANY failure (unreachable, non-2xx, timeout,
 * malformed body) so the caller can fall back to the broadcast archive
 * rather than fail the whole request over a single flaky source.
 *
 * Fetches as TEXT and keeps the raw bytes in `rawDataBytes` — `data` below is
 * a PARSED COPY for inspection only (staleness, presence checks), never for
 * transmission (BLOCKER 3, see GenericFeedPayload.rawDataBytes). The absent
 * `answer.ts` case is NOT defaulted to "now" (that used to defeat the
 * staleness gate below by construction) — an empty string fails
 * Date.parse(), which validationError() rejects.
 */
async function tryFetchLive(
  slug: string,
  publisher: string,
  liveUrl: string,
): Promise<GenericFeedPayload | null> {
  const now = Date.now();
  const cached = liveCache.get(liveUrl);
  if (cached && now - cached.fetchedAt < config.cacheTtl) {
    return cached.payload;
  }
  try {
    const res = await fetch(`${liveUrl}/latest`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const rawText = await res.text();
    let body: LiveOracleResponse;
    try {
      body = JSON.parse(rawText) as LiveOracleResponse;
    } catch {
      return null;
    }
    if (!body.answer || body.error) return null;
    const out: GenericFeedPayload = {
      feed: slug,
      publisher,
      timestamp: typeof body.answer.ts === "string" ? body.answer.ts : "",
      source: "live",
      payloadHash: body.attestation?.payloadHash,
      data: body,
      rawDataBytes: rawText,
    };
    liveCache.set(liveUrl, { payload: out, fetchedAt: now });
    return out;
  } catch {
    return null;
  }
}

// Reject a payload timestamped further ahead than this — a clock-skew /
// misbehaving-source guard (FD 2026-07-28, L1). Generous enough to tolerate
// ordinary clock drift between hosts, tight enough to catch a source dating
// its answer into the future to dodge the staleness check below.
const FUTURE_SKEW_TOLERANCE_S = 120;

/**
 * The single gate every candidate payload must pass before being served for
 * a paid request — applied IDENTICALLY regardless of source. Returns a
 * human-readable rejection reason, or null if the payload is usable.
 *
 * FD 2026-07-28, BLOCKER 1: fetchFeedPayload used to `return live` the
 * moment tryFetchLive produced ANYTHING shaped like an answer, before ever
 * reaching the archive path's null/staleness checks below — so a
 * well-formed-but-EMPTY live payload sailed straight through. Proven
 * concretely: weather's build_payload() legitimately returns
 * `{"locations":[]}` when NWS is fully unreachable (every per-city fetch
 * fails independently and the empty results just get filtered out) —
 * live.py would sign that, cache it for 300s, and the buyer would be charged
 * for zero forecasts. Emptiness itself is feed-specific (an empty
 * `quakes` array is a NORMAL non-degenerate state for earthquakes), so THAT
 * check now lives in each live.py, which refuses to sign/serve a genuinely
 * degenerate payload in the first place (see each live.py's docstring) —
 * this function only checks what's true for every feed: presence of data,
 * presence of a live payload's attestation, and freshness.
 */
function validationError(
  payload: GenericFeedPayload,
  opts: { slug: string; staleAfterS?: number },
): string | null {
  if (payload.data === null) {
    return `${opts.slug}: no data — refusing to serve null data for a paid request`;
  }
  if (payload.source === "live" && !payload.payloadHash) {
    return (
      `${opts.slug}: live response carries no attestation.payloadHash — ` +
      `refusing to serve an unsigned live payload for a paid request`
    );
  }
  const tsMs = Date.parse(payload.timestamp);
  if (!Number.isFinite(tsMs)) {
    return (
      `${opts.slug}: payload has no usable timestamp — refusing to serve for ` +
      `a paid request (cannot verify freshness)`
    );
  }
  const ageS = (Date.now() - tsMs) / 1000;
  if (ageS < -FUTURE_SKEW_TOLERANCE_S) {
    return (
      `${opts.slug}: payload timestamp is ${Math.round(-ageS)}s in the future ` +
      `(beyond ${FUTURE_SKEW_TOLERANCE_S}s skew tolerance) — refusing to serve ` +
      `for a paid request`
    );
  }
  if (opts.staleAfterS !== undefined && ageS > opts.staleAfterS) {
    return (
      `${opts.slug}: payload is stale (age ${Math.round(ageS)}s > ` +
      `${opts.staleAfterS}s tolerance) — refusing to serve stale data for a paid request`
    );
  }
  return null;
}

/**
 * The GET-route entry point (replaces direct calls to
 * fetchLatestPublisherPayload in index.ts). Order of preference:
 *
 *   1. Live companion service, if `liveUrl` is configured AND its candidate
 *      passes validationError() — the actual current-data path, fully
 *      decoupled from broadcast-subscriber economics.
 *   2. Broadcast archive (fetchLatestPublisherPayload) — tried whenever live
 *      is unconfigured, unreachable, or fails validation (treated the same
 *      as "unavailable", maximizing availability without weakening safety).
 *   3. FAIL CLOSED: throws with the archive candidate's specific
 *      validationError() reason — never resolves with null, unsigned, stale,
 *      or clock-skewed data — so the route handler's catch returns 502. A
 *      >=400 response makes the x402 middleware cancel settlement, so a
 *      paying caller is NEVER charged for a rejected payload, regardless of
 *      which source produced it.
 *
 * A feed with neither liveUrl nor staleAfterS configured (e.g. threat-intel)
 * still gets the null/attestation/timestamp checks — zero PRACTICAL behavior
 * change for any feed whose archive is actually fresh and well-formed today.
 */
export async function fetchFeedPayload(opts: {
  slug: string;
  publisher: string;
  liveUrl?: string;
  staleAfterS?: number;
}): Promise<GenericFeedPayload> {
  if (opts.liveUrl) {
    const live = await tryFetchLive(opts.slug, opts.publisher, opts.liveUrl);
    if (live && !validationError(live, opts)) return live;
  }

  const archived = await fetchLatestPublisherPayload({
    slug: opts.slug,
    publisher: opts.publisher,
  });

  const err = validationError(archived, opts);
  if (err) throw new Error(err);
  return archived;
}
