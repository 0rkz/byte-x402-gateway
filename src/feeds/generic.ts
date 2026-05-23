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
  source: "byte-library-broadcast";
  txHash?: string;
  payloadHash?: string;
  payloadBytes?: number;
  data: unknown;
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
