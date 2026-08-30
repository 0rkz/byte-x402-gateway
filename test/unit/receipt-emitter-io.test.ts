/**
 * IO-shell tests for src/lib/receipt-emitter.ts (G5). The pure-function
 * surface (HMAC/hash copies, resource derivation, context building, outcome
 * classification, guard evaluation, response parsing) is covered in
 * test/unit/receipt-emitter.test.ts. This file drives the network/clock/
 * filesystem-touching functions — postPaymentContext, emitWithRetry,
 * logReceiptOutcome, and emitFromSettleContext — against a real
 * `node:http` server on localhost, so what's asserted is the actual bytes
 * that go over the wire and the actual JSONL line written to disk.
 *
 * Retry backoff (2s, 8s per BACKOFF_MS) is driven via node:test's built-in
 * MockTimers rather than waited out in real time, so this file stays fast
 * and deterministic while still exercising the real setTimeout-based retry
 * loop end to end.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  postPaymentContext,
  emitWithRetry,
  logReceiptOutcome,
  emitFromSettleContext,
  buildPaymentContext,
  type BuiltPaymentContext,
  type OutcomeLogRecord,
} from "../../src/lib/receipt-emitter.js";

// ── test server helper ──────────────────────────────────────────────────

interface CapturedRequest {
  method: string | undefined;
  contextHeader: string | undefined;
  hmacHeader: string | undefined;
  body: string;
}

/** Spins up a local HTTP stub replaying `responses` in order (one per request, then holding the last), capturing every request it saw, for the duration of `fn`. */
async function withStubServer(
  responses: Array<{ status: number; body: unknown }>,
  fn: (ctx: { url: string; requests: CapturedRequest[] }) => Promise<void>,
): Promise<void> {
  const requests: CapturedRequest[] = [];
  let i = 0;
  const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      requests.push({
        method: req.method,
        contextHeader: req.headers["x-byte-payment-context"] as string | undefined,
        hmacHeader: req.headers["x-byte-payment-context-hmac"] as string | undefined,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      const resp = responses[Math.min(i, responses.length - 1)];
      i += 1;
      res.writeHead(resp.status, { "content-type": "application/json" });
      res.end(JSON.stringify(resp.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  try {
    await fn({ url: `http://127.0.0.1:${port}`, requests });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** Advances node:test's mock setTimeout in a loop until `p` settles, or a cap is hit (guards against an accidental infinite hang). */
async function drainWithMockTimers<T>(t: import("node:test").TestContext, p: Promise<T>, stepMs = 2000, maxSteps = 20): Promise<T> {
  let settled = false;
  p.then(
    () => (settled = true),
    () => (settled = true),
  );
  for (let i = 0; i < maxSteps && !settled; i++) {
    t.mock.timers.tick(stepMs);
    await new Promise((r) => setImmediate(r));
  }
  return p;
}

function testBuilt(): BuiltPaymentContext {
  return buildPaymentContext(
    {
      payer: "0x1111111111111111111111111111111111111111",
      nonce: `0x${"cd".repeat(32)}` as `0x${string}`,
      txHash: `0x${"ab".repeat(32)}` as `0x${string}`,
      body: { asset: "BTC", h: 4 },
      signalObj: { asset: "BTC", regime: "range" },
      nowSeconds: 1_800_000_000,
    },
    "io-test-secret",
  );
}

// ── postPaymentContext ───────────────────────────────────────────────────

test("postPaymentContext: sends the raw context + HMAC as headers, exactly as built (not re-serialized)", async () => {
  await withStubServer([{ status: 200, body: { signal: {}, receipt: { id: "r1" } } }], async ({ url, requests }) => {
    const built = testBuilt();
    const result = await postPaymentContext(`${url}/query`, { asset: "BTC", h: 4 }, built.raw, built.hmac);
    assert.equal(result.status, 200);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].contextHeader, built.raw);
    assert.equal(requests[0].hmacHeader, built.hmac);
    assert.equal(requests[0].method, "POST");
  });
});

test("postPaymentContext: network error (nothing listening) -> status null, no throw", async () => {
  const built = testBuilt();
  // Port 1 is reserved/unroutable — connection is refused immediately.
  const result = await postPaymentContext("http://127.0.0.1:1/query", {}, built.raw, built.hmac);
  assert.equal(result.status, null);
  assert.equal(result.parsedBody, null);
});

// ── emitWithRetry ─────────────────────────────────────────────────────────

test("emitWithRetry: identical raw context + HMAC bytes on every attempt (serialize-once on the wire)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer(
      [
        { status: 503, body: {} },
        { status: 503, body: {} },
        { status: 200, body: { signal: {}, receipt: { id: "r-final" } } },
      ],
      async ({ url, requests }) => {
        const built = testBuilt();
        const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, { asset: "BTC", h: 4 }, built));
        assert.equal(result.outcome, "minted");
        assert.equal(result.attempts, 3);
        assert.equal(result.httpStatus, 200);
        assert.equal(requests.length, 3);
        for (const r of requests) {
          assert.equal(r.contextHeader, built.raw, "context header must be byte-identical across attempts");
          assert.equal(r.hmacHeader, built.hmac, "HMAC header must be byte-identical across attempts");
        }
      },
    );
  } finally {
    t.mock.timers.reset();
  }
});

test("emitWithRetry: 503 -> retries, eventually succeeds (classification through the real retry loop)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer(
      [
        { status: 503, body: {} },
        { status: 200, body: { signal: {}, receipt: { id: "r2" } } },
      ],
      async ({ url }) => {
        const built = testBuilt();
        const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, {}, built));
        assert.equal(result.outcome, "minted");
        assert.equal(result.attempts, 2);
      },
    );
  } finally {
    t.mock.timers.reset();
  }
});

test("emitWithRetry: 502 -> exactly one attempt, no retry (nonce already burned — retrying cannot help)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer([{ status: 502, body: { error: "mint failed" } }], async ({ url, requests }) => {
      const built = testBuilt();
      const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, {}, built));
      assert.equal(result.outcome, "permanent");
      assert.equal(result.attempts, 1);
      assert.equal(result.httpStatus, 502);
      assert.equal(requests.length, 1);
    });
  } finally {
    t.mock.timers.reset();
  }
});

test("emitWithRetry: 200 + receipt:null -> exactly one attempt, no retry (considered refusal)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer(
      [{ status: 200, body: { signal: {}, receipt: null, receipt_reason: "settlement pending" } }],
      async ({ url, requests }) => {
        const built = testBuilt();
        const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, {}, built));
        assert.equal(result.outcome, "permanent");
        assert.equal(result.attempts, 1);
        assert.equal(result.receiptReason, "settlement pending");
        assert.equal(requests.length, 1);
      },
    );
  } finally {
    t.mock.timers.reset();
  }
});

test("emitWithRetry: 200 + receipt:null + 'payment_nonce already used' -> already_minted, one attempt (G9)", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer(
      [
        {
          status: 200,
          body: { signal: {}, receipt: null, receipt_reason: "payment_nonce already used — a receipt was already minted for this payment" },
        },
      ],
      async ({ url, requests }) => {
        const built = testBuilt();
        const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, {}, built));
        assert.equal(result.outcome, "already_minted");
        assert.equal(result.attempts, 1);
        assert.equal(requests.length, 1);
      },
    );
  } finally {
    t.mock.timers.reset();
  }
});

test("emitWithRetry: exhausts all 3 attempts on persistent 503 -> retryable, httpStatus of last attempt", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withStubServer([{ status: 503, body: {} }], async ({ url, requests }) => {
      const built = testBuilt();
      const result = await drainWithMockTimers(t, emitWithRetry(`${url}/query`, {}, built), 8000, 10);
      assert.equal(result.outcome, "retryable");
      assert.equal(result.attempts, 3);
      assert.equal(result.httpStatus, 503);
      assert.equal(requests.length, 3);
    });
  } finally {
    t.mock.timers.reset();
  }
});

// ── logReceiptOutcome: JSONL line shape ─────────────────────────────────

test("logReceiptOutcome: appends one valid JSON line with the full OutcomeLogRecord shape to GATEWAY_RECEIPTS_LOG", async (t) => {
  const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "receipt-log-test-"));
  const logFile = path.join(scratchDir, "nested", "gateway-receipts.jsonl");
  const prevEnv = process.env.GATEWAY_RECEIPTS_LOG;
  process.env.GATEWAY_RECEIPTS_LOG = logFile;
  t.after(() => {
    if (prevEnv === undefined) delete process.env.GATEWAY_RECEIPTS_LOG;
    else process.env.GATEWAY_RECEIPTS_LOG = prevEnv;
    fs.rmSync(scratchDir, { recursive: true, force: true });
  });

  const rec: OutcomeLogRecord = {
    ts: new Date(0).toISOString(),
    feed: "regime-signal",
    payer: "0x1111111111111111111111111111111111111111",
    nonce: `0x${"cd".repeat(32)}`,
    txHash: `0x${"ab".repeat(32)}`,
    outcome: "minted",
    attempts: 1,
    http_status: 200,
    receipt_id: "r-abc",
  };

  assert.equal(fs.existsSync(logFile), false, "log dir must not exist before the first write (lazy mkdir, G8)");
  logReceiptOutcome(rec);

  // appendFile's callback is async — wait for the write to land.
  for (let i = 0; i < 50 && !fs.existsSync(logFile); i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.ok(fs.existsSync(logFile), "log file should exist after a write");

  const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
  assert.equal(lines.length, 1);
  const parsed = JSON.parse(lines[0]);
  assert.deepEqual(parsed, rec);
});

// ── emitFromSettleContext: full hook entry point against the stub ──────────

test("emitFromSettleContext: happy-path settle mints a receipt end-to-end and logs http_status", async (t) => {
  const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "receipt-e2e-test-"));
  const logFile = path.join(scratchDir, "gateway-receipts.jsonl");
  const prevLogEnv = process.env.GATEWAY_RECEIPTS_LOG;
  const prevSecretEnv = process.env.GATEWAY_HMAC_SECRET;
  process.env.GATEWAY_RECEIPTS_LOG = logFile;
  process.env.GATEWAY_HMAC_SECRET = "e2e-test-secret";
  t.after(() => {
    if (prevLogEnv === undefined) delete process.env.GATEWAY_RECEIPTS_LOG;
    else process.env.GATEWAY_RECEIPTS_LOG = prevLogEnv;
    if (prevSecretEnv === undefined) delete process.env.GATEWAY_HMAC_SECRET;
    else process.env.GATEWAY_HMAC_SECRET = prevSecretEnv;
    fs.rmSync(scratchDir, { recursive: true, force: true });
  });

  await withStubServer(
    [{ status: 200, body: { signal: { asset: "BTC" }, receipt: { id: "e2e-1" }, receipt_id: "e2e-1" } }],
    async ({ url, requests }) => {
      const responseBody = JSON.stringify({ signal: { asset: "BTC", regime: "range" }, receipt: null });
      const ctx = {
        result: { success: true, transaction: `0x${"ab".repeat(32)}`, payer: "0x1111111111111111111111111111111111111111", network: "eip155:8453" },
        paymentPayload: { payload: { authorization: { from: "0x1111111111111111111111111111111111111111", nonce: `0x${"cd".repeat(32)}` } } },
        transportContext: {
          request: { path: "/feeds/regime-signal/", adapter: { getBody: () => ({ asset: "BTC", h: 4 }) } },
          responseBody,
        },
      };

      await emitFromSettleContext(ctx, { regimeSignalUrl: url });

      assert.equal(requests.length, 1, "should have posted exactly once to the stub");

      for (let i = 0; i < 50 && !fs.existsSync(logFile); i++) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.ok(fs.existsSync(logFile));
      const line = fs.readFileSync(logFile, "utf8").trim();
      const rec = JSON.parse(line);
      assert.equal(rec.outcome, "minted");
      assert.equal(rec.http_status, 200);
      assert.equal(rec.attempts, 1);
      assert.equal(rec.receipt_id, "e2e-1");
    },
  );
});

test("emitFromSettleContext: Permit2 settle never reaches the network (skips before any POST)", async () => {
  await withStubServer([{ status: 200, body: { signal: {}, receipt: { id: "should-not-happen" } } }], async ({ url, requests }) => {
    const ctx = {
      result: { success: true, transaction: `0x${"ab".repeat(32)}`, payer: "0x1111111111111111111111111111111111111111", network: "eip155:8453" },
      paymentPayload: { payload: { permit2Authorization: { from: "0x1111111111111111111111111111111111111111", nonce: "999" } } },
      transportContext: {
        request: { path: "/feeds/regime-signal", adapter: { getBody: () => ({ asset: "BTC", h: 4 }) } },
        responseBody: JSON.stringify({ signal: { asset: "BTC" }, receipt: null }),
      },
    };
    await emitFromSettleContext(ctx, { regimeSignalUrl: url });
    assert.equal(requests.length, 0, "permit2 settle must never mint — no request should ever reach receipts");
  });
});
