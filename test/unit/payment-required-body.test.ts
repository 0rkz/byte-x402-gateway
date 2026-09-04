/**
 * Unit tests for src/lib/payment-required-body.ts — the 402 body mirror.
 *
 * The defect: @x402/express answers an unpaid request with the challenge in
 * the PAYMENT-REQUIRED header and `{}` in the body. The acceptance here is
 * never "body is non-empty": it is decode-both-and-compare. The body must
 * parse to the SAME object core's decoder yields from the header, and the
 * header string must go out byte-for-byte unchanged.
 *
 * Every request runs through a real express app on a real loopback listener,
 * so Content-Type, Content-Length and JSON encoding are express's own, not a
 * fake response object's. The handler reproduces the adapter's exact write
 * sequence on the unpaid path: status(402) → setHeader → json({}).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import express from "express";
import type { Response } from "express";
import { encodePaymentRequiredHeader, decodePaymentRequiredHeader } from "@x402/core/http";

import { mirrorPaymentRequiredBody, decodeChallenge } from "../../src/lib/payment-required-body.js";

// The live challenge shape (loopback gateway, 2026-09-04), values as measured.
const SAMPLE = {
  x402Version: 2,
  error: "Payment required",
  resource: {
    url: "http://127.0.0.1:3402/feeds/earthquakes",
    description: "USGS earthquakes, last hour",
    mimeType: "application/json",
  },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:8453",
      amount: "3000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0xffFf4B8Da8C165B556326453446F6940C8AFE0DB",
      maxTimeoutSeconds: 300,
      extra: { name: "USD Coin", version: "2" },
    },
  ],
  extensions: { bazaar: { info: { input: { type: "http", method: "GET" } } } },
};

type Served = { status: number; headers: http.IncomingHttpHeaders; body: string };

/** One GET through express with the wrapper installed (or not), real loopback bytes. */
async function serve(handler: (res: Response) => void, install = true): Promise<Served> {
  const app = express();
  app.use((_req, res, next) => {
    if (install) mirrorPaymentRequiredBody(res);
    next();
  });
  app.get("/feeds/earthquakes", (_req, res) => handler(res));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  try {
    return await new Promise<Served>((resolve, reject) => {
      http
        .get({ host: "127.0.0.1", port, path: "/feeds/earthquakes" }, (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
        })
        .on("error", reject);
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** Exactly what @x402/express does on the unpaid path. */
const adapterUnpaidWrite = (header: string) => (res: Response) => {
  res.status(402);
  res.setHeader("PAYMENT-REQUIRED", header);
  res.json({});
};

test("402: body parses to the decoded PAYMENT-REQUIRED header; header bytes unchanged", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const r = await serve(adapterUnpaidWrite(header));
  assert.equal(r.status, 402);
  assert.equal(r.headers["payment-required"], header);
  assert.deepEqual(JSON.parse(r.body), decodePaymentRequiredHeader(header));
  assert.deepEqual(JSON.parse(r.body), SAMPLE);
  assert.ok(String(r.headers["content-type"]).startsWith("application/json"));
  assert.equal(Number(r.headers["content-length"]), Buffer.byteLength(r.body));
});

test("402 with nested `extensions`: JSON.parse(body) deep-equals decode(header) (order-independent)", async () => {
  // Deeper than the live shape on purpose: several extension keys, nested
  // arrays, unicode, numbers and booleans, and keys written in a different
  // order from SAMPLE. The acceptance is deep-equality against core's decoder
  // — never "the body is non-empty".
  const NESTED = {
    accepts: SAMPLE.accepts,
    extensions: {
      bazaar: {
        info: { input: { type: "http", method: "GET", query: { limit: 10, verbose: false } }, output: { example: { feeds: [{ id: "earthquakes", price: "$0.003" }] } } },
        schema: { input: { type: "object", properties: { limit: { type: "integer", minimum: 1 } }, required: [] } },
      },
      "byte-attestation": { chainId: 421614, domain: "BYTE Library", note: "receipt over exact bytes — ✓" },
      list: [1, "two", { three: 3 }, [4]],
    },
    resource: { mimeType: "application/json", url: "http://127.0.0.1:3402/feeds/earthquakes" },
    error: "Payment required",
    x402Version: 2,
  };
  const header = encodePaymentRequiredHeader(NESTED as never);
  const r = await serve(adapterUnpaidWrite(header));
  assert.equal(r.status, 402);
  assert.equal(r.headers["payment-required"], header);
  const body = JSON.parse(r.body);
  const decoded = decodePaymentRequiredHeader(header);
  assert.deepEqual(body, decoded);
  assert.deepEqual(body, NESTED);
  assert.deepEqual(body.extensions.bazaar.schema.input.properties.limit, { type: "integer", minimum: 1 });
  assert.deepEqual(body.extensions.list, [1, "two", { three: 3 }, [4]]);
  assert.equal(body.extensions["byte-attestation"].note, "receipt over exact bytes — ✓");
});

test("control: without the wrapper the same write is the defect — body `{}`", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const r = await serve(adapterUnpaidWrite(header), false);
  assert.equal(r.status, 402);
  assert.equal(r.headers["payment-required"], header);
  assert.equal(r.body, "{}");
});

test("402 with `undefined` body (res.json()) is mirrored too", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const r = await serve((res) => {
    res.status(402);
    res.setHeader("PAYMENT-REQUIRED", header);
    (res as Response & { json: (b?: unknown) => Response }).json();
  });
  assert.deepEqual(JSON.parse(r.body), decodePaymentRequiredHeader(header));
});

test("402 that already carries a body is left alone", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const r = await serve((res) => {
    res.status(402);
    res.setHeader("PAYMENT-REQUIRED", header);
    res.json({ error: "invalid payment signature" });
  });
  assert.deepEqual(JSON.parse(r.body), { error: "invalid payment signature" });
  assert.equal(r.headers["payment-required"], header);
});

test("402 with no challenge header stays `{}`", async () => {
  const r = await serve((res) => {
    res.status(402);
    res.json({});
  });
  assert.equal(r.status, 402);
  assert.equal(r.body, "{}");
  assert.equal(r.headers["payment-required"], undefined);
});

test("non-402 responses are untouched, even with the header present and an empty body", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const ok = await serve((res) => {
    res.status(200);
    res.setHeader("PAYMENT-REQUIRED", header);
    res.json({});
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.body, "{}");
  const data = await serve((res) => {
    res.status(200);
    res.json({ ok: true, feeds: [] });
  });
  assert.deepEqual(JSON.parse(data.body), { ok: true, feeds: [] });
});

test("malformed header: body stays `{}`, nothing throws, header still echoed", async () => {
  const r = await serve((res) => {
    res.status(402);
    res.setHeader("PAYMENT-REQUIRED", "!!!not-base64-json!!!");
    res.json({});
  });
  assert.equal(r.status, 402);
  assert.equal(r.body, "{}");
  assert.equal(r.headers["payment-required"], "!!!not-base64-json!!!");
});

test("HTML paywall path (res.send) is not intercepted", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const r = await serve((res) => {
    res.status(402);
    res.setHeader("PAYMENT-REQUIRED", header);
    res.type("html").send("<html>pay</html>");
  });
  assert.equal(r.body, "<html>pay</html>");
  assert.ok(String(r.headers["content-type"]).startsWith("text/html"));
});

test("installing twice wraps once (idempotent)", async () => {
  const header = encodePaymentRequiredHeader(SAMPLE as never);
  const app = express();
  let wraps = 0;
  app.use((_req, res, next) => {
    const before = res.json;
    mirrorPaymentRequiredBody(res);
    const afterFirst = res.json;
    mirrorPaymentRequiredBody(res);
    if (before !== afterFirst) wraps++;
    if (afterFirst !== res.json) wraps++;
    next();
  });
  app.get("/feeds/earthquakes", (_req, res) => adapterUnpaidWrite(header)(res));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  try {
    const body = await new Promise<string>((resolve, reject) => {
      http
        .get({ host: "127.0.0.1", port, path: "/feeds/earthquakes" }, (res) => {
          let b = "";
          res.setEncoding("utf8");
          res.on("data", (c) => (b += c));
          res.on("end", () => resolve(b));
        })
        .on("error", reject);
    });
    assert.equal(wraps, 1);
    assert.deepEqual(JSON.parse(body), decodePaymentRequiredHeader(header));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("decodeChallenge: null for non-strings, empty, malformed, or non-object payloads", () => {
  assert.equal(decodeChallenge(undefined), null);
  assert.equal(decodeChallenge(42), null);
  assert.equal(decodeChallenge(""), null);
  assert.equal(decodeChallenge("%%%"), null);
  assert.equal(decodeChallenge(Buffer.from("[1,2]").toString("base64")), null);
  assert.deepEqual(decodeChallenge(encodePaymentRequiredHeader(SAMPLE as never)), SAMPLE);
});
