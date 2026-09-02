/**
 * Unit tests for src/lib/receipt-id.ts - the receipt-transparency routes'
 * validator and status mapping.
 *
 * Why these exist: the validator is the only thing between a caller-supplied
 * path segment and an upstream URL, on a gateway whose upstream serves a route
 * (POST /query) with no payment check of its own. A traversal that escaped the
 * validator would be a paywall bypass, not a 404. The first cut of this change
 * shipped both the validator and the mapping with zero coverage.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  RECEIPT_ID_RE,
  normalizeReceiptId,
  isValidReceiptId,
  mapUpstreamStatus,
} from "../../src/lib/receipt-id.js";

const VALID_LOWER = "0x" + "a1".repeat(32);
const VALID_UPPER = "0x" + "A1".repeat(32);

test("isValidReceiptId accepts a well-formed lowercase id", () => {
  assert.equal(isValidReceiptId(VALID_LOWER), true);
});

test("isValidReceiptId accepts uppercase hex as input tolerance", () => {
  assert.equal(isValidReceiptId(VALID_UPPER), true);
});

test("normalizeReceiptId lowercases, so a case-sensitive upstream lookup cannot miss on case alone", () => {
  assert.equal(normalizeReceiptId(VALID_UPPER), VALID_LOWER);
});

test("normalizeReceiptId coerces null/undefined to an empty string rather than the word null", () => {
  assert.equal(normalizeReceiptId(undefined), "");
  assert.equal(normalizeReceiptId(null), "");
});

test("isValidReceiptId rejects traversal-shaped ids - the paywall-bypass class", () => {
  const bads = [
    "..%2f..%2fquery",
    "../query",
    "..%252f..%252fquery",
    VALID_LOWER + "%2f..%2fquery",
    VALID_LOWER + "/../query",
  ];
  for (const bad of bads) {
    assert.equal(isValidReceiptId(bad), false, "must reject " + bad);
  }
});

test("isValidReceiptId rejects wrong lengths, missing prefix, and junk", () => {
  const bads = [
    "",
    "abc",
    "0x00",
    "0x" + "a".repeat(63),
    "0x" + "a".repeat(65),
    "a".repeat(64),
    "0x" + "g".repeat(64),
    VALID_LOWER + " ",
    " " + VALID_LOWER,
  ];
  for (const bad of bads) {
    assert.equal(isValidReceiptId(bad), false, "must reject " + JSON.stringify(bad));
  }
});

test("an uppercase 0X prefix is ACCEPTED because normalize lowercases first", () => {
  // Pinning the real behaviour rather than an assumption about it: normalize
  // lowercases the whole string, so 0X becomes 0x before the regex sees it.
  assert.equal(isValidReceiptId("0X" + "a1".repeat(32)), true);
});

test("RECEIPT_ID_RE itself is case-tolerant but anchored at both ends", () => {
  assert.equal(RECEIPT_ID_RE.test(VALID_UPPER), true);
  assert.equal(RECEIPT_ID_RE.test(VALID_LOWER + "x"), false);
  assert.equal(RECEIPT_ID_RE.test("x" + VALID_LOWER), false);
});

test("mapUpstreamStatus preserves a 404 as an honest miss, not a fault", () => {
  assert.deepEqual(mapUpstreamStatus(404), { status: 404, error: "not_found" });
});

test("mapUpstreamStatus collapses every 5xx to 502", () => {
  for (const s of [500, 502, 503, 504, 599]) {
    assert.equal(mapUpstreamStatus(s).status, 502, "upstream " + s + " must become 502");
    assert.equal(mapUpstreamStatus(s).error, "upstream error");
  }
});

test("mapUpstreamStatus passes other 4xx through without claiming not_found", () => {
  assert.deepEqual(mapUpstreamStatus(400), { status: 400, error: "upstream error" });
  assert.deepEqual(mapUpstreamStatus(429), { status: 429, error: "upstream error" });
});
