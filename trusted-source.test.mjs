import assert from "node:assert/strict";
import { test } from "node:test";
import { createTrustedSourceResolver } from "./trusted-source.mjs";

const request = (remoteAddress, forwarded) => ({
  socket: { remoteAddress }, headers: { "x-forwarded-for": forwarded },
});

test("direct peers cannot spoof their source through forwarding headers", () => {
  const source = createTrustedSourceResolver({ trustedProxyIps: ["127.0.0.1"] });
  assert.equal(source(request("9.9.9.9", "1.1.1.1")), "9.9.9.9");
  assert.equal(source(request("::ffff:9.9.9.9", "1.1.1.1")), "9.9.9.9");
  assert.throws(() => source(request("not-an-ip", "1.1.1.1")), /remoteAddress/);
});

test("trusted proxies select the nearest untrusted hop, not a spoofed leftmost value", () => {
  const source = createTrustedSourceResolver({ trustedProxyIps: ["127.0.0.1", "10.0.0.2", "2001:db8::1"] });
  assert.equal(source(request("127.0.0.1", "1.1.1.1, 8.8.8.8")), "8.8.8.8");
  assert.equal(source(request("127.0.0.1", "1.1.1.1, 8.8.8.8, 10.0.0.2")), "8.8.8.8");
  assert.equal(source(request("2001:0db8:0:0::1", "2001:4860:4860::8888")), "2001:4860:4860::8888");
});

test("trusted proxy chain fails on absent, malformed, or all-trusted source data", () => {
  const source = createTrustedSourceResolver({ trustedProxyIps: ["127.0.0.1"] });
  assert.throws(() => source(request("127.0.0.1", undefined)), /must provide/);
  assert.throws(() => source(request("127.0.0.1", ["8.8.8.8", "1.1.1.1"])), /must provide/);
  assert.throws(() => source(request("127.0.0.1", "8.8.8.8, bad")), /forwarded hop/);
  assert.throws(() => source(request("127.0.0.1", "127.0.0.1")), /no untrusted source/);
  assert.throws(() => source(request("127.0.0.1", Array(17).fill("8.8.8.8").join(","))), /too many/);
  assert.throws(() => createTrustedSourceResolver({ trustedProxyIps: ["0.0.0.0/0"] }), /trusted proxy/);
});
