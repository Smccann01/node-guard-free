import assert from "node:assert/strict";
import { test } from "node:test";
import express from "express";
import { createNodeGuard } from "./index.mjs";
import { createExpressNodeGuard } from "./express.mjs";
import { createPolicyGuardV1 } from "./policy-runtime.mjs";
import { createTrustedSourceResolver } from "./trusted-source.mjs";

test("Express preserves normal traffic and applies a temporary application restriction", async () => {
  let at = 1_000_000;
  let verifiedSourceIp = "8.8.8.8";
  const guard = createNodeGuard({ mode: "enforce", thresholds: { replay_burst: 2 }, blockMs: 2_000,
    now: () => at, canActOnSource: () => true });
  const app = express();
  app.use(createExpressNodeGuard({ guard, getVerifiedSourceIp: () => verifiedSourceIp }));
  app.get("/health", (_req, res) => res.json({ ok: true }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/health`;
    assert.equal((await fetch(url)).status, 200);
    guard.record({ sourceIp: verifiedSourceIp, reasonCode: "replay_burst" });
    guard.record({ sourceIp: verifiedSourceIp, reasonCode: "replay_burst" });
    const limited = await fetch(url, { headers: { "X-Forwarded-For": "1.1.1.1" } });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "2");
    assert.deepEqual(await limited.json(), { error: "node_guard_restricted" });
    verifiedSourceIp = "9.9.9.9";
    assert.equal((await fetch(url)).status, 200);
    verifiedSourceIp = "8.8.8.8";
    at += 2_001;
    assert.equal((await fetch(url)).status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("Express does not silently bypass a missing verified source", async () => {
  const guard = createNodeGuard({ mode: "enforce", canActOnSource: () => true });
  const app = express();
  app.use(createExpressNodeGuard({ guard, getVerifiedSourceIp: () => undefined }));
  app.get("/health", (_req, res) => res.json({ ok: true }));
  app.use((_error, _req, res, _next) => res.status(503).json({ error: "source_unavailable" }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/health`);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "source_unavailable" });
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("Express mounts a v1 DENY policy only on its protected route", async () => {
  const at = Date.parse("2026-11-03T18:00:00Z");
  const policy = { schema_version: 1, policy_id: "auth-login-v1", application_id: "billing-api",
    mode: "ENFORCE", route_id: "auth.login", reason_code: "authentication_failure",
    window_seconds: 60, threshold: 2, action: "DENY", restriction_seconds: 60 };
  const guard = createPolicyGuardV1({ policy, now: () => at, canActOnSource: () => true });
  const event = (event_id) => ({ schema_version: 1, application_id: "billing-api", event_id,
    observed_at: "2026-11-03T18:00:00Z", route_id: "auth.login", reason_code: "authentication_failure",
    source_ip: "8.8.8.8", protocol: "HTTPS" });
  const app = express();
  app.use("/login", createExpressNodeGuard({ guard, getVerifiedSourceIp: () => "8.8.8.8" }));
  app.get("/login", (_req, res) => res.json({ ok: true }));
  app.get("/health", (_req, res) => res.json({ ok: true }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    guard.record(event("event-001"));
    guard.record(event("event-002"));
    assert.equal((await fetch(`${base}/login`)).status, 403);
    assert.equal((await fetch(`${base}/health`)).status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("Express honors the nearest untrusted forwarded address from an explicit proxy", async () => {
  const at = Date.parse("2026-11-03T18:00:00Z");
  const policy = { schema_version: 1, policy_id: "auth-login-v1", application_id: "billing-api",
    mode: "ENFORCE", route_id: "auth.login", reason_code: "authentication_failure",
    window_seconds: 60, threshold: 2, action: "THROTTLE", restriction_seconds: 60 };
  const guard = createPolicyGuardV1({ policy, now: () => at, canActOnSource: () => true });
  const resolveSource = createTrustedSourceResolver({ trustedProxyIps: ["127.0.0.1"] });
  let sequence = 0;
  const app = express();
  app.use("/login", createExpressNodeGuard({ guard, getVerifiedSourceIp: resolveSource }));
  app.post("/login", (req, res) => {
    sequence++;
    guard.record({ schema_version: 1, application_id: "billing-api", event_id: `login-event-${sequence}`,
      observed_at: "2026-11-03T18:00:00Z", route_id: "auth.login", reason_code: "authentication_failure",
      source_ip: resolveSource(req), protocol: "HTTPS" });
    res.status(401).json({ error: "simulated_failure" });
  });
  app.get("/login", (_req, res) => res.json({ ok: true }));
  app.use((_error, _req, res, _next) => res.status(503).json({ error: "source_unavailable" }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/login`;
    const headers = { "X-Forwarded-For": "1.1.1.1, 8.8.8.8" };
    assert.equal((await fetch(url, { method: "POST", headers })).status, 401);
    assert.equal((await fetch(url, { method: "POST", headers })).status, 401);
    assert.equal((await fetch(url, { headers })).status, 429);
    assert.equal((await fetch(url, { headers: { "X-Forwarded-For": "9.9.9.9" } })).status, 200);
    assert.equal((await fetch(url)).status, 503);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
