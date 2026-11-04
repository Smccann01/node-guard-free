import assert from "node:assert/strict";
import { test } from "node:test";
import { createNodeGuard } from "./index.mjs";
import { createNextRouteGuard } from "./next-route.mjs";
import { createPolicyGuardV1 } from "./policy-runtime.mjs";

test("Next Route Handler check uses a verified source and returns a temporary response", async () => {
  const guard = createNodeGuard({ mode: "enforce", thresholds: { replay_burst: 2 }, canActOnSource: () => true });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  const check = createNextRouteGuard({ guard, getVerifiedSourceIp: async () => "8.8.8.8" });
  const request = new Request("https://example.test/api/login", { headers: { "x-forwarded-for": "1.1.1.1" } });
  const response = await check(request);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.ok(Number(response.headers.get("retry-after")) > 0);
  assert.deepEqual(await response.json(), { error: "node_guard_restricted" });
  assert.equal(await createNextRouteGuard({ guard, getVerifiedSourceIp: () => "9.9.9.9" })(request), null);
});

test("Next Route Handler check reports missing attribution instead of permitting traffic", async () => {
  const guard = createNodeGuard({ mode: "observe" });
  const request = new Request("https://example.test/api/login");
  assert.throws(() => createNextRouteGuard({ guard }), /getVerifiedSourceIp/);
  const missing = await createNextRouteGuard({ guard, getVerifiedSourceIp: () => undefined })(request);
  assert.equal(missing.status, 503);
  assert.deepEqual(await missing.json(), { error: "verified_source_unavailable" });
  assert.equal((await createNextRouteGuard({ guard, getVerifiedSourceIp: () => { throw new Error("invalid ingress"); } })(request)).status, 503);
});

test("Next Route Handler check returns 403 for a v1 DENY restriction", async () => {
  const at = Date.parse("2026-11-03T18:00:00Z");
  const policy = { schema_version: 1, policy_id: "auth-login-v1", application_id: "billing-api",
    mode: "ENFORCE", route_id: "auth.login", reason_code: "authentication_failure",
    window_seconds: 60, threshold: 2, action: "DENY", restriction_seconds: 60 };
  const guard = createPolicyGuardV1({ policy, now: () => at, canActOnSource: () => true });
  for (const event_id of ["event-001", "event-002"]) guard.record({ schema_version: 1,
    application_id: "billing-api", event_id, observed_at: "2026-11-03T18:00:00Z",
    route_id: "auth.login", reason_code: "authentication_failure", source_ip: "8.8.8.8", protocol: "HTTPS" });
  const check = createNextRouteGuard({ guard, getVerifiedSourceIp: () => "8.8.8.8" });
  assert.equal((await check(new Request("https://example.test/api/login"))).status, 403);
});
