import assert from "node:assert/strict";
import { test } from "node:test";
import { createVerifiedIdentity } from "./identity-policy.mjs";
import { createIdentityPolicySetV2 } from "./identity-policy-set.mjs";
import { createExpressIdentityPolicySetV2 } from "./identity-policy-set-express.mjs";
import { createNextIdentityPolicySetV2 } from "./identity-policy-set-next.mjs";

const at = Date.parse("2026-11-04T07:00:00Z");
const common = { schema_version: 2, application_id: "billing-api", mode: "ENFORCE",
  reason_code: "authentication_failure", identity_scope: "subject_id", window_seconds: 60,
  threshold: 2, action: "THROTTLE", restriction_seconds: 60 };
const exact = { ...common, policy_id: "login-exact", route_id: "auth.login" };
const wildcard = { ...common, policy_id: "all-other", route_id: "*", excluded_route_ids: ["health.check"] };
const observation = (id, routeId) => ({ schema_version: 2, application_id: "billing-api", event_id: id,
  observed_at: new Date(at).toISOString(), route_id: routeId, reason_code: "authentication_failure",
  source_ip: "8.8.8.8", protocol: "HTTPS" });

test("exact route policy takes precedence over a wildcard for record and restriction", () => {
  const subject = createVerifiedIdentity({ subjectId: "subject-1" });
  const set = createIdentityPolicySetV2({ policies: [wildcard, exact], now: () => at, canActOnSource: () => true });
  set.record(observation("event-001", "api.transfer"), subject);
  assert.equal(set.record(observation("event-002", "api.transfer"), subject).decision.policy_id, "all-other");
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", identity: subject, routeId: "api.transfer" }), true);
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", identity: subject, routeId: "auth.login" }), false);
  set.record(observation("event-003", "auth.login"), subject);
  assert.equal(set.record(observation("event-004", "auth.login"), subject).decision.policy_id, "login-exact");
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", identity: subject, routeId: "auth.login" }), true);
  assert.deepEqual(new Set(set.snapshot().map((item) => item.policy_id)), new Set(["all-other", "login-exact"]));
  assert.equal(set.release({ policyId: "all-other", sourceIp: "8.8.8.8", identity: subject }), 1);
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", identity: subject, routeId: "auth.login" }), true);
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", identity: subject, routeId: "api.transfer" }), false);
});

test("excluded routes and cross-policy replay do not create restrictions", () => {
  const subject = createVerifiedIdentity({ subjectId: "subject-1" });
  const set = createIdentityPolicySetV2({ policies: [exact, wildcard], now: () => at, canActOnSource: () => true });
  assert.equal(set.matches("health.check"), false);
  assert.equal(set.record(observation("event-001", "health.check"), subject).reason, "policy_mismatch");
  assert.equal(set.record(observation("event-001", "auth.login"), subject).action, "recorded");
  assert.equal(set.record(observation("event-001", "api.transfer"), subject).reason, "duplicate_event");
  assert.equal(set.record({ ...observation("event-002", "auth.login"), reason_code: "replay_burst" }, subject).reason, "policy_mismatch");
  assert.equal(set.isBlocked({ sourceIp: "8.8.8.8", routeId: "health.check" }), false);
  assert.throws(() => set.matches("invalid route"), /verified routeId/);
  assert.throws(() => set.release({ policyId: "unknown", sourceIp: "8.8.8.8", identity: subject }), /known policyId/);
});

test("ambiguous policy collections are rejected before runtime", () => {
  assert.throws(() => createIdentityPolicySetV2({ policies: [exact, { ...exact, policy_id: "different" }], canActOnSource: () => true }), /per exact route/);
  assert.throws(() => createIdentityPolicySetV2({ policies: [wildcard, { ...wildcard, policy_id: "different" }], canActOnSource: () => true }), /one wildcard/);
  assert.throws(() => createIdentityPolicySetV2({ policies: [exact, { ...wildcard, application_id: "other-app" }], canActOnSource: () => true }), /one application/);
  assert.throws(() => createIdentityPolicySetV2({ policies: [exact], maxSeenEvents: 1, canActOnSource: () => true }), /threshold/);
});

test("Express and Next adapters use exact-route precedence and fail on missing verified identity", async () => {
  const subject = createVerifiedIdentity({ subjectId: "subject-1" });
  const set = createIdentityPolicySetV2({ policies: [wildcard, exact], now: () => at, canActOnSource: () => true });
  set.record(observation("event-001", "api.transfer"), subject);
  set.record(observation("event-002", "api.transfer"), subject);
  const calls = [];
  const middleware = createExpressIdentityPolicySetV2({ policySet: set,
    getRouteId: (request) => request.routeId, getVerifiedSourceIp: () => "8.8.8.8",
    getVerifiedIdentity: (request) => request.identity });
  const response = { set: (key, value) => calls.push([key, value]),
    status: (status) => ({ json: (body) => calls.push([status, body]) }) };
  middleware({ routeId: "auth.login", identity: subject }, response, (error) => calls.push(error ?? "next"));
  middleware({ routeId: "api.transfer", identity: subject }, response, (error) => calls.push(error ?? "next"));
  middleware({ routeId: "health.check" }, response, (error) => calls.push(error ?? "next"));
  middleware({ routeId: "api.transfer" }, response, (error) => calls.push(error ?? "next"));
  assert.equal(calls[0], "next");
  assert.deepEqual(calls[1], ["Retry-After", "60"]);
  assert.equal(calls[2][0], 429);
  assert.equal(calls[3], "next");
  assert.match(calls[4].message, /verified subject_id/);
  const next = createNextIdentityPolicySetV2({ policySet: set,
    getRouteId: async (request) => request.routeId,
    getVerifiedSourceIp: async () => "8.8.8.8",
    getVerifiedIdentity: async (request) => request.identity });
  assert.equal(await next({ routeId: "auth.login", identity: subject }), null);
  assert.equal((await next({ routeId: "api.transfer", identity: subject })).status, 429);
  assert.equal(await next({ routeId: "health.check" }), null);
  assert.equal((await next({ routeId: "api.transfer" })).status, 503);
});
