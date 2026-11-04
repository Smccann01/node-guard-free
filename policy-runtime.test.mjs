import assert from "node:assert/strict";
import { test } from "node:test";
import { createPolicyGuardV1 } from "./policy-runtime.mjs";

const start = Date.parse("2026-11-03T18:00:00Z");
const policy = {
  schema_version: 1, policy_id: "auth-login-v1", application_id: "billing-api",
  mode: "ENFORCE", route_id: "auth.login", reason_code: "authentication_failure",
  window_seconds: 60, threshold: 2, action: "THROTTLE", restriction_seconds: 120,
};
const observation = (id, overrides = {}) => ({
  schema_version: 1, application_id: "billing-api", event_id: id,
  observed_at: "2026-11-03T18:00:00Z", route_id: "auth.login",
  reason_code: "authentication_failure", source_ip: "8.8.8.8", protocol: "HTTPS",
  ...overrides,
});

test("live v1 policy restricts one source, expires, releases, and resets on restart", () => {
  let at = start;
  const options = { policy, now: () => at, canActOnSource: () => true };
  const guard = createPolicyGuardV1(options);
  assert.equal(guard.record(observation("event-001")).action, "recorded");
  assert.equal(guard.record(observation("event-002")).action, "THROTTLE");
  assert.equal(guard.restriction("8.8.8.8").retryAfterSeconds, 120);
  assert.equal(guard.isBlocked("9.9.9.9"), false);
  assert.equal(guard.snapshot().length, 1);
  assert.equal(createPolicyGuardV1(options).isBlocked("8.8.8.8"), false);
  assert.equal(guard.release("8.8.8.8"), 1);
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  guard.record(observation("event-003"));
  guard.record(observation("event-004"));
  assert.equal(guard.isBlocked("8.8.8.8"), true);
  at += 120_001;
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.deepEqual(guard.snapshot(), []);
});

test("replay, wrong app, wrong route, exclusions, and stale events cannot arm a restriction", () => {
  const guard = createPolicyGuardV1({ policy, now: () => start, canActOnSource: (ip) => ip !== "1.1.1.1" });
  assert.equal(guard.record(observation("event-001", { application_id: "other-api" })).reason, "policy_mismatch");
  assert.equal(guard.record(observation("event-001", { route_id: "auth.reset" })).reason, "policy_mismatch");
  assert.equal(guard.record(observation("event-001", { source_ip: "1.1.1.1" })).reason, "source_excluded");
  assert.equal(guard.record(observation("event-001", { observed_at: "2026-11-03T17:58:59Z" })).reason, "outside_window");
  assert.equal(guard.record(observation("event-001")).action, "recorded");
  assert.equal(guard.record(observation("event-001", { source_ip: "9.9.9.9" })).reason, "duplicate_event");
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.equal(guard.record(observation("event-002")).action, "THROTTLE");
  assert.equal(guard.isBlocked("8.8.8.8"), true);
});

test("OBSERVE never restricts and capacity stays bounded", () => {
  const observe = createPolicyGuardV1({ policy: { ...policy, mode: "OBSERVE" }, now: () => start, maxSources: 1, maxObservations: 2 });
  assert.equal(observe.record(observation("event-001")).action, "recorded");
  assert.equal(observe.record(observation("event-002")).action, "OBSERVE");
  assert.equal(observe.isBlocked("8.8.8.8"), false);
  assert.equal(observe.record(observation("event-003", { source_ip: "9.9.9.9" })).reason, "capacity_exhausted");
  assert.throws(() => createPolicyGuardV1({ policy, canActOnSource: () => true, maxObservations: 1 }), /meet the policy threshold/);
  assert.throws(() => createPolicyGuardV1({ policy }), /canActOnSource/);
});

test("v1 policy counts equivalent IPv6 forms as one source and honors canonical protection", () => {
  const expanded = '2606:4700:4700:0:0:0:0:1111';
  const compact = '2606:4700:4700::1111';
  const guard = createPolicyGuardV1({ policy, now: () => start, canActOnSource: () => true });
  assert.equal(guard.record(observation('event-101', { source_ip: expanded })).action, 'recorded');
  assert.equal(guard.record(observation('event-102', { source_ip: compact })).action, 'THROTTLE');
  assert.equal(guard.isBlocked(expanded), true);
  assert.equal(guard.snapshot()[0].sourceIp, compact);
  assert.equal(guard.release(expanded), 1);
  assert.equal(guard.isBlocked(compact), false);
  const protectedGuard = createPolicyGuardV1({ policy, now: () => start,
    canActOnSource: (ip) => ip !== compact });
  assert.equal(protectedGuard.record(observation('event-103', { source_ip: expanded })).reason, 'source_excluded');
});
