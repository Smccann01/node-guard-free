import assert from "node:assert/strict";
import { test } from "node:test";
import { createVerifiedIdentity, createIdentityGuardV2, validateIdentityObservationV2,
  validateIdentityPolicyV2, simulateIdentityPolicyV2 } from "./identity-policy.mjs";
import { createExpressIdentityGuardV2 } from "./identity-express.mjs";
import { createNextIdentityGuardV2 } from "./identity-next-route.mjs";

const atStart = Date.parse("2026-11-04T06:00:00Z");
const policy = { schema_version: 2, policy_id: "login-by-user", application_id: "billing-api", mode: "ENFORCE",
  route_id: "*", excluded_route_ids: ["health.check"], reason_code: "authentication_failure",
  identity_scope: "subject_id", window_seconds: 60, threshold: 2, action: "THROTTLE", restriction_seconds: 60 };
const event = (id, overrides = {}) => ({ schema_version: 2, application_id: "billing-api", event_id: id,
  observed_at: "2026-11-04T06:00:00Z", route_id: "auth.login", reason_code: "authentication_failure",
  source_ip: "8.8.8.8", protocol: "HTTPS", ...overrides });

test("v2 policy and observation reject ambiguity and network-supplied identity fields", () => {
  assert.equal(validateIdentityPolicyV2(policy).identity_scope, "subject_id");
  assert.throws(() => validateIdentityPolicyV2({ ...policy, identity_scope: "user_header" }), /identity_scope/);
  assert.throws(() => validateIdentityPolicyV2({ ...policy, route_id: "auth.login" }), /route exclusions/);
  assert.throws(() => validateIdentityPolicyV2({ ...policy, excluded_route_ids: ["health.check", "health.check"] }), /distinct/);
  assert.throws(() => validateIdentityPolicyV2({ ...policy, threshold: 1 }), /threshold/);
  assert.throws(() => validateIdentityObservationV2(event("event-001", { subject_id: "user-from-body" })), /unknown field/);
  assert.throws(() => validateIdentityObservationV2(event("event-001", { source_ip: "127.0.0.1" })), /eligible public IP/);
  assert.throws(() => createVerifiedIdentity({ subjectId: "user\nadmin" }), /bounded/);
  assert.throws(() => createVerifiedIdentity({}), /at least one/);
});

test("v2 simulation is deterministic and accepts synthetic identities only", () => {
  const entries = [
    { observation: event("event-001"), fixture_identity: "fixture:alice" },
    { observation: event("event-002"), fixture_identity: "fixture:alice" },
    { observation: event("event-002", { source_ip: "9.9.9.9" }), fixture_identity: "fixture:bob" },
    { observation: event("event-003", { route_id: "health.check" }), fixture_identity: "fixture:alice" },
  ];
  const options = { at: "2026-11-04T06:00:00Z" };
  const first = simulateIdentityPolicyV2(policy, entries, options);
  assert.deepEqual(first, simulateIdentityPolicyV2(policy, entries, options));
  assert.deepEqual(first.map((result) => [result.identity_ref, result.hit_count, result.decision]),
    [["fixture:alice", 2, "THROTTLE"]]);
  assert.throws(() => simulateIdentityPolicyV2(policy, [{ observation: event("event-001"), fixture_identity: "alice@example.com" }], options), /synthetic/);
  assert.throws(() => simulateIdentityPolicyV2(policy, entries, { at: "2026-02-31T06:00:00Z" }), /valid UTC/);
});

test("two authenticated subjects behind the same IP remain isolated; forged JSON context fails", async () => {
  let at = atStart;
  const decisions = [];
  const guard = createIdentityGuardV2({ policy, now: () => at, canActOnSource: () => true,
    onDecision: (decision) => decisions.push(decision) });
  const alice = createVerifiedIdentity({ subjectId: "alice", tenantId: "company-1" });
  const bob = createVerifiedIdentity({ subjectId: "bob", tenantId: "company-1" });
  assert.equal(JSON.stringify(alice), '{"verified":true}');
  assert.throws(() => guard.record(event("event-001"), JSON.parse(JSON.stringify(alice))), /verified subject_id/);
  assert.equal(guard.record(event("event-001"), alice).action, "recorded");
  assert.equal(guard.record(event("event-002"), alice).action, "THROTTLE");
  assert.equal(guard.isBlocked({ sourceIp: "8.8.8.8", routeId: "auth.login", identity: alice }), true);
  assert.equal(guard.isBlocked({ sourceIp: "8.8.8.8", routeId: "auth.login", identity: bob }), false);
  assert.equal(guard.isBlocked({ sourceIp: "8.8.8.8", routeId: "health.check", identity: alice }), false);
  assert.throws(() => guard.isBlocked({ sourceIp: "8.8.8.8", identity: alice }), /verified routeId/);
  assert.equal(guard.record(event("event-002", { source_ip: "9.9.9.9" }), bob).reason, "duplicate_event");
  assert.equal(guard.record(event("event-003", { route_id: "health.check" }), bob).reason, "policy_mismatch");
  assert.equal(guard.snapshot().length, 1);
  assert.doesNotMatch(JSON.stringify(guard.snapshot()), /alice|bob/);
  assert.equal(createIdentityGuardV2({ policy, now: () => at, canActOnSource: () => true }).isBlocked({ sourceIp: "8.8.8.8", routeId: "auth.login", identity: alice }), false);
  assert.equal(guard.release({ sourceIp: "8.8.8.8", identity: bob }), 0);
  assert.equal(guard.release({ sourceIp: "8.8.8.8", identity: alice }), 1);
  assert.equal(guard.isBlocked({ sourceIp: "8.8.8.8", routeId: "auth.login", identity: alice }), false);
  guard.record(event("event-004"), alice);
  guard.record(event("event-005"), alice);
  at += 60_001;
  assert.equal(guard.isBlocked({ sourceIp: "8.8.8.8", routeId: "auth.login", identity: alice }), false);
  await Promise.resolve();
  assert.equal(decisions.length, 2);
  assert.doesNotMatch(JSON.stringify(decisions), /alice|bob/);
});

test("source-scoped IPv6 policy treats equivalent text forms as one verified source", () => {
  const ipv6Policy = { ...policy, identity_scope: "source_ip" };
  const guard = createIdentityGuardV2({ policy: ipv6Policy, now: () => atStart, canActOnSource: () => true });
  const short = "2606:4700:4700::1111";
  const long = "2606:4700:4700:0000:0000:0000:0000:1111";
  guard.record(event("event-001", { source_ip: short }));
  assert.equal(guard.record(event("event-002", { source_ip: long })).action, "THROTTLE");
  assert.equal(guard.isBlocked({ sourceIp: short, routeId: "auth.login" }), true);
  assert.equal(guard.isBlocked({ sourceIp: long, routeId: "auth.login" }), true);
  assert.equal(guard.release({ sourceIp: long }), 1);
  assert.equal(guard.isBlocked({ sourceIp: short, routeId: "auth.login" }), false);
});

test("tenant and API key scopes select the right verified identity and obey source protection", () => {
  for (const [scope, field] of [["tenant_id", "tenantId"], ["api_key_id", "apiKeyId"]]) {
    const guard = createIdentityGuardV2({ policy: { ...policy, identity_scope: scope }, now: () => atStart,
      canActOnSource: (source) => source !== "1.1.1.1" });
    const one = createVerifiedIdentity({ [field]: "company-1" });
    const two = createVerifiedIdentity({ [field]: "company-2" });
    assert.throws(() => guard.record(event("event-001"), createVerifiedIdentity({ subjectId: "alice" })), /verified/);
    guard.record(event("event-001"), one);
    guard.record(event("event-002"), one);
    assert.equal(guard.isBlocked({ sourceIp: "9.9.9.9", routeId: "auth.login", identity: one }), true);
    assert.equal(guard.isBlocked({ sourceIp: "9.9.9.9", routeId: "auth.login", identity: two }), false);
    assert.equal(guard.isBlocked({ sourceIp: "1.1.1.1", routeId: "auth.login", identity: one }), false);
  }
});

test("Express and Next adapters fail on missing identity and enforce only the selected subject", async () => {
  const guard = createIdentityGuardV2({ policy, now: () => atStart, canActOnSource: () => true });
  const alice = createVerifiedIdentity({ subjectId: "alice" });
  const bob = createVerifiedIdentity({ subjectId: "bob" });
  guard.record(event("event-001"), alice);
  guard.record(event("event-002"), alice);
  const middleware = createExpressIdentityGuardV2({ guard, getVerifiedSourceIp: (req) => req.sourceIp,
    getRouteId: (req) => req.routeId,
    getVerifiedIdentity: (req) => req.authenticatedIdentity });
  const calls = [];
  const response = { set: (name, value) => { calls.push([name, value]); },
    status: (code) => ({ json: (body) => { calls.push([code, body]); } }) };
  middleware({ sourceIp: "8.8.8.8", routeId: "auth.login", authenticatedIdentity: bob }, response, (error) => calls.push(error ?? "next"));
  middleware({ routeId: "health.check" }, response, (error) => calls.push(error ?? "next"));
  middleware({ sourceIp: "8.8.8.8", routeId: "auth.login", authenticatedIdentity: alice }, response, (error) => calls.push(error ?? "next"));
  middleware({ sourceIp: "8.8.8.8", routeId: "auth.login" }, response, (error) => calls.push(error ?? "next"));
  assert.equal(calls[0], "next");
  assert.equal(calls[1], "next");
  assert.deepEqual(calls[2], ["Retry-After", "60"]);
  assert.equal(calls[3][0], 429);
  assert.match(calls[4].message, /verified subject_id/);
  const check = createNextIdentityGuardV2({ guard, getVerifiedSourceIp: async () => "8.8.8.8",
    getRouteId: async (req) => req.routeId ?? "auth.login",
    getVerifiedIdentity: async (req) => req.identity });
  assert.equal(await check({ identity: bob }), null);
  assert.equal(await check({ routeId: "health.check" }), null);
  const limited = await check({ identity: alice });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("Retry-After"), "60");
  assert.equal((await check({})).status, 503);
});
