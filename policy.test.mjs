import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { simulatePolicyV1, validateObservationV1, validatePolicyV1 } from "./policy.mjs";

const at = "2026-11-03T18:00:00Z";
const policy = {
  schema_version: 1, policy_id: "auth-login-v1", application_id: "billing-api",
  mode: "ENFORCE", route_id: "auth.login", reason_code: "authentication_failure",
  window_seconds: 60, threshold: 2, action: "THROTTLE", restriction_seconds: 120,
};
const event = (event_id, overrides = {}) => ({
  schema_version: 1, application_id: "billing-api", event_id,
  observed_at: "2026-11-03T17:59:30Z", route_id: "auth.login",
  reason_code: "authentication_failure", source_ip: "8.8.8.8", protocol: "HTTPS",
  ...overrides,
});

test("v1 policy rejects unknown fields and unsafe or ambiguous values", () => {
  assert.equal(validatePolicyV1(policy).policy_id, "auth-login-v1");
  assert.throws(() => validatePolicyV1({ ...policy, schema_version: 2 }), /unsupported/);
  assert.throws(() => validatePolicyV1({ ...policy, accidental_allow: true }), /unknown field/);
  assert.throws(() => validatePolicyV1({ ...policy, threshold: 1 }), /threshold/);
  assert.throws(() => validatePolicyV1({ ...policy, restriction_seconds: 86_400 }), /restriction_seconds/);
  assert.throws(() => validateObservationV1(event("event-001", { source_ip: "127.0.0.1" })), /eligible public IP/);
  assert.throws(() => validateObservationV1(event("event-001", { subject_key: "raw-email@example.com" })), /unknown field/);
  assert.throws(() => validateObservationV1(event("event-001", { observed_at: "2026-02-31T18:00:00Z" })), /valid UTC timestamp/);
});

test("simulation counts independent events only within the correct app, route, and window", () => {
  const observations = [
    event("event-001"), event("event-001"),
    event("event-002", { application_id: "other-api" }),
    event("event-003", { route_id: "other.route" }),
    event("event-004", { observed_at: "2026-11-03T17:58:59Z" }),
    event("event-005", { source_ip: "9.9.9.9" }),
  ];
  assert.deepEqual(simulatePolicyV1(policy, observations, { at }).map((result) => [result.source_ip, result.hit_count, result.decision]), [
    ["8.8.8.8", 1, "NONE"], ["9.9.9.9", 1, "NONE"],
  ]);
  observations.push(event("event-006"));
  const result = simulatePolicyV1(policy, observations, { at }).find((item) => item.source_ip === "8.8.8.8");
  assert.equal(result.decision, "THROTTLE");
  assert.equal(result.restriction_expires_at, "2026-11-03T18:02:00.000Z");
  const observe = simulatePolicyV1({ ...policy, mode: "OBSERVE" }, observations, { at });
  assert.equal(observe.find((item) => item.source_ip === "8.8.8.8").decision, "OBSERVE");
  assert.equal(observe.find((item) => item.source_ip === "8.8.8.8").restriction_expires_at, null);
  assert.throws(() => simulatePolicyV1(policy, [event("event-007", { observed_at: "2026-11-03T18:00:01Z" })], { at }), /after simulation time/);
});

test("simulation counts equivalent IPv6 spellings under one canonical source", () => {
  const observations = [
    event("event-101", { source_ip: "2606:4700:4700:0:0:0:0:1111" }),
    event("event-102", { source_ip: "2606:4700:4700::1111" }),
  ];
  const result = simulatePolicyV1(policy, observations, { at });
  assert.equal(result.length, 1);
  assert.equal(result[0].source_ip, "2606:4700:4700::1111");
  assert.equal(result[0].hit_count, 2);
});

test("CLI validates and simulates policy files from a clean local input", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "nodeguard-policy-"));
  try {
    const policyPath = path.join(directory, "policy.json");
    const eventsPath = path.join(directory, "events.json");
    await writeFile(policyPath, JSON.stringify(policy));
    await writeFile(eventsPath, JSON.stringify([event("event-001"), event("event-002")]));
    const cli = path.join(process.cwd(), "bin", "nodeguard.mjs");
    assert.match(execFileSync(process.execPath, [cli, "policy", "validate", policyPath], { encoding: "utf8" }), /Valid policy v1/);
    const output = JSON.parse(execFileSync(process.execPath, [cli, "policy", "test", policyPath, eventsPath, "--at", at], { encoding: "utf8" }));
    assert.equal(output.results[0].decision, "THROTTLE");
    await writeFile(policyPath, JSON.stringify({ ...policy, schema_version: 2 }));
    assert.throws(() => execFileSync(process.execPath, [cli, "policy", "validate", policyPath], { stdio: "pipe" }), /unknown identity_scope/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("init writes an OBSERVE policy once and doctor does not claim source trust", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "nodeguard-init-"));
  try {
    const policyPath = path.join(directory, "nodeguard.policy.json");
    const cli = path.join(process.cwd(), "bin", "nodeguard.mjs");
    assert.match(execFileSync(process.execPath, [cli, "init", "--output", policyPath], { encoding: "utf8" }), /Created OBSERVE policy/);
    const diagnostic = JSON.parse(execFileSync(process.execPath, [cli, "doctor", policyPath], { encoding: "utf8" }));
    assert.equal(diagnostic.policy_mode, "OBSERVE");
    assert.equal(diagnostic.source_trust, "not checked");
    assert.equal(diagnostic.multi_worker_consistency, "not provided");
    assert.throws(() => execFileSync(process.execPath, [cli, "init", "--output", policyPath], { stdio: "pipe" }), /EEXIST/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
