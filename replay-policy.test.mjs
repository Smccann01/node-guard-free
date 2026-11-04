import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { replayIdentityPolicyV2, replayPolicyV1 } from './replay-policy.mjs';
import { createPolicyGuardV1 } from './policy-runtime.mjs';
import { createIdentityGuardV2, createVerifiedIdentity } from './identity-policy.mjs';

const policy = {
  schema_version: 1, policy_id: 'login-v1', application_id: 'billing-api',
  mode: 'ENFORCE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 30,
};
const event = (id, at, source = '8.8.8.8') => ({
  schema_version: 1, application_id: 'billing-api', event_id: id,
  observed_at: at, route_id: 'auth.login', reason_code: 'authentication_failure',
  source_ip: source, protocol: 'HTTPS',
});
const first = event('event-001', '2026-11-04T10:00:00Z');
const second = event('event-002', '2026-11-04T10:00:01Z');

test('replay shows chronological restriction and natural expiration without host enforcement', () => {
  const observations = [first, second];
  const active = replayPolicyV1({ policy, observations, at: '2026-11-04T10:00:20Z', protectedSources: [] });
  assert.equal(active.enforcement_scope, 'simulation_only');
  assert.match(active.policy_fingerprint_sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(active.timeline.map((entry) => entry.record_action), ['recorded', 'THROTTLE']);
  assert.deepEqual(active.timeline.map((entry) => entry.trigger_hit_count), [null, 2]);
  assert.deepEqual(active.timeline.map((entry) => entry.effective_action), ['ALLOW', 'THROTTLE']);
  assert.deepEqual(active.active_restrictions, [{ source_ip: '8.8.8.8', action: 'THROTTLE',
    expires_at: '2026-11-04T10:00:31.000Z' }]);
  const expired = replayPolicyV1({ policy, observations, at: '2026-11-04T10:00:32Z' });
  assert.deepEqual(expired.active_restrictions, []);
  assert.equal(observations.length, 2);
});

test('v1 replay trigger matches the runtime decision for the same ordered events', async () => {
  let clock = Date.parse(first.observed_at);
  const decisions = [];
  const live = createPolicyGuardV1({ policy, now: () => clock,
    canActOnSource: () => true, onDecision: (decision) => decisions.push(decision) });
  for (const observation of [first, second]) {
    clock = Date.parse(observation.observed_at);
    live.record(observation);
  }
  await Promise.resolve();
  const replay = replayPolicyV1({ policy, observations: [first, second],
    at: '2026-11-04T10:00:20Z' });
  assert.equal(decisions.length, 1);
  assert.equal(replay.timeline[1].record_action, decisions[0].action);
  assert.equal(replay.timeline[1].trigger_hit_count, decisions[0].hit_count);
  assert.equal(replay.timeline[1].restriction_expires_at, decisions[0].restriction_expires_at);
});

test('policy fingerprint is stable across key order and changes when behavior changes', () => {
  const reordered = Object.fromEntries(Object.entries(policy).reverse());
  const baseline = replayPolicyV1({ policy, observations: [], at: first.observed_at });
  const same = replayPolicyV1({ policy: reordered, observations: [], at: first.observed_at });
  const changed = replayPolicyV1({ policy: { ...policy, threshold: 3 }, observations: [], at: first.observed_at });
  assert.equal(baseline.policy_fingerprint_sha256, same.policy_fingerprint_sha256);
  assert.notEqual(baseline.policy_fingerprint_sha256, changed.policy_fingerprint_sha256);
});

test('redacted replay keeps one alias per source without exposing source IPs', () => {
  const report = replayPolicyV1({ policy, observations: [first, second],
    at: '2026-11-04T10:00:20Z', redactSources: true });
  assert.equal(report.source_representation, 'pseudonym');
  assert.match(report.timeline[0].source_ref, /^source-[a-f0-9]{24}$/);
  assert.equal(report.timeline[0].source_ref, report.timeline[1].source_ref);
  assert.equal(report.timeline[1].source_ref, report.active_restrictions[0].source_ref);
  assert.equal(report.timeline[0].source_ip, undefined);
  assert.equal(JSON.stringify(report).includes('8.8.8.8'), false);
});

test('replay preserves duplicate and protected-source rejection', () => {
  const replay = replayPolicyV1({ policy, observations: [first, first, second,
    event('event-003', '2026-11-04T10:00:02Z', '1.1.1.1')],
  at: '2026-11-04T10:00:03Z', protectedSources: ['1.1.1.1'] });
  assert.equal(replay.timeline[1].rejection_reason, 'duplicate_event');
  assert.equal(replay.timeline[2].effective_action, 'THROTTLE');
  assert.equal(replay.timeline[3].rejection_reason, 'source_excluded');
  assert.deepEqual(replay.active_restrictions.map((entry) => entry.source_ip), ['8.8.8.8']);
});

test('replay protects an IPv6 source across equivalent text forms', () => {
  const expanded = '2606:4700:4700:0:0:0:0:1111';
  const compact = '2606:4700:4700::1111';
  const replay = replayPolicyV1({ policy,
    observations: [event('event-201', first.observed_at, expanded)],
    at: '2026-11-04T10:00:01Z', protectedSources: [compact] });
  assert.equal(replay.timeline[0].rejection_reason, 'source_excluded');
  assert.deepEqual(replay.active_restrictions, []);
  assert.throws(() => replayPolicyV1({ policy, observations: [], at: first.observed_at,
    protectedSources: [expanded, compact] }), /distinct/);
});

test('OBSERVE replay records a trigger without a restriction', () => {
  const replay = replayPolicyV1({ policy: { ...policy, mode: 'OBSERVE' },
    observations: [first, second], at: '2026-11-04T10:00:20Z' });
  assert.equal(replay.timeline[1].record_action, 'OBSERVE');
  assert.equal(replay.timeline[1].effective_action, 'ALLOW');
  assert.deepEqual(replay.active_restrictions, []);
});

test('replay refuses out-of-order, future, malformed, and untrusted observations', () => {
  assert.throws(() => replayPolicyV1({ policy, observations: [second, first],
    at: '2026-11-04T10:01:00Z' }), /ordered/);
  assert.throws(() => replayPolicyV1({ policy, observations: [second],
    at: '2026-11-04T10:00:00Z' }), /after replay time/);
  assert.throws(() => replayPolicyV1({ policy, observations: [{ ...first, raw_password: 'secret' }],
    at: '2026-11-04T10:01:00Z' }), /unknown field/);
  assert.throws(() => replayPolicyV1({ policy, observations: [event('event-004', first.observed_at, '127.0.0.1')],
    at: '2026-11-04T10:01:00Z' }), /eligible public IP/);
  assert.throws(() => replayPolicyV1({ policy, observations: [first],
    at: '2026-11-04T10:00:60Z' }), /valid UTC timestamp/);
});

test('CLI requires an explicit protected-source file for ENFORCE replay', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'nodeguard-replay-'));
  const cli = fileURLToPath(new URL('./bin/nodeguard.mjs', import.meta.url));
  try {
    const policyPath = path.join(root, 'policy.json');
    const eventsPath = path.join(root, 'events.json');
    const protectedPath = path.join(root, 'protected.json');
    writeFileSync(policyPath, JSON.stringify(policy));
    writeFileSync(eventsPath, JSON.stringify([first, second]));
    writeFileSync(protectedPath, '[]');
    assert.throws(() => execFileSync(process.execPath, [cli, 'replay', policyPath, eventsPath,
      '--at', '2026-11-04T10:00:20Z'], { stdio: 'pipe' }), /ENFORCE replay requires/);
    const output = JSON.parse(execFileSync(process.execPath, [cli, 'replay', policyPath, eventsPath,
      '--at', '2026-11-04T10:00:20Z', '--protected', protectedPath], { encoding: 'utf8' }));
    assert.equal(output.active_restrictions.length, 1);
    assert.equal(output.enforcement_scope, 'simulation_only');
    const redacted = execFileSync(process.execPath, [cli, 'replay', policyPath, eventsPath,
      '--at', '2026-11-04T10:00:20Z', '--protected', protectedPath, '--redact'], { encoding: 'utf8' });
    assert.equal(redacted.includes('8.8.8.8'), false);
    assert.equal(JSON.parse(redacted).source_representation, 'pseudonym');
    assert.deepEqual(JSON.parse(readFileSync(protectedPath, 'utf8')), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('v2 replay uses synthetic identities and shows restriction expiry', () => {
  const v2 = { ...policy, schema_version: 2, identity_scope: 'subject_id', excluded_route_ids: [] };
  const entries = [first, second].map((observation) => ({
    observation: { ...observation, schema_version: 2 }, fixture_identity: 'fixture:member_01',
  }));
  const active = replayIdentityPolicyV2({ policy: v2, entries, at: '2026-11-04T10:00:20Z', redactSources: true });
  assert.equal(active.schema_version, 2);
  assert.deepEqual(active.timeline.map((entry) => entry.record_action), ['recorded', 'THROTTLE']);
  assert.deepEqual(active.active_restrictions, [{ identity_scope: 'subject_id',
    identity_ref: 'fixture:member_01', action: 'THROTTLE', expires_at: '2026-11-04T10:00:31.000Z' }]);
  assert.equal(JSON.stringify(active).includes('8.8.8.8'), false);
  assert.equal(JSON.stringify(active).includes('subject_id:'), false);
  const expired = replayIdentityPolicyV2({ policy: v2, entries, at: '2026-11-04T10:00:32Z' });
  assert.deepEqual(expired.active_restrictions, []);
});

test('v2 synthetic replay trigger matches the runtime decision for the same events', async () => {
  const v2 = { ...policy, schema_version: 2, identity_scope: 'subject_id', excluded_route_ids: [] };
  const entries = [first, second].map((observation) => ({
    observation: { ...observation, schema_version: 2 }, fixture_identity: 'fixture:member_01',
  }));
  let clock = Date.parse(first.observed_at);
  const decisions = [];
  const live = createIdentityGuardV2({ policy: v2, now: () => clock,
    canActOnSource: () => true, onDecision: (decision) => decisions.push(decision) });
  const identity = createVerifiedIdentity({ subjectId: 'fixture:member_01' });
  for (const entry of entries) {
    clock = Date.parse(entry.observation.observed_at);
    live.record(entry.observation, identity);
  }
  await Promise.resolve();
  const replay = replayIdentityPolicyV2({ policy: v2, entries,
    at: '2026-11-04T10:00:20Z' });
  assert.equal(decisions.length, 1);
  assert.equal(replay.timeline[1].record_action, decisions[0].action);
  assert.equal(replay.timeline[1].trigger_hit_count, decisions[0].hit_count);
  assert.equal(replay.timeline[1].restriction_expires_at, decisions[0].restriction_expires_at);
});

test('v2 replay rejects untrusted identity fixture fields and mismatched scope', () => {
  const v2 = { ...policy, schema_version: 2, identity_scope: 'tenant_id', excluded_route_ids: [] };
  const observation = { ...first, schema_version: 2 };
  assert.throws(() => replayIdentityPolicyV2({ policy: v2,
    entries: [{ observation, fixture_identity: 'real-user@example.com' }], at: '2026-11-04T10:00:20Z' }), /synthetic/);
  assert.throws(() => replayIdentityPolicyV2({ policy: v2,
    entries: [{ observation, fixture_identity: 'fixture:one', bearer_token: 'secret' }], at: '2026-11-04T10:00:20Z' }), /optional fixture_identity/);
  assert.throws(() => replayIdentityPolicyV2({ policy: { ...v2, identity_scope: 'source_ip' },
    entries: [{ observation, fixture_identity: 'fixture:one' }], at: '2026-11-04T10:00:20Z' }), /must not supply/);
});

test('v2 source-scope CLI replay redacts source and enforces protected-source input', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'nodeguard-replay-v2-'));
  const cli = fileURLToPath(new URL('./bin/nodeguard.mjs', import.meta.url));
  try {
    const policyPath = path.join(root, 'policy.json');
    const eventsPath = path.join(root, 'events.json');
    const protectedPath = path.join(root, 'protected.json');
    writeFileSync(policyPath, JSON.stringify({ ...policy, schema_version: 2,
      identity_scope: 'source_ip', excluded_route_ids: [] }));
    writeFileSync(eventsPath, JSON.stringify([first, second].map((observation) => ({
      observation: { ...observation, schema_version: 2 },
    }))));
    writeFileSync(protectedPath, '[]');
    const report = JSON.parse(execFileSync(process.execPath, [cli, 'replay', policyPath, eventsPath,
      '--at', '2026-11-04T10:00:20Z', '--protected', protectedPath, '--redact'], { encoding: 'utf8' }));
    assert.equal(report.active_restrictions.length, 1);
    assert.match(report.active_restrictions[0].identity_ref, /^source-[a-f0-9]{24}$/);
    assert.equal(JSON.stringify(report).includes('8.8.8.8'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('v2 replay cannot arm a restriction for a protected source', () => {
  const v2 = { ...policy, schema_version: 2, identity_scope: 'source_ip', excluded_route_ids: [] };
  const entries = [first, second].map((observation) => ({ observation: { ...observation, schema_version: 2 } }));
  const report = replayIdentityPolicyV2({ policy: v2, entries,
    at: '2026-11-04T10:00:20Z', protectedSources: ['8.8.8.8'] });
  assert.deepEqual(report.timeline.map((entry) => entry.rejection_reason), ['source_excluded', 'source_excluded']);
  assert.deepEqual(report.active_restrictions, []);
});
