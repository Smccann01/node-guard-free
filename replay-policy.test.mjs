import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { replayPolicyV1 } from './replay-policy.mjs';

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
  assert.deepEqual(active.timeline.map((entry) => entry.record_action), ['recorded', 'THROTTLE']);
  assert.deepEqual(active.timeline.map((entry) => entry.effective_action), ['ALLOW', 'THROTTLE']);
  assert.deepEqual(active.active_restrictions, [{ source_ip: '8.8.8.8', action: 'THROTTLE',
    expires_at: '2026-11-04T10:00:31.000Z' }]);
  const expired = replayPolicyV1({ policy, observations, at: '2026-11-04T10:00:32Z' });
  assert.deepEqual(expired.active_restrictions, []);
  assert.equal(observations.length, 2);
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
    assert.deepEqual(JSON.parse(readFileSync(protectedPath, 'utf8')), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
