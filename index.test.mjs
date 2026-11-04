import assert from 'node:assert/strict';
import test from 'node:test';
import { createNodeGuard, isEligibleSource } from './index.mjs';

test('standalone local enforcement needs no account, license, or agent and expires', () => {
  let at = Date.parse('2026-11-03T18:00:00Z');
  const guard = createNodeGuard({ mode: 'enforce', thresholds: { replay_burst: 2 },
    blockMs: 30_000, now: () => at, canActOnSource: (ip) => ip !== '1.1.1.1' });
  assert.equal(guard.record({ sourceIp: '8.8.8.8', reasonCode: 'replay_burst' }).action, 'recorded');
  assert.equal(guard.record({ sourceIp: '8.8.8.8', reasonCode: 'replay_burst' }).action, 'limit_armed');
  assert.equal(guard.isBlocked('8.8.8.8'), true);
  assert.equal(guard.record({ sourceIp: '1.1.1.1', reasonCode: 'replay_burst' }).reason, 'source_excluded');
  at += 30_001;
  assert.equal(guard.isBlocked('8.8.8.8'), false);
});

test('observe and unsafe sources do not block', () => {
  const guard = createNodeGuard({ mode: 'observe', thresholds: { api_probe_burst: 2 } });
  for (const ip of ['127.0.0.1', '10.0.0.1', '203.0.113.2', '::1']) {
    assert.equal(isEligibleSource(ip), false);
    assert.equal(guard.record({ sourceIp: ip, reasonCode: 'api_probe_burst' }).accepted, false);
  }
  guard.record({ sourceIp: '8.8.8.8', reasonCode: 'api_probe_burst' });
  assert.equal(guard.record({ sourceIp: '8.8.8.8', reasonCode: 'api_probe_burst' }).action, 'observed');
  assert.equal(guard.isBlocked('8.8.8.8'), false);
});

test('standalone guard uses one IPv6 identity across equivalent spellings and protected sources', () => {
  const expanded = '2606:4700:4700:0:0:0:0:1111';
  const compact = '2606:4700:4700::1111';
  const guard = createNodeGuard({ mode: 'enforce', thresholds: { replay_burst: 2 },
    canActOnSource: () => true });
  assert.equal(guard.record({ sourceIp: expanded, reasonCode: 'replay_burst' }).action, 'recorded');
  assert.equal(guard.record({ sourceIp: compact, reasonCode: 'replay_burst' }).action, 'limit_armed');
  assert.equal(guard.isBlocked(expanded), true);
  assert.equal(guard.snapshot()[0].sourceIp, compact);
  assert.equal(guard.release(expanded), 1);
  assert.equal(guard.isBlocked(compact), false);
  const protectedGuard = createNodeGuard({ mode: 'enforce', canActOnSource: (ip) => ip !== compact });
  assert.equal(protectedGuard.record({ sourceIp: expanded, reasonCode: 'replay_burst' }).reason, 'source_excluded');
});
