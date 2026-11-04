import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffPolicies } from './policy-diff.mjs';

const base = {
  schema_version: 1, policy_id: 'auth-login-v1', application_id: 'billing-api',
  mode: 'OBSERVE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 4, action: 'THROTTLE', restriction_seconds: 30,
};

test('reports every changed field and flags enforcement expansion without applying it', () => {
  const after = { ...base, mode: 'ENFORCE', threshold: 2, restriction_seconds: 120, action: 'DENY' };
  const diff = diffPolicies(base, after);
  assert.deepEqual(diff.changes.map((change) => change.field),
    ['mode', 'threshold', 'action', 'restriction_seconds']);
  assert.deepEqual(diff.review_reasons,
    ['enforcement_enabled', 'threshold_lowered', 'restriction_extended', 'response_strengthened']);
  assert.equal(diff.activation, 'none');
  assert.notEqual(diff.before_fingerprint_sha256, diff.after_fingerprint_sha256);
});

test('fingerprint ignores JSON property order and order of route exclusions', () => {
  const v2 = { ...base, schema_version: 2, route_id: '*', identity_scope: 'subject_id',
    excluded_route_ids: ['health.check', 'admin.read'] };
  const reordered = { excluded_route_ids: ['admin.read', 'health.check'],
    ...Object.fromEntries(Object.entries(v2).filter(([key]) => key !== 'excluded_route_ids').reverse()) };
  const diff = diffPolicies(v2, reordered);
  assert.equal(diff.changed, false);
  assert.equal(diff.before_fingerprint_sha256, diff.after_fingerprint_sha256);
  assert.deepEqual(diff.review_reasons, []);
});

test('removed exclusion and identity scope change require review', () => {
  const before = { ...base, schema_version: 2, route_id: '*', identity_scope: 'subject_id',
    excluded_route_ids: ['health.check'] };
  const after = { ...before, identity_scope: 'source_ip', excluded_route_ids: [] };
  assert.deepEqual(diffPolicies(before, after).review_reasons,
    ['route_exclusion_removed', 'identity_scope_changed']);
});

test('rejects cross-application and schema revisions and invalid policy fields', () => {
  assert.throws(() => diffPolicies(base, { ...base, application_id: 'another-app' }), /application_id/);
  assert.throws(() => diffPolicies(base, { ...base, schema_version: 2, identity_scope: 'source_ip', excluded_route_ids: [] }), /schema migration/);
  assert.throws(() => diffPolicies(base, { ...base, unknown: true }), /unknown field/);
});

test('CLI prints a read-only review of two policy files', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'nodeguard-policy-diff-'));
  try {
    const current = path.join(directory, 'current.json');
    const proposed = path.join(directory, 'proposed.json');
    writeFileSync(current, JSON.stringify(base));
    writeFileSync(proposed, JSON.stringify({ ...base, mode: 'ENFORCE' }));
    const cli = fileURLToPath(new URL('./bin/nodeguard.mjs', import.meta.url));
    const report = JSON.parse(execFileSync(process.execPath,
      [cli, 'policy', 'diff', current, proposed], { encoding: 'utf8' }));
    assert.deepEqual(report.review_reasons, ['enforcement_enabled']);
    assert.equal(report.activation, 'none');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
