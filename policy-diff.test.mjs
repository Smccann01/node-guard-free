import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { comparePolicySimulation, diffPolicies } from './policy-diff.mjs';

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

test('compares point-in-time decisions on the same observations without activation', () => {
  const observations = ['event-001', 'event-002'].map((event_id) => ({
    schema_version: 1, application_id: 'billing-api', event_id,
    observed_at: '2026-11-04T10:00:00Z', route_id: 'auth.login',
    reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS',
  }));
  const comparison = comparePolicySimulation(base,
    { ...base, mode: 'ENFORCE', threshold: 2 }, observations,
    { at: '2026-11-04T10:00:10Z' });
  assert.equal(comparison.comparison_scope, 'simulation_only');
  assert.equal(comparison.fixture_count, 2);
  assert.equal(comparison.decision_changes.length, 1);
  assert.equal(comparison.decision_changes[0].before.decision, 'NONE');
  assert.equal(comparison.decision_changes[0].after.decision, 'THROTTLE');
  const directory = mkdtempSync(path.join(tmpdir(), 'nodeguard-policy-compare-'));
  try {
    const current = path.join(directory, 'current.json');
    const proposed = path.join(directory, 'proposed.json');
    const fixtures = path.join(directory, 'fixtures.json');
    writeFileSync(current, JSON.stringify(base));
    writeFileSync(proposed, JSON.stringify({ ...base, mode: 'ENFORCE', threshold: 2 }));
    writeFileSync(fixtures, JSON.stringify(observations));
    const cli = fileURLToPath(new URL('./bin/nodeguard.mjs', import.meta.url));
    const report = JSON.parse(execFileSync(process.execPath,
      [cli, 'policy', 'compare', current, proposed, fixtures, '--at', '2026-11-04T10:00:10Z'],
      { encoding: 'utf8' }));
    assert.deepEqual(report.decision_changes, comparison.decision_changes);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('redacted comparisons use one source alias across before and after decisions', () => {
  const observations = ['event-101', 'event-102'].map((event_id) => ({
    schema_version: 1, application_id: 'billing-api', event_id,
    observed_at: '2026-11-04T10:00:00Z', route_id: 'auth.login',
    reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS',
  }));
  const at = '2026-11-04T10:00:10Z';
  const proposed = { ...base, mode: 'ENFORCE', threshold: 2 };
  const report = comparePolicySimulation(base, proposed, observations, { at, redactSources: true });
  const change = report.decision_changes[0];
  assert.equal(report.source_redacted, true);
  assert.match(change.source_ref, /^source-[a-f0-9]{24}$/);
  assert.equal(change.before.source_ref, change.source_ref);
  assert.equal(change.after.source_ref, change.source_ref);
  assert.equal(JSON.stringify(report).includes('8.8.8.8'), false);
  assert.equal(change.before.source_ip, undefined);
  assert.throws(() => comparePolicySimulation(base, proposed, observations,
    { at, redactSources: 'yes' }), /redactSources/);

  const v2 = { ...base, schema_version: 2, identity_scope: 'source_ip', excluded_route_ids: [] };
  const entries = observations.map((observation) => ({ observation: { ...observation, schema_version: 2 } }));
  const v2Report = comparePolicySimulation(v2, { ...v2, mode: 'ENFORCE', threshold: 2 },
    entries, { at, redactSources: true });
  assert.equal(v2Report.decision_changes[0].identity_ref,
    v2Report.decision_changes[0].after.identity_ref);
  assert.equal(JSON.stringify(v2Report).includes('8.8.8.8'), false);

  const directory = mkdtempSync(path.join(tmpdir(), 'nodeguard-policy-redacted-'));
  try {
    const current = path.join(directory, 'current.json');
    const next = path.join(directory, 'proposed.json');
    const fixtures = path.join(directory, 'fixtures.json');
    writeFileSync(current, JSON.stringify(base));
    writeFileSync(next, JSON.stringify(proposed));
    writeFileSync(fixtures, JSON.stringify(observations));
    const cli = fileURLToPath(new URL('./bin/nodeguard.mjs', import.meta.url));
    const output = execFileSync(process.execPath,
      [cli, 'policy', 'compare', current, next, fixtures, '--at', at, '--redact'],
      { encoding: 'utf8' });
    assert.equal(JSON.parse(output).source_redacted, true);
    assert.equal(output.includes('8.8.8.8'), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('refuses comparing incompatible identity scopes or untrusted fixture fields', () => {
  const v2 = { ...base, schema_version: 2, identity_scope: 'subject_id', excluded_route_ids: [] };
  assert.throws(() => comparePolicySimulation(v2, { ...v2, identity_scope: 'source_ip' }, [],
    { at: '2026-11-04T10:00:00Z' }), /identity_scope changes/);
  assert.throws(() => comparePolicySimulation(base, base,
    [{ raw_password: 'secret' }], { at: '2026-11-04T10:00:00Z' }), /unknown field/);
});
