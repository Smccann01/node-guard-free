import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const cli = new URL('./bin/nodeguard.mjs', import.meta.url).pathname;

test('inspect and export include only validated policy, never observation data', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-cli-'));
  try {
    const policyPath = path.join(dir, 'policy.json');
    const exportPath = path.join(dir, 'export.json');
    const policy = JSON.parse(await readFile(new URL('./examples/auth-policy.json', import.meta.url), 'utf8'));
    await writeFile(policyPath, JSON.stringify(policy));
    const inspection = JSON.parse(execFileSync(process.execPath, [cli, 'inspect', policyPath], { encoding: 'utf8' }));
    assert.equal(inspection.state_scope, 'one_process');
    assert.equal(inspection.policy_id, policy.policy_id);
    execFileSync(process.execPath, [cli, 'export', policyPath, '--output', exportPath]);
    assert.deepEqual(JSON.parse(await readFile(exportPath, 'utf8')), policy);
    assert.throws(() => execFileSync(process.execPath, [cli, 'export', policyPath, '--output', exportPath], { stdio: 'pipe' }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI validates and simulates identity policy v2 with synthetic fixture IDs', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-v2-cli-'));
  try {
    const policyPath = path.join(dir, 'identity-policy.json');
    const exportPath = path.join(dir, 'export.json');
    const fixturesPath = new URL('./examples/identity-observations.json', import.meta.url).pathname;
    const policy = JSON.parse(await readFile(new URL('./examples/identity-policy.json', import.meta.url), 'utf8'));
    await writeFile(policyPath, JSON.stringify(policy));
    assert.match(execFileSync(process.execPath, [cli, 'policy', 'validate', policyPath], { encoding: 'utf8' }), /Valid policy v2/);
    const doctor = JSON.parse(execFileSync(process.execPath, [cli, 'doctor', policyPath], { encoding: 'utf8' }));
    assert.equal(doctor.policy_schema_version, 2);
    const inspection = JSON.parse(execFileSync(process.execPath, [cli, 'inspect', policyPath], { encoding: 'utf8' }));
    assert.equal(inspection.identity_scope, 'subject_id');
    execFileSync(process.execPath, [cli, 'export', policyPath, '--output', exportPath]);
    assert.deepEqual(JSON.parse(await readFile(exportPath, 'utf8')), policy);
    const simulated = JSON.parse(execFileSync(process.execPath,
      [cli, 'policy', 'test', policyPath, fixturesPath, '--at', '2026-11-04T06:00:00Z'], { encoding: 'utf8' }));
    assert.equal(simulated.schema_version, 2);
    assert.deepEqual(simulated.results.map((result) => [result.identity_ref, result.decision]), [['fixture:alice', 'OBSERVE']]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
