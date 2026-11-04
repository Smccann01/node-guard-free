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
