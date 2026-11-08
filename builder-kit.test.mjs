import assert from 'node:assert/strict';
import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkBuilderProject, initBuilderProject, listBuilderTemplates, writeBuilderReview } from './builder-kit.mjs';

test('Builder creates a local synthetic project and compares policy decisions without activation', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  const directory = join(parent, 'project');
  try {
    await initBuilderProject(directory);
    const result = await checkBuilderProject(directory);
    assert.equal(result.event_count, 3);
    assert.equal(result.review.activation, 'none');
    assert.equal(result.review.comparison_scope, 'simulation_only');
    assert.equal(result.review.source_redacted, true);
    assert.equal(result.review.decision_changes[0].before.decision, 'OBSERVE');
    assert.equal(result.review.decision_changes[0].after.decision, 'THROTTLE');
    assert.equal(result.unchanged_control_evidence, true);
    assert.equal(result.review_gates.source_attribution_verified, false);
    assert.equal(result.review_gates.production_approved, false);
    await assert.rejects(initBuilderProject(directory), { code: 'EEXIST' });
    const observations = await readFile(join(directory, 'observations.json'), 'utf8');
    assert.match(observations, /sample-login-abuse-1/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('Builder templates produce valid redacted reviews and refuse to overwrite', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  try {
    assert.deepEqual(listBuilderTemplates().map((item) => item.id), ['login-abuse', 'api-probing', 'webhook-replay', 'tenant-api']);
    for (const template of listBuilderTemplates().map((item) => item.id)) {
      const directory = join(parent, template);
      const output = join(parent, `${template}-review.json`);
      await initBuilderProject(directory, { template });
      const result = await checkBuilderProject(directory);
      assert.equal(result.template, template);
      assert.equal(result.unchanged_control_evidence, true);
      if (template === 'tenant-api') assert.equal(result.review.policy_schema_version, 2);
      assert.equal(result.canonical_current_policy_sha256, result.review.before_fingerprint_sha256);
      const saved = await writeBuilderReview(directory, output);
      assert.equal(saved.decision_change_count, 1);
      const report = await readFile(output, 'utf8');
      assert.equal(JSON.parse(report).activation, 'none');
      assert.equal(report.includes('8.8.8.8'), false);
      assert.equal(report.includes('1.1.1.1'), false);
      assert.equal((await lstat(output)).mode & 0o777, 0o600);
      await assert.rejects(writeBuilderReview(directory, output), { code: 'EEXIST' });
    }
    await assert.rejects(initBuilderProject(join(parent, 'bad'), { template: 'unknown' }), /unknown Builder template/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('Builder rejects invalid local event fixtures before policy comparison', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  const directory = join(parent, 'project');
  try {
    await initBuilderProject(directory);
    await writeFile(join(directory, 'observations.json'), JSON.stringify([{ source_ip: '127.0.0.1' }]));
    await assert.rejects(checkBuilderProject(directory));
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('Builder reports a missing control fixture without approving deployment', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  const directory = join(parent, 'project');
  try {
    await initBuilderProject(directory);
    const observations = JSON.parse(await readFile(join(directory, 'observations.json'), 'utf8'));
    await writeFile(join(directory, 'observations.json'), JSON.stringify(observations.filter((item) => item.source_ip !== '1.1.1.1')));
    const result = await checkBuilderProject(directory);
    assert.equal(result.unchanged_control_evidence, false);
    assert.equal(result.review_gates.production_approved, false);
    assert.match(result.next_checks.join(' '), /unaffected control source/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('Builder rejects a symlinked fixture file', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  const directory = join(parent, 'project');
  try {
    await initBuilderProject(directory);
    await rm(join(directory, 'observations.json'));
    await symlink(join(parent, 'outside.json'), join(directory, 'observations.json'));
    await writeFile(join(parent, 'outside.json'), '[]');
    await assert.rejects(checkBuilderProject(directory), /must be a JSON file/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
