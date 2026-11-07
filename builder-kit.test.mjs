import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkBuilderProject, initBuilderProject } from './builder-kit.mjs';

test('Builder creates a local synthetic project and compares policy decisions without activation', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'nodeguard-builder-'));
  const directory = join(parent, 'project');
  try {
    await initBuilderProject(directory);
    const result = await checkBuilderProject(directory);
    assert.equal(result.event_count, 2);
    assert.equal(result.review.activation, 'none');
    assert.equal(result.review.comparison_scope, 'simulation_only');
    assert.equal(result.review.source_redacted, true);
    assert.equal(result.review.decision_changes[0].before.decision, 'OBSERVE');
    assert.equal(result.review.decision_changes[0].after.decision, 'THROTTLE');
    await assert.rejects(initBuilderProject(directory), { code: 'EEXIST' });
    const observations = await readFile(join(directory, 'observations.json'), 'utf8');
    assert.match(observations, /sample-1/);
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
