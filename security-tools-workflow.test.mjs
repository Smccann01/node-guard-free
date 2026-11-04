import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('signed local delivery can feed a redacted policy review and simulation-only replay', () => {
  const output = execFileSync(process.execPath,
    [fileURLToPath(new URL('./examples/security-tools-workflow.mjs', import.meta.url))],
    { encoding: 'utf8' });
  const result = JSON.parse(output);
  assert.equal(result.delivery.accepted, true);
  assert.equal(result.policy_review.source_redacted, true);
  assert.deepEqual(result.policy_review.review_reasons, ['enforcement_enabled']);
  assert.equal(result.policy_review.decision_changes[0].after.decision, 'THROTTLE');
  assert.equal(result.replay.enforcement_scope, 'simulation_only');
  assert.equal(result.replay.active_restrictions.length, 1);
  assert.equal(result.replay.policy_fingerprint_sha256,
    result.policy_review.after_fingerprint_sha256);
  assert.equal(output.includes('8.8.8.8'), false);
});
