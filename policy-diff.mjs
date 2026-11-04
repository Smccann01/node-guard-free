import { createHash } from 'node:crypto';
import { validatePolicyV1 } from './policy.mjs';
import { validateIdentityPolicyV2 } from './identity-policy.mjs';

const FIELDS = ['schema_version', 'policy_id', 'application_id', 'mode', 'route_id',
  'reason_code', 'window_seconds', 'threshold', 'action', 'restriction_seconds',
  'identity_scope', 'excluded_route_ids'];

function validate(input) {
  return input?.schema_version === 2 ? validateIdentityPolicyV2(input) : validatePolicyV1(input);
}

function canonical(input) {
  return FIELDS.filter((field) => Object.hasOwn(input, field)).map((field) => [field,
    field === 'excluded_route_ids' ? [...input[field]].sort() : input[field]]);
}

function fingerprint(input) {
  return createHash('sha256').update(JSON.stringify(canonical(input))).digest('hex');
}

/** Read-only review of two validated policies. No active policy or runtime state is changed. */
export function diffPolicies(beforeInput, afterInput) {
  const before = validate(beforeInput);
  const after = validate(afterInput);
  if (before.schema_version !== after.schema_version) {
    throw new TypeError('policy schema migration requires a separate review');
  }
  if (before.application_id !== after.application_id) {
    throw new TypeError('application_id cannot change in a policy revision');
  }
  if (before.policy_id !== after.policy_id) {
    throw new TypeError('policy_id cannot change in a policy revision');
  }
  const beforeFields = new Map(canonical(before));
  const afterFields = new Map(canonical(after));
  const changes = FIELDS.filter((field) => JSON.stringify(beforeFields.get(field)) !== JSON.stringify(afterFields.get(field)))
    .map((field) => ({ field, before: beforeFields.get(field) ?? null, after: afterFields.get(field) ?? null }));
  const reviewReasons = [];
  if (before.mode === 'OBSERVE' && after.mode === 'ENFORCE') reviewReasons.push('enforcement_enabled');
  if (before.threshold > after.threshold) reviewReasons.push('threshold_lowered');
  if (before.window_seconds < after.window_seconds) reviewReasons.push('observation_window_extended');
  if (before.restriction_seconds < after.restriction_seconds) reviewReasons.push('restriction_extended');
  if (before.action === 'THROTTLE' && after.action === 'DENY') reviewReasons.push('response_strengthened');
  if (before.route_id !== '*' && after.route_id === '*') reviewReasons.push('route_scope_broadened');
  if (before.schema_version === 2 && after.schema_version === 2) {
    if (before.excluded_route_ids.some((route) => !after.excluded_route_ids.includes(route))) {
      reviewReasons.push('route_exclusion_removed');
    }
    if (before.identity_scope !== after.identity_scope) reviewReasons.push('identity_scope_changed');
  }
  return {
    schema_version: 1,
    policy_schema_version: before.schema_version,
    application_id: before.application_id,
    policy_id: before.policy_id,
    before_fingerprint_sha256: fingerprint(before),
    after_fingerprint_sha256: fingerprint(after),
    changed: changes.length > 0,
    changes,
    review_reasons: reviewReasons,
    activation: 'none',
  };
}
