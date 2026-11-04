import { createHash, createHmac, randomBytes } from 'node:crypto';
import { normalizeEligibleSource } from './guard-core.mjs';
import { validateObservationV1, validatePolicyV1 } from './policy.mjs';
import { createPolicyGuardV1 } from './policy-runtime.mjs';
import { createIdentityGuardV2, createVerifiedIdentity, validateIdentityObservationV2, validateIdentityPolicyV2 } from './identity-policy.mjs';

const MAX_EVENTS = 10_000;
const MAX_PROTECTED_SOURCES = 256;
const POLICY_FIELDS = ['schema_version', 'policy_id', 'application_id', 'mode', 'route_id',
  'reason_code', 'window_seconds', 'threshold', 'action', 'restriction_seconds',
  'identity_scope', 'excluded_route_ids'];

function policyFingerprint(policy) {
  const canonical = POLICY_FIELDS.filter((field) => Object.hasOwn(policy, field)).map((field) => [field,
    field === 'excluded_route_ids' ? [...policy[field]].sort() : policy[field]]);
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function protectedSetFrom(input) {
  if (!Array.isArray(input) || input.length > MAX_PROTECTED_SOURCES ||
      input.some((ip) => !normalizeEligibleSource(ip)) ||
      new Set(input.map(normalizeEligibleSource)).size !== input.length) {
    throw new TypeError('protectedSources must contain at most 256 distinct eligible public IPs');
  }
  return new Set(input.map(normalizeEligibleSource));
}

function sourceFormatter(redactSources) {
  if (typeof redactSources !== 'boolean') throw new TypeError('redactSources must be a boolean');
  const key = redactSources ? randomBytes(32) : null;
  return (sourceIp) => key
    ? { source_ref: `source-${createHmac('sha256', key).update(sourceIp).digest('hex').slice(0, 24)}` }
    : { source_ip: sourceIp };
}

function utcMilliseconds(value, name) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) {
    throw new TypeError(`${name} must be an ISO 8601 UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError(`${name} must be a valid UTC timestamp`);
  const canonical = value.replace(/(?:\.(\d{1,3}))?Z$/, (_match, fraction) =>
    `.${(fraction ?? '').padEnd(3, '0')}Z`);
  if (new Date(milliseconds).toISOString() !== canonical) throw new TypeError(`${name} must be a valid UTC timestamp`);
  return milliseconds;
}

/** Replays v1 observations in memory. Never opens a socket or applies host enforcement. */
export function replayPolicyV1({ policy: inputPolicy, observations, at, protectedSources = [], redactSources = false } = {}) {
  const policy = validatePolicyV1(inputPolicy);
  if (!Array.isArray(observations) || observations.length > MAX_EVENTS) {
    throw new RangeError(`observations must be an array of at most ${MAX_EVENTS} events`);
  }
  const replayAt = utcMilliseconds(at, 'at');
  const protectedSet = protectedSetFrom(protectedSources);
  const sourceField = sourceFormatter(redactSources);
  let now = replayAt;
  let previousTime = -Infinity;
  const guard = createPolicyGuardV1({ policy, now: () => now,
    canActOnSource: (sourceIp) => !protectedSet.has(sourceIp),
    maxObservations: Math.max(50_000, policy.threshold) });
  const timeline = [];

  for (const input of observations) {
    const observation = validateObservationV1(input);
    const eventTime = utcMilliseconds(observation.observed_at, 'observed_at');
    if (eventTime < previousTime) throw new RangeError('observations must be ordered by observed_at');
    if (eventTime > replayAt) throw new RangeError('observation occurs after replay time');
    previousTime = eventTime;
    now = eventTime;
    const result = guard.record(observation);
    const restriction = guard.restriction(observation.source_ip);
    timeline.push({
      event_id: observation.event_id,
      observed_at: observation.observed_at,
      ...sourceField(observation.source_ip),
      accepted: result.accepted,
      record_action: result.accepted ? result.action : 'REJECTED',
      trigger_hit_count: result.decision?.hit_count ?? null,
      ...(result.accepted ? {} : { rejection_reason: result.reason }),
      effective_action: restriction?.action ?? 'ALLOW',
      restriction_expires_at: restriction?.expiresAt ?? null,
    });
  }

  now = replayAt;
  const activeRestrictions = guard.snapshot().map((entry) => ({
    ...sourceField(entry.sourceIp),
    action: entry.action,
    expires_at: entry.expiresAt,
  })).sort((a, b) => (a.source_ref ?? a.source_ip).localeCompare(b.source_ref ?? b.source_ip));
  return {
    schema_version: 1,
    policy_id: policy.policy_id,
    application_id: policy.application_id,
    policy_fingerprint_sha256: policyFingerprint(policy),
    policy_mode: policy.mode,
    replay_at: new Date(replayAt).toISOString(),
    event_count: timeline.length,
    source_representation: redactSources ? 'pseudonym' : 'ip',
    timeline,
    active_restrictions: activeRestrictions,
    enforcement_scope: 'simulation_only',
  };
}

/** Replays v2 synthetic identity fixtures through the in-memory v2 guard. */
export function replayIdentityPolicyV2({ policy: inputPolicy, entries, at, protectedSources = [], redactSources = false } = {}) {
  const policy = validateIdentityPolicyV2(inputPolicy);
  if (!Array.isArray(entries) || entries.length > MAX_EVENTS) {
    throw new RangeError(`entries must be an array of at most ${MAX_EVENTS} fixtures`);
  }
  const replayAt = utcMilliseconds(at, 'at');
  const protectedSet = protectedSetFrom(protectedSources);
  const sourceField = sourceFormatter(redactSources);
  let now = replayAt;
  let previousTime = -Infinity;
  const guard = createIdentityGuardV2({ policy, now: () => now,
    canActOnSource: (sourceIp) => !protectedSet.has(sourceIp),
    maxObservations: Math.max(50_000, policy.threshold) });
  const timeline = [];
  const identityLabels = new Map();

  for (const input of entries) {
    if (!input || typeof input !== 'object' || Array.isArray(input) ||
        Object.keys(input).some((key) => !['observation', 'fixture_identity'].includes(key))) {
      throw new TypeError('each fixture must contain observation and optional fixture_identity');
    }
    const observation = validateIdentityObservationV2(input.observation);
    const fixture = input.fixture_identity;
    if (policy.identity_scope === 'source_ip') {
      if (fixture !== undefined) throw new TypeError('source_ip replay must not supply fixture_identity');
    } else if (typeof fixture !== 'string' || !/^fixture:[A-Za-z0-9_-]{1,64}$/.test(fixture)) {
      throw new TypeError('identity replay requires a synthetic fixture_identity');
    }
    const eventTime = utcMilliseconds(observation.observed_at, 'observed_at');
    if (eventTime < previousTime) throw new RangeError('entries must be ordered by observed_at');
    if (eventTime > replayAt) throw new RangeError('observation occurs after replay time');
    previousTime = eventTime;
    now = eventTime;
    const identity = fixture === undefined ? undefined : createVerifiedIdentity({
      [{ subject_id: 'subjectId', tenant_id: 'tenantId', api_key_id: 'apiKeyId' }[policy.identity_scope]]: fixture,
    });
    const result = guard.record(observation, identity);
    if (result.decision && fixture !== undefined) identityLabels.set(result.decision.identity_ref, fixture);
    const restriction = guard.restriction({ sourceIp: observation.source_ip,
      routeId: observation.route_id, identity });
    timeline.push({
      event_id: observation.event_id,
      observed_at: observation.observed_at,
      ...sourceField(observation.source_ip),
      identity_scope: policy.identity_scope,
      identity_ref: fixture ?? (sourceField(observation.source_ip).source_ref ?? observation.source_ip),
      accepted: result.accepted,
      record_action: result.accepted ? result.action : 'REJECTED',
      trigger_hit_count: result.decision?.hit_count ?? null,
      ...(result.accepted ? {} : { rejection_reason: result.reason }),
      effective_action: restriction?.action ?? 'ALLOW',
      restriction_expires_at: restriction?.expiresAt ?? null,
    });
  }

  now = replayAt;
  const activeRestrictions = guard.snapshot().map((entry) => {
    const source = policy.identity_scope === 'source_ip'
      ? entry.identity_ref.slice('source_ip:'.length) : null;
    const label = source === null ? identityLabels.get(entry.identity_ref) :
      (sourceField(source).source_ref ?? source);
    if (!label) throw new Error('unmapped runtime identity in replay snapshot');
    return { identity_scope: policy.identity_scope, identity_ref: label,
      action: entry.action, expires_at: entry.expires_at };
  }).sort((a, b) => a.identity_ref.localeCompare(b.identity_ref));
  return {
    schema_version: 2,
    policy_id: policy.policy_id,
    application_id: policy.application_id,
    policy_fingerprint_sha256: policyFingerprint(policy),
    policy_mode: policy.mode,
    replay_at: new Date(replayAt).toISOString(),
    event_count: timeline.length,
    source_representation: redactSources ? 'pseudonym' : 'ip',
    timeline,
    active_restrictions: activeRestrictions,
    enforcement_scope: 'simulation_only',
  };
}
