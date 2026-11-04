import { createHash, createHmac, randomBytes } from 'node:crypto';
import { normalizeEligibleSource } from './guard-core.mjs';
import { validateObservationV1, validatePolicyV1 } from './policy.mjs';
import { createPolicyGuardV1 } from './policy-runtime.mjs';

const MAX_EVENTS = 10_000;
const MAX_PROTECTED_SOURCES = 256;
const POLICY_FIELDS = ['schema_version', 'policy_id', 'application_id', 'mode', 'route_id',
  'reason_code', 'window_seconds', 'threshold', 'action', 'restriction_seconds'];

function policyFingerprint(policy) {
  const canonical = POLICY_FIELDS.map((field) => [field, policy[field]]);
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
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
  if (typeof redactSources !== 'boolean') throw new TypeError('redactSources must be a boolean');
  if (!Array.isArray(observations) || observations.length > MAX_EVENTS) {
    throw new RangeError(`observations must be an array of at most ${MAX_EVENTS} events`);
  }
  if (!Array.isArray(protectedSources) || protectedSources.length > MAX_PROTECTED_SOURCES ||
      protectedSources.some((ip) => !normalizeEligibleSource(ip)) ||
      new Set(protectedSources.map(normalizeEligibleSource)).size !== protectedSources.length) {
    throw new TypeError('protectedSources must contain at most 256 distinct eligible public IPs');
  }
  const replayAt = utcMilliseconds(at, 'at');
  const protectedSet = new Set(protectedSources.map(normalizeEligibleSource));
  const redactionKey = redactSources ? randomBytes(32) : null;
  const sourceField = (sourceIp) => redactionKey
    ? { source_ref: `source-${createHmac('sha256', redactionKey).update(sourceIp).digest('hex').slice(0, 24)}` }
    : { source_ip: sourceIp };
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
