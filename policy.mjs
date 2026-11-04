import { isEligibleSource, REASON_CODES } from "./guard-core.mjs";

export const POLICY_REASON_CODES = Object.freeze([...REASON_CODES, "authentication_failure"]);
const POLICY_FIELDS = new Set(["schema_version", "policy_id", "application_id", "mode", "route_id", "reason_code", "window_seconds", "threshold", "action", "restriction_seconds"]);
const OBSERVATION_FIELDS = new Set(["schema_version", "application_id", "event_id", "observed_at", "route_id", "reason_code", "source_ip", "protocol"]);
const IDENTIFIER = /^[a-z][a-z0-9._-]{1,63}$/;
const EVENT_ID = /^[A-Za-z0-9_-]{8,128}$/;
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

function object(value, name, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  for (const key of Object.keys(value)) {
    if (!fields.has(key)) throw new TypeError(`${name} has unknown field ${key}`);
  }
}

function identifier(value, name) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError(`${name} must be a 2-64 character identifier`);
}

function integer(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${name} must be ${min}-${max}`);
}

function timestamp(value, name) {
  if (typeof value !== "string" || !UTC_TIME.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new TypeError(`${name} must be an ISO 8601 UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  const canonical = value.replace(/(?:\.(\d{1,3}))?Z$/, (_match, fraction) => `.${(fraction ?? "").padEnd(3, "0")}Z`);
  if (new Date(milliseconds).toISOString() !== canonical) throw new TypeError(`${name} must be a valid UTC timestamp`);
  return milliseconds;
}

export function validatePolicyV1(policy) {
  object(policy, "policy", POLICY_FIELDS);
  if (policy.schema_version !== 1) throw new TypeError("unsupported policy schema_version");
  identifier(policy.policy_id, "policy_id");
  identifier(policy.application_id, "application_id");
  identifier(policy.route_id, "route_id");
  if (!POLICY_REASON_CODES.includes(policy.reason_code)) throw new TypeError("unknown policy reason_code");
  if (policy.mode !== "OBSERVE" && policy.mode !== "ENFORCE") throw new TypeError("mode must be OBSERVE or ENFORCE");
  if (policy.action !== "THROTTLE" && policy.action !== "DENY") throw new TypeError("action must be THROTTLE or DENY");
  integer(policy.window_seconds, "window_seconds", 1, 300);
  integer(policy.threshold, "threshold", 2, 10_000);
  integer(policy.restriction_seconds, "restriction_seconds", 1, 300);
  return Object.freeze({ ...policy });
}

export function validateObservationV1(observation) {
  object(observation, "observation", OBSERVATION_FIELDS);
  if (observation.schema_version !== 1) throw new TypeError("unsupported observation schema_version");
  identifier(observation.application_id, "application_id");
  identifier(observation.route_id, "route_id");
  if (typeof observation.event_id !== "string" || !EVENT_ID.test(observation.event_id)) throw new TypeError("invalid event_id");
  timestamp(observation.observed_at, "observed_at");
  if (!POLICY_REASON_CODES.includes(observation.reason_code)) throw new TypeError("unknown observation reason_code");
  if (!isEligibleSource(observation.source_ip)) throw new TypeError("source_ip must be an eligible public IP");
  if (observation.protocol !== "HTTP" && observation.protocol !== "HTTPS") throw new TypeError("protocol must be HTTP or HTTPS");
  return Object.freeze({ ...observation });
}

/** Pure, source-scoped simulation. It does not install a live restriction. */
export function simulatePolicyV1(policyInput, observationInputs, { at } = {}) {
  const policy = validatePolicyV1(policyInput);
  if (!Array.isArray(observationInputs) || observationInputs.length > 10_000) {
    throw new RangeError("observations must be an array of at most 10000 events");
  }
  const atMs = timestamp(at, "at");
  const seen = new Set();
  const counts = new Map();
  for (const input of observationInputs) {
    const observation = validateObservationV1(input);
    const observedMs = Date.parse(observation.observed_at);
    if (observedMs > atMs) throw new RangeError("observation occurs after simulation time");
    if (observation.application_id !== policy.application_id ||
        observation.route_id !== policy.route_id || observation.reason_code !== policy.reason_code ||
        observedMs <= atMs - policy.window_seconds * 1_000) continue;
    if (seen.has(observation.event_id)) continue;
    seen.add(observation.event_id);
    counts.set(observation.source_ip, (counts.get(observation.source_ip) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([sourceIp, hitCount]) => {
    const triggered = hitCount >= policy.threshold;
    return {
      policy_id: policy.policy_id, source_ip: sourceIp, hit_count: hitCount,
      decision: !triggered ? "NONE" : policy.mode === "OBSERVE" ? "OBSERVE" : policy.action,
      restriction_expires_at: triggered && policy.mode === "ENFORCE"
        ? new Date(atMs + policy.restriction_seconds * 1_000).toISOString() : null,
    };
  });
}
