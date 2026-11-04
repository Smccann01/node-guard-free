import { isEligibleSource } from "./guard-core.mjs";
import { validateObservationV1, validatePolicyV1 } from "./policy.mjs";

function boundedInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be 1-${maximum}`);
  }
  return value;
}

/** One policy, one application, one exact route. State is local to this process. */
export function createPolicyGuardV1({ policy: policyInput, canActOnSource, onDecision = () => {},
  now = Date.now, maxSources = 20_000, maxObservations = 50_000 } = {}) {
  const policy = validatePolicyV1(policyInput);
  if (policy.mode === "ENFORCE" && typeof canActOnSource !== "function") {
    throw new TypeError("ENFORCE requires canActOnSource");
  }
  if (canActOnSource !== undefined && typeof canActOnSource !== "function") throw new TypeError("canActOnSource must be a function");
  if (typeof onDecision !== "function" || typeof now !== "function") throw new TypeError("callbacks must be functions");
  boundedInteger(maxSources, "maxSources", 100_000);
  boundedInteger(maxObservations, "maxObservations", 100_000);
  if (maxObservations < policy.threshold) throw new RangeError("maxObservations must meet the policy threshold");
  const windowMs = policy.window_seconds * 1_000;
  const restrictionMs = policy.restriction_seconds * 1_000;
  const state = new Map();
  const seenIds = new Map();

  function allows(sourceIp) {
    try { return (canActOnSource ?? (() => true))(sourceIp) === true; }
    catch { return false; }
  }

  function pruneEntry(entry, at) {
    for (const [id, observedAt] of entry.hits) {
      if (observedAt <= at - windowMs) {
        entry.hits.delete(id);
      }
    }
  }

  function pruneSeen(at) {
    for (const [id, observedAt] of seenIds) {
      if (observedAt <= at - windowMs) seenIds.delete(id);
    }
  }

  function prune(at) {
    pruneSeen(at);
    for (const [sourceIp, entry] of state) {
      pruneEntry(entry, at);
      if (entry.hits.size === 0 && entry.restrictionUntil <= at && entry.reportedUntil <= at) state.delete(sourceIp);
    }
  }

  function record(input) {
    const observation = validateObservationV1(input);
    if (observation.application_id !== policy.application_id || observation.route_id !== policy.route_id ||
        observation.reason_code !== policy.reason_code) return { accepted: false, reason: "policy_mismatch" };
    if (!allows(observation.source_ip)) return { accepted: false, reason: "source_excluded" };
    const at = now();
    if (!Number.isSafeInteger(at)) throw new TypeError("now must return epoch milliseconds");
    const observedAt = Date.parse(observation.observed_at);
    if (observedAt <= at - windowMs || observedAt > at + 5_000) return { accepted: false, reason: "outside_window" };
    const prior = seenIds.get(observation.event_id);
    if (prior !== undefined && prior > at - windowMs) return { accepted: false, reason: "duplicate_event" };
    if (prior !== undefined) seenIds.delete(observation.event_id);
    if (seenIds.size >= maxObservations) pruneSeen(at);
    if (seenIds.size >= maxObservations) return { accepted: false, reason: "capacity_exhausted" };

    let entry = state.get(observation.source_ip);
    if (entry) pruneEntry(entry, at);
    if (!entry) {
      if (state.size >= maxSources) prune(at);
      if (state.size >= maxSources) return { accepted: false, reason: "capacity_exhausted" };
      entry = { hits: new Map(), restrictionUntil: 0, reportedUntil: 0 };
      state.set(observation.source_ip, entry);
    }
    if (entry.hits.size >= policy.threshold) {
      entry.hits.delete(entry.hits.keys().next().value);
    }
    entry.hits.set(observation.event_id, observedAt);
    seenIds.set(observation.event_id, observedAt);
    if (entry.hits.size < policy.threshold || entry.reportedUntil > at) return { accepted: true, action: "recorded" };

    entry.reportedUntil = at + windowMs;
    if (policy.mode === "ENFORCE") entry.restrictionUntil = at + restrictionMs;
    const decision = Object.freeze({
      schema_version: 1, policy_id: policy.policy_id, application_id: policy.application_id,
      route_id: policy.route_id, source_ip: observation.source_ip, reason_code: policy.reason_code,
      action: policy.mode === "OBSERVE" ? "OBSERVE" : policy.action,
      hit_count: entry.hits.size, observed_at: new Date(at).toISOString(),
      restriction_expires_at: policy.mode === "ENFORCE" ? new Date(entry.restrictionUntil).toISOString() : null,
    });
    Promise.resolve().then(() => onDecision(decision)).catch(() => {});
    return { accepted: true, action: decision.action, decision };
  }

  function restriction(sourceIp) {
    if (policy.mode !== "ENFORCE" || !isEligibleSource(sourceIp) || !allows(sourceIp)) return null;
    const at = now();
    const entry = state.get(sourceIp);
    if (!entry || entry.restrictionUntil <= at) return null;
    return {
      action: policy.action, policyId: policy.policy_id,
      expiresAt: new Date(entry.restrictionUntil).toISOString(),
      retryAfterSeconds: Math.ceil((entry.restrictionUntil - at) / 1_000),
    };
  }

  function release(sourceIp) {
    const entry = state.get(sourceIp);
    if (!entry) return 0;
    state.delete(sourceIp);
    return 1;
  }

  function snapshot() {
    const at = now();
    prune(at);
    if (policy.mode !== "ENFORCE") return [];
    return [...state.keys()].filter((sourceIp) => allows(sourceIp)).map((sourceIp) => {
      const active = restriction(sourceIp);
      return active ? { sourceIp, ...active } : null;
    }).filter(Boolean);
  }

  return Object.freeze({ policy, record, restriction, isBlocked: (sourceIp) => restriction(sourceIp) !== null, release, snapshot });
}
