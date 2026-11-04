import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { isEligibleSource } from "./guard-core.mjs";
import { validateObservationV1, validatePolicyV1 } from "./policy.mjs";

const trustedIdentities = new WeakMap();
const scopes = new Set(["source_ip", "subject_id", "tenant_id", "api_key_id"]);
const identifier = /^[a-z][a-z0-9._-]{1,63}$/;

function boundedString(value, name) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value) > 128 || value !== value.trim() || /[\x00-\x1f\x7f]/.test(value)) {
    throw new TypeError(`${name} must be a nonempty, bounded identifier`);
  }
  return value;
}

/** Build this object only after application authentication; it cannot be reconstructed from JSON. */
export function createVerifiedIdentity(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !["subjectId", "tenantId", "apiKeyId"].includes(key))) {
    throw new TypeError("verified identity must contain only subjectId, tenantId, or apiKeyId");
  }
  const { subjectId, tenantId, apiKeyId } = input;
  const values = {};
  for (const [field, value] of [["subject_id", subjectId], ["tenant_id", tenantId], ["api_key_id", apiKeyId]]) {
    if (value !== undefined) values[field] = boundedString(value, field);
  }
  if (Object.keys(values).length === 0) throw new TypeError("at least one verified identity is required");
  const identity = Object.freeze({ verified: true });
  trustedIdentities.set(identity, Object.freeze(values));
  return identity;
}

export function validateIdentityPolicyV2(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("policy must be an object");
  const { identity_scope: scope, excluded_route_ids: excluded = [], ...base } = input;
  if (input.schema_version !== 2) throw new TypeError("unsupported policy schema_version");
  if (!scopes.has(scope)) throw new TypeError("unknown identity_scope");
  if (!Array.isArray(excluded) || excluded.length > 32 || excluded.some((route) => typeof route !== "string" || !identifier.test(route)) || new Set(excluded).size !== excluded.length) {
    throw new TypeError("excluded_route_ids must contain at most 32 distinct route IDs");
  }
  const route = input.route_id;
  if (route !== "*" && excluded.length) throw new TypeError("route exclusions require route_id *");
  validatePolicyV1({ ...base, route_id: route === "*" ? "all.routes" : route, schema_version: 1 });
  return Object.freeze({ ...input, excluded_route_ids: Object.freeze([...excluded]) });
}

export function validateIdentityObservationV2(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || input.schema_version !== 2) {
    throw new TypeError("unsupported observation schema_version");
  }
  validateObservationV1({ ...input, schema_version: 1 });
  return Object.freeze({ ...input, source_ip: normalizeEligibleIp(input.source_ip) });
}

/** Pure simulation. Non-IP scopes accept synthetic fixture IDs only. */
export function simulateIdentityPolicyV2(policyInput, entries, { at } = {}) {
  const policy = validateIdentityPolicyV2(policyInput);
  if (!Array.isArray(entries) || entries.length > 10_000) throw new RangeError("entries must contain at most 10000 fixtures");
  if (typeof at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(at) ||
      !Number.isFinite(Date.parse(at))) throw new TypeError("at must be an ISO 8601 UTC timestamp");
  const atMs = Date.parse(at);
  if (new Date(atMs).toISOString() !== at.replace(/(?:\.(\d{1,3}))?Z$/, (_match, fraction) => `.${(fraction ?? "").padEnd(3, "0")}Z`)) {
    throw new TypeError("at must be a valid UTC timestamp");
  }
  const counts = new Map();
  const seenIds = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) ||
        Object.keys(entry).some((key) => !["observation", "fixture_identity"].includes(key))) {
      throw new TypeError("each fixture must contain an observation and optional fixture_identity");
    }
    const observation = validateIdentityObservationV2(entry.observation);
    const fixture = entry.fixture_identity;
    if (policy.identity_scope === "source_ip") {
      if (fixture !== undefined) throw new TypeError("source_ip simulation must not supply fixture_identity");
    } else if (typeof fixture !== "string" || !/^fixture:[A-Za-z0-9_-]{1,64}$/.test(fixture)) {
      throw new TypeError("identity simulation requires a synthetic fixture_identity");
    }
    const observedMs = Date.parse(observation.observed_at);
    if (observedMs > atMs) throw new RangeError("observation occurs after simulation time");
    if (observation.application_id !== policy.application_id || observation.reason_code !== policy.reason_code ||
        (policy.route_id !== "*" && observation.route_id !== policy.route_id) ||
        policy.excluded_route_ids.includes(observation.route_id) ||
        observedMs <= atMs - policy.window_seconds * 1000 || seenIds.has(observation.event_id)) continue;
    seenIds.add(observation.event_id);
    const identityRef = policy.identity_scope === "source_ip" ? observation.source_ip : fixture;
    counts.set(identityRef, (counts.get(identityRef) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([identityRef, count]) => {
    const triggered = count >= policy.threshold;
    return { policy_id: policy.policy_id, identity_scope: policy.identity_scope, identity_ref: identityRef,
      hit_count: count, decision: !triggered ? "NONE" : policy.mode === "OBSERVE" ? "OBSERVE" : policy.action,
      restriction_expires_at: triggered && policy.mode === "ENFORCE"
        ? new Date(atMs + policy.restriction_seconds * 1000).toISOString() : null };
  });
}

function normalizeEligibleIp(sourceIp) {
  if (!isEligibleSource(sourceIp)) return null;
  return isIP(sourceIp) === 6 ? new URL(`http://[${sourceIp}]/`).hostname.slice(1, -1) : sourceIp;
}

function positive(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new RangeError(`${name} must be 1-${maximum}`);
}

/** One policy and one process. Identity values stay in application memory, not in audit output. */
export function createIdentityGuardV2({ policy: policyInput, canActOnSource, onDecision = () => {}, now = Date.now,
  maxIdentities = 20_000, maxObservations = 50_000 } = {}) {
  const policy = validateIdentityPolicyV2(policyInput);
  if (policy.mode === "ENFORCE" && typeof canActOnSource !== "function") throw new TypeError("ENFORCE requires canActOnSource");
  if (canActOnSource !== undefined && typeof canActOnSource !== "function") throw new TypeError("canActOnSource must be a function");
  if (typeof onDecision !== "function" || typeof now !== "function") throw new TypeError("callbacks must be functions");
  positive(maxIdentities, "maxIdentities", 100_000);
  positive(maxObservations, "maxObservations", 100_000);
  if (maxObservations < policy.threshold) throw new RangeError("maxObservations must meet the policy threshold");

  const secret = randomBytes(32);
  const state = new Map();
  const seenIds = new Map();
  const windowMs = policy.window_seconds * 1000;
  const restrictionMs = policy.restriction_seconds * 1000;

  function sourceAllowed(sourceIp) {
    const normalized = normalizeEligibleIp(sourceIp);
    if (!normalized) return false;
    try { return (canActOnSource ?? (() => true))(normalized) === true; }
    catch { return false; }
  }

  function keyFor(sourceIp, identity) {
    if (policy.identity_scope === "source_ip") return `source_ip:${sourceIp}`;
    const values = trustedIdentities.get(identity);
    if (!values || !values[policy.identity_scope]) throw new TypeError(`verified ${policy.identity_scope} is required`);
    const digest = createHmac("sha256", secret).update(`${policy.application_id}\0${policy.identity_scope}\0${values[policy.identity_scope]}`).digest("hex");
    return `${policy.identity_scope}:${digest}`;
  }

  function routeEligible(routeId) {
    if (typeof routeId !== "string" || !identifier.test(routeId)) throw new TypeError("verified routeId is required");
    return (policy.route_id === "*" || policy.route_id === routeId) && !policy.excluded_route_ids.includes(routeId);
  }

  function prune(at) {
    for (const [id, seenAt] of seenIds) if (seenAt <= at - windowMs) seenIds.delete(id);
    for (const [key, entry] of state) {
      for (const [id, seenAt] of entry.hits) if (seenAt <= at - windowMs) entry.hits.delete(id);
      if (entry.hits.size === 0 && entry.restrictionUntil <= at && entry.reportedUntil <= at) state.delete(key);
    }
  }

  function record(input, identity) {
    const observation = validateIdentityObservationV2(input);
    if (observation.application_id !== policy.application_id || observation.reason_code !== policy.reason_code ||
        (policy.route_id !== "*" && observation.route_id !== policy.route_id) || policy.excluded_route_ids.includes(observation.route_id)) {
      return { accepted: false, reason: "policy_mismatch" };
    }
    if (!sourceAllowed(observation.source_ip)) return { accepted: false, reason: "source_excluded" };
    const key = keyFor(observation.source_ip, identity);
    const at = now();
    if (!Number.isSafeInteger(at)) throw new TypeError("now must return epoch milliseconds");
    const observedAt = Date.parse(observation.observed_at);
    if (observedAt <= at - windowMs || observedAt > at + 5000) return { accepted: false, reason: "outside_window" };
    if ((seenIds.get(observation.event_id) ?? 0) > at - windowMs) return { accepted: false, reason: "duplicate_event" };
    if (seenIds.size >= maxObservations || state.size >= maxIdentities) prune(at);
    if (seenIds.size >= maxObservations || (!state.has(key) && state.size >= maxIdentities)) return { accepted: false, reason: "capacity_exhausted" };
    const entry = state.get(key) ?? { hits: new Map(), restrictionUntil: 0, reportedUntil: 0 };
    state.set(key, entry);
    for (const [id, seenAt] of entry.hits) if (seenAt <= at - windowMs) entry.hits.delete(id);
    if (entry.hits.size >= policy.threshold) entry.hits.delete(entry.hits.keys().next().value);
    entry.hits.set(observation.event_id, observedAt);
    seenIds.set(observation.event_id, observedAt);
    if (entry.hits.size < policy.threshold || entry.reportedUntil > at) return { accepted: true, action: "recorded" };
    entry.reportedUntil = at + windowMs;
    if (policy.mode === "ENFORCE") entry.restrictionUntil = at + restrictionMs;
    const decision = Object.freeze({ schema_version: 2, policy_id: policy.policy_id,
      application_id: policy.application_id, route_id: observation.route_id, reason_code: policy.reason_code,
      identity_scope: policy.identity_scope, identity_ref: key, source_ip: observation.source_ip,
      action: policy.mode === "OBSERVE" ? "OBSERVE" : policy.action, hit_count: entry.hits.size,
      observed_at: new Date(at).toISOString(), restriction_expires_at: policy.mode === "ENFORCE" ? new Date(entry.restrictionUntil).toISOString() : null });
    Promise.resolve().then(() => onDecision(decision)).catch(() => {});
    return { accepted: true, action: decision.action, decision };
  }

  function restriction({ sourceIp, identity, routeId } = {}) {
    if (!routeEligible(routeId) || policy.mode !== "ENFORCE" || !sourceAllowed(sourceIp)) return null;
    const key = keyFor(normalizeEligibleIp(sourceIp), identity);
    const entry = state.get(key);
    const at = now();
    if (!entry || entry.restrictionUntil <= at) return null;
    return { action: policy.action, policyId: policy.policy_id, identityScope: policy.identity_scope,
      expiresAt: new Date(entry.restrictionUntil).toISOString(), retryAfterSeconds: Math.ceil((entry.restrictionUntil - at) / 1000) };
  }

  function release({ sourceIp, identity } = {}) {
    const normalized = normalizeEligibleIp(sourceIp);
    if (!normalized) return 0;
    return Number(state.delete(keyFor(normalized, identity)));
  }

  function snapshot() {
    const at = now();
    prune(at);
    if (policy.mode !== "ENFORCE") return [];
    return [...state.entries()].filter(([key, entry]) => entry.restrictionUntil > at &&
      (policy.identity_scope !== "source_ip" || sourceAllowed(key.slice("source_ip:".length)))).map(([key, entry]) => ({
      identity_scope: policy.identity_scope, identity_ref: key, action: policy.action,
      expires_at: new Date(entry.restrictionUntil).toISOString(), policy_id: policy.policy_id,
    }));
  }

  return Object.freeze({ policy, record, restriction, isBlocked: (context) => restriction(context) !== null, release, snapshot });
}
