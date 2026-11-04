import { validateIdentityObservationV2, validateIdentityPolicyV2, createIdentityGuardV2 } from "./identity-policy.mjs";

const routePattern = /^[a-z][a-z0-9._-]{1,63}$/;

/** Route precedence: one exact policy wins over the one optional wildcard policy. */
export function createIdentityPolicySetV2({ policies: policyInputs, canActOnSource, onDecision = () => {}, now = Date.now,
  maxSeenEvents = 50_000, maxIdentitiesPerPolicy = 1_000, maxObservationsPerPolicy = 10_000 } = {}) {
  if (!Array.isArray(policyInputs) || policyInputs.length < 1 || policyInputs.length > 16) {
    throw new RangeError("policies must contain 1-16 entries");
  }
  if (typeof now !== "function" || typeof onDecision !== "function") throw new TypeError("callbacks must be functions");
  if (!Number.isSafeInteger(maxSeenEvents) || maxSeenEvents < 1 || maxSeenEvents > 100_000) {
    throw new RangeError("maxSeenEvents must be 1-100000");
  }
  const policies = Object.freeze(policyInputs.map(validateIdentityPolicyV2));
  if (maxSeenEvents < Math.max(...policies.map((policy) => policy.threshold))) {
    throw new RangeError("maxSeenEvents must meet every policy threshold");
  }
  const applicationId = policies[0].application_id;
  const routes = new Map();
  const byId = new Map();
  let wildcard;
  for (const policy of policies) {
    if (policy.application_id !== applicationId || byId.has(policy.policy_id)) {
      throw new TypeError("policies require one application ID and distinct policy IDs");
    }
    if (policy.route_id === "*") {
      if (wildcard) throw new TypeError("only one wildcard policy is allowed");
      wildcard = policy;
    } else {
      if (routes.has(policy.route_id)) throw new TypeError("only one policy per exact route is allowed");
      routes.set(policy.route_id, policy);
    }
    byId.set(policy.policy_id, createIdentityGuardV2({ policy, canActOnSource, onDecision, now,
      maxIdentities: maxIdentitiesPerPolicy, maxObservations: maxObservationsPerPolicy }));
  }

  const seen = new Map();
  const longestWindowMs = Math.max(...policies.map((policy) => policy.window_seconds)) * 1000;

  function select(routeId) {
    if (typeof routeId !== "string" || !routePattern.test(routeId)) throw new TypeError("verified routeId is required");
    const exact = routes.get(routeId);
    if (exact) return exact;
    return wildcard && !wildcard.excluded_route_ids.includes(routeId) ? wildcard : undefined;
  }

  function record(input, identity) {
    const observation = validateIdentityObservationV2(input);
    if (observation.application_id !== applicationId) return { accepted: false, reason: "policy_mismatch" };
    const policy = select(observation.route_id);
    if (!policy || observation.reason_code !== policy.reason_code) return { accepted: false, reason: "policy_mismatch" };
    const at = now();
    if (!Number.isSafeInteger(at)) throw new TypeError("now must return epoch milliseconds");
    for (const [eventId, observedAt] of seen) if (observedAt <= at - longestWindowMs) seen.delete(eventId);
    if (seen.has(observation.event_id)) return { accepted: false, reason: "duplicate_event" };
    if (seen.size >= maxSeenEvents) return { accepted: false, reason: "capacity_exhausted" };
    const result = byId.get(policy.policy_id).record(observation, identity);
    if (result.accepted) seen.set(observation.event_id, Date.parse(observation.observed_at));
    return result;
  }

  function restriction({ sourceIp, identity, routeId } = {}) {
    const policy = select(routeId);
    return policy ? byId.get(policy.policy_id).restriction({ sourceIp, identity, routeId }) : null;
  }

  function release({ policyId, sourceIp, identity } = {}) {
    const guard = byId.get(policyId);
    if (!guard) throw new TypeError("known policyId is required for release");
    return guard.release({ sourceIp, identity });
  }

  function snapshot() {
    return [...byId.values()].flatMap((guard) => guard.snapshot());
  }

  return Object.freeze({ policies, matches: (routeId) => Boolean(select(routeId)), record, restriction,
    isBlocked: (context) => restriction(context) !== null, release, snapshot });
}
