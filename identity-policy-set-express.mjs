/** Express adapter for a route-aware identity policy set. */
export function createExpressIdentityPolicySetV2({ policySet, getVerifiedSourceIp, getVerifiedIdentity, getRouteId } = {}) {
  if (!policySet || typeof policySet.matches !== "function" || typeof policySet.restriction !== "function" ||
      !Array.isArray(policySet.policies) || policySet.policies.some((policy) => policy.schema_version !== 2)) {
    throw new TypeError("policySet must be a v2 identity policy set");
  }
  if (typeof getVerifiedSourceIp !== "function" || typeof getRouteId !== "function" ||
      (policySet.policies.some((policy) => policy.identity_scope !== "source_ip") && typeof getVerifiedIdentity !== "function")) {
    throw new TypeError("trusted source, route, and identity callbacks are required");
  }
  return function identityPolicySetMiddleware(request, response, next) {
    try {
      const routeId = getRouteId(request);
      if (!policySet.matches(routeId)) return next();
      const sourceIp = getVerifiedSourceIp(request);
      const identity = getVerifiedIdentity?.(request);
      const active = policySet.restriction({ sourceIp, identity, routeId });
      if (!active) return next();
      response.set("Retry-After", String(active.retryAfterSeconds));
      return response.status(active.action === "DENY" ? 403 : 429).json({ error: "node_guard_restricted" });
    } catch (error) {
      return next(error);
    }
  };
}
