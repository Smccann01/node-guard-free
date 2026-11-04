/** Next.js Node Route Handler check for a route-aware identity policy set. */
export function createNextIdentityPolicySetV2({ policySet, getVerifiedSourceIp, getVerifiedIdentity, getRouteId } = {}) {
  if (!policySet || typeof policySet.matches !== "function" || typeof policySet.restriction !== "function" ||
      !Array.isArray(policySet.policies) || policySet.policies.some((policy) => policy.schema_version !== 2)) {
    throw new TypeError("policySet must be a v2 identity policy set");
  }
  if (typeof getVerifiedSourceIp !== "function" || typeof getRouteId !== "function" ||
      (policySet.policies.some((policy) => policy.identity_scope !== "source_ip") && typeof getVerifiedIdentity !== "function")) {
    throw new TypeError("trusted source, route, and identity callbacks are required");
  }
  return async function checkRoute(request) {
    try {
      const routeId = await getRouteId(request);
      if (!policySet.matches(routeId)) return null;
      const sourceIp = await getVerifiedSourceIp(request);
      const identity = await getVerifiedIdentity?.(request);
      const active = policySet.restriction({ sourceIp, identity, routeId });
      if (!active) return null;
      return Response.json({ error: "node_guard_restricted" }, { status: active.action === "DENY" ? 403 : 429,
        headers: { "Retry-After": String(active.retryAfterSeconds), "Cache-Control": "no-store" } });
    } catch {
      return Response.json({ error: "verified_context_unavailable" }, { status: 503,
        headers: { "Cache-Control": "no-store" } });
    }
  };
}
