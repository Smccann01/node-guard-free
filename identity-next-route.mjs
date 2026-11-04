/** Check an identity-scoped policy in a Node.js App Router Route Handler. */
export function createNextIdentityGuardV2({ guard, getVerifiedSourceIp, getVerifiedIdentity, getRouteId } = {}) {
  if (!guard || guard.policy?.schema_version !== 2 || typeof guard.restriction !== "function") {
    throw new TypeError("guard must be an identity policy v2 runtime");
  }
  if (typeof getVerifiedSourceIp !== "function" || typeof getRouteId !== "function" ||
      (guard.policy.identity_scope !== "source_ip" && typeof getVerifiedIdentity !== "function")) {
    throw new TypeError("trusted source and identity callbacks are required");
  }
  return async function checkRoute(request) {
    try {
      const routeId = await getRouteId(request);
      if (guard.policy.excluded_route_ids?.includes(routeId) ||
          (guard.policy.route_id !== "*" && guard.policy.route_id !== routeId)) return null;
      const sourceIp = await getVerifiedSourceIp(request);
      const identity = await getVerifiedIdentity?.(request);
      const active = guard.restriction({ sourceIp, identity, routeId });
      if (!active) return null;
      return Response.json({ error: "node_guard_restricted" }, { status: active.action === "DENY" ? 403 : 429,
        headers: { "Retry-After": String(active.retryAfterSeconds), "Cache-Control": "no-store" } });
    } catch {
      return Response.json({ error: "verified_context_unavailable" }, { status: 503,
        headers: { "Cache-Control": "no-store" } });
    }
  };
}
