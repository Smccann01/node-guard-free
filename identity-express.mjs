/** Express adapter for an identity-scoped policy. Authentication remains in the application. */
export function createExpressIdentityGuardV2({ guard, getVerifiedSourceIp, getVerifiedIdentity, getRouteId } = {}) {
  if (!guard || guard.policy?.schema_version !== 2 || typeof guard.restriction !== "function") {
    throw new TypeError("guard must be an identity policy v2 runtime");
  }
  if (typeof getVerifiedSourceIp !== "function" || typeof getRouteId !== "function" ||
      (guard.policy.identity_scope !== "source_ip" && typeof getVerifiedIdentity !== "function")) {
    throw new TypeError("trusted source and identity callbacks are required");
  }
  return function identityGuardMiddleware(request, response, next) {
    try {
      const routeId = getRouteId(request);
      if (guard.policy.excluded_route_ids?.includes(routeId) ||
          (guard.policy.route_id !== "*" && guard.policy.route_id !== routeId)) return next();
      const sourceIp = getVerifiedSourceIp(request);
      const identity = getVerifiedIdentity?.(request);
      const active = guard.restriction({ sourceIp, identity, routeId });
      if (!active) return next();
      response.set("Retry-After", String(active.retryAfterSeconds));
      return response.status(active.action === "DENY" ? 403 : 429).json({ error: "node_guard_restricted" });
    } catch (error) {
      return next(error);
    }
  };
}
