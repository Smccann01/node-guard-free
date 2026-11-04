/** Check one Next.js App Router Route Handler request in the Node.js runtime. */
export function createNextRouteGuard({ guard, getVerifiedSourceIp } = {}) {
  if (!guard || typeof guard.restriction !== "function") {
    throw new TypeError("guard must provide restriction(sourceIp)");
  }
  if (typeof getVerifiedSourceIp !== "function") {
    throw new TypeError("getVerifiedSourceIp must be a function");
  }

  return async function checkRoute(request) {
    try {
      const sourceIp = await getVerifiedSourceIp(request);
      if (typeof sourceIp !== "string" || sourceIp.length === 0) {
        throw new TypeError("trusted ingress did not provide a verified source IP");
      }
      const restriction = guard.restriction(sourceIp);
      if (!restriction) return null;
      return Response.json({ error: "node_guard_restricted" }, {
        status: restriction.action === "DENY" ? 403 : 429,
        headers: { "Retry-After": String(restriction.retryAfterSeconds), "Cache-Control": "no-store" },
      });
    } catch {
      return Response.json({ error: "verified_source_unavailable" }, {
        status: 503, headers: { "Cache-Control": "no-store" },
      });
    }
  };
}
