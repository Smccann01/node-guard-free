/** Express adapter for a Guard instance and an application-verified source. */
export function createExpressNodeGuard({ guard, getVerifiedSourceIp } = {}) {
  if (!guard || typeof guard.restriction !== "function") {
    throw new TypeError("guard must provide restriction(sourceIp)");
  }
  if (typeof getVerifiedSourceIp !== "function") {
    throw new TypeError("getVerifiedSourceIp must be a function");
  }

  return function nodeGuardMiddleware(req, res, next) {
    try {
      const sourceIp = getVerifiedSourceIp(req);
      if (typeof sourceIp !== "string" || sourceIp.length === 0) {
        throw new TypeError("trusted ingress did not provide a verified source IP");
      }
      const restriction = guard.restriction(sourceIp);
      if (!restriction) return next();
      res.set("Retry-After", String(restriction.retryAfterSeconds));
      return res.status(restriction.action === "DENY" ? 403 : 429).json({ error: "node_guard_restricted" });
    } catch (error) {
      return next(error);
    }
  };
}
