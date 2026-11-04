/** Express middleware for an application-scoped local coordinator client. */
export function createLocalExpressNodeGuard({ client, getVerifiedSourceIp, getVerifiedRouteId } = {}) {
  if (!client || typeof client.evaluate !== 'function') throw new TypeError('client must provide evaluate(sourceIp, routeId)');
  if (typeof getVerifiedSourceIp !== 'function') throw new TypeError('getVerifiedSourceIp must be a function');
  if (typeof getVerifiedRouteId !== 'function') throw new TypeError('getVerifiedRouteId must be a function');

  return async function localNodeGuardMiddleware(request, response, next) {
    try {
      const sourceIp = getVerifiedSourceIp(request);
      const routeId = getVerifiedRouteId(request);
      const result = await client.evaluate(sourceIp, routeId);
      if (!result || !['ALLOW', 'THROTTLE', 'DENY'].includes(result.decision) ||
          (result.decision === 'ALLOW' && result.restriction != null) ||
          (result.decision !== 'ALLOW' && (!Number.isSafeInteger(result.restriction?.retry_after_seconds) ||
            result.restriction.retry_after_seconds < 1 || result.restriction.retry_after_seconds > 300))) {
        throw new Error('invalid coordinator decision');
      }
      if (result.decision === 'ALLOW') return next();
      response.set('Cache-Control', 'no-store');
      response.set('Retry-After', String(result.restriction.retry_after_seconds));
      return response.status(result.decision === 'DENY' ? 403 : 429).json({ error: 'node_guard_restricted' });
    } catch {
      response.set('Cache-Control', 'no-store');
      return response.status(503).json({ error: 'node_guard_unavailable' });
    }
  };
}
