# Next.js Route Handler integration

Use Node Guard only in App Router Route Handlers that execute in the Node.js runtime. The default in-memory state is tied to one persistent process. Edge and serverless instances are outside this alpha's qualified scope.

```js
export const runtime = 'nodejs';

import { createNextRouteGuard } from '@honeymesh/node-guard/next-route';

const check = createNextRouteGuard({
  guard,
  getVerifiedSourceIp: async (request) => ingress.getVerifiedSourceIp(request),
});

export async function POST(request) {
  const restriction = await check(request);
  if (restriction) return restriction;
  // Authenticate, process the request, and record only verified security events.
  return Response.json({ ok: true });
}
```

`ingress.getVerifiedSourceIp` is an application-owned function backed by a trusted deployment boundary. Next Route Handler `Request` does not by itself establish a trusted socket peer. Do not take `X-Forwarded-For` directly from the request without authenticating the ingress path. If the source cannot be verified, the adapter returns `503` with `Cache-Control: no-store`.

For a deployment with multiple workers or changing serverless instances, use OBSERVE only until a qualified shared state adapter exists. Never claim a fleet-wide rate limit from one process's memory.
