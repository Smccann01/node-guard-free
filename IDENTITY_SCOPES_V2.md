# Experimental identity-scoped policy v2

The separately imported `identity-policy` module adds per-user, per-tenant, and per-API-key application limits. It does not change the published v1 source-IP policy. **This module is a development candidate and is not in the `0.2.0-alpha.6` registry package.**

## Trust contract

- Resolve the client IP through the actual trusted ingress. Never use a client-supplied forwarding header by itself.
- Call `createVerifiedIdentity` only after your application's authentication and tenant authorization have completed. Build it from server-side session, token verification, or database state. Do not pass a request body, query parameter, or unverified header into it.
- Identity objects are opaque to JSON; a parsed object cannot impersonate a verified identity. The application process is still trusted code. If application code itself constructs identities from untrusted input, Node Guard cannot repair that trust error.
- For an unauthenticated login failure, use a source-IP policy. A submitted username is not a verified subject and must not trigger a subject-wide restriction.
- Identity values are HMAC keyed inside one guard instance. Decisions and snapshots expose only a process-local reference; they do not contain the raw user, tenant, or API-key ID. Restart clears state and changes the reference.

## Policy and app integration

Validate and simulate the included synthetic fixtures before wiring a live application:

```sh
nodeguard policy validate examples/identity-policy.json
nodeguard policy test examples/identity-policy.json examples/identity-observations.json --at 2026-11-04T06:00:00Z
```

The simulator accepts only `fixture:` identity labels for non-IP scopes. These labels are not runtime credentials or customer identifiers.

```js
import { randomUUID } from 'node:crypto';
import { createVerifiedIdentity, createIdentityGuardV2 } from '@network-decode/node-guard/identity-policy';
import { createExpressIdentityGuardV2 } from '@network-decode/node-guard/identity-express';

const policy = {
  schema_version: 2,
  policy_id: 'replay-by-user', application_id: 'billing-api',
  mode: 'OBSERVE', route_id: '*', excluded_route_ids: ['health.check'],
  reason_code: 'replay_burst', identity_scope: 'subject_id',
  window_seconds: 60, threshold: 3, action: 'THROTTLE', restriction_seconds: 60,
};
const guard = createIdentityGuardV2({ policy, canActOnSource: (ip) => !operatorIps.has(ip) });

// Your existing auth middleware must set req.auth from a verified session.
// Your ingress integration must set req.verifiedClientIp, and the route map
// must set req.routeId from a server-side route definition.
app.use(createExpressIdentityGuardV2({
  guard,
  getVerifiedSourceIp: (req) => req.verifiedClientIp,
  getRouteId: (req) => req.routeId,
  getVerifiedIdentity: (req) => createVerifiedIdentity({ subjectId: req.auth.subjectId }),
}));

// Call only when the application has actually verified a replay attempt.
guard.record({
  schema_version: 2, application_id: 'billing-api', event_id: randomUUID(),
  observed_at: new Date().toISOString(), route_id: 'api.transfer',
  reason_code: 'replay_burst', source_ip: req.verifiedClientIp, protocol: 'HTTPS',
}, createVerifiedIdentity({ subjectId: req.auth.subjectId }));
```

`operatorIps`, `req.auth`, `req.routeId`, `req.verifiedClientIp`, and the Express `app` are supplied by the host application. Start in `OBSERVE`; change to `ENFORCE` only after representative normal traffic, protected-source rules, and recovery are checked. The action is still only an application response: `429` for `THROTTLE` or `403` for `DENY`.

The policy supports exact routes or `*` with at most 32 exact exclusions. Exclusions apply both when recording observations and when checking restrictions. The adapter skips an excluded route before requesting authentication context, so a health endpoint can stay available. Missing trusted context on an included route is passed to the Express error handler or returned as `503` by the Next Route Handler adapter; it is never treated as an unrestricted identity.

## Scope and state

`source_ip` uses a normalized public IP. `subject_id`, `tenant_id`, and `api_key_id` use separately verified application context. Different users behind one NAT address are independent under a subject policy; a tenant policy intentionally spans that tenant's users and source addresses. A protected source remains exempt when checking any scope.

This candidate is one policy in one process. It has bounded identity and event storage, temporary restrictions, explicit release, and no durable or shared state. A worker restart clears limits, and two workers do not share counters. Do not deploy it behind multiple workers as though it were a global rate limit. It does not grant HoneyMesh host or XDP authority.
