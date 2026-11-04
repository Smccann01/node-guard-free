# Experimental route-aware identity policy set

This development branch adds a policy set for one application. It accepts up to 16 validated v2 policies, with at most one exact policy per route and one optional wildcard (`*`) policy. An exact route policy takes precedence for both event recording and request checks. The wildcard handles other routes unless its `excluded_route_ids` lists the route. A mismatched reason on an exact route does not fall back to the wildcard.

Each policy owns its own bounded, process-local observation and restriction state. An event ID is also deduplicated across the set so a replay cannot count once under each route. A release names one `policyId`, leaving other policy restrictions intact. The set does not combine actions from multiple matching policies or provide shared counters across workers.

Use `createVerifiedIdentity` only after application authentication has established the subject, tenant, or API key. Use a trusted ingress for `source_ip` and a server-defined `routeId`. A client-supplied route or identity could change which policy applies. The Express and Next.js Node Route Handler adapters need all three trusted callbacks for identity-scoped policies. Excluded routes skip identity lookup; an included route with missing verified context fails closed.

This module is not in the registry's `0.2.0-alpha.6` or the candidate `0.2.0-alpha.8`. It is a later development candidate. It does not classify events automatically, impose a global fleet quota, or authorize HoneyMesh host enforcement.

```js
import { createVerifiedIdentity } from '@network-decode/node-guard/identity-policy';
import { createIdentityPolicySetV2 } from '@network-decode/node-guard/identity-policy-set';
import { createExpressIdentityPolicySetV2 } from '@network-decode/node-guard/identity-policy-set-express';

const set = createIdentityPolicySetV2({
  policies: [exactLoginPolicy, wildcardApiPolicy],
  canActOnSource: (ip) => !protectedOperatorIps.has(ip),
});
app.use(createExpressIdentityPolicySetV2({
  policySet: set,
  getVerifiedSourceIp: (req) => req.verifiedClientIp,
  getRouteId: (req) => req.serverRouteId,
  getVerifiedIdentity: (req) => createVerifiedIdentity({ subjectId: req.authenticatedSubjectId }),
}));
```

The identifiers and callbacks in this example are supplied by the application after authentication and ingress verification. To record an actual event, call `set.record(observation, verifiedIdentity)` after the application confirms that event. To release a restriction, call `set.release({ policyId, sourceIp, identity })`; naming the policy avoids clearing another policy's state.
