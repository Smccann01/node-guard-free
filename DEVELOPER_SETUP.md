# Developer setup

1. Use Node.js 20 or newer in a persistent Node process. Install a verified npm version of `@network-decode/node-guard` and run `npx nodeguard init`.
2. Run `npx nodeguard doctor nodeguard.policy.json`. The `source_trust: not checked` result means the CLI cannot verify your ingress topology.
3. Inspect the generated OBSERVE policy. Set `application_id` and `route_id` to stable identifiers. Keep `mode` as `OBSERVE` until normal traffic has been reviewed.
4. Determine the actual socket peer address. If a reverse proxy is used, list each trusted proxy IP in `createTrustedSourceResolver({ trustedProxyIps })`. Never trust `X-Forwarded-For` from an unlisted peer.
5. Let application authentication and route handlers identify verified events. Use `createPolicyGuardV1` and call `record` for explicit events only. Use a random unique `event_id` for each observation. Avoid logging credentials or request bodies.
6. Run `nodeguard policy test` against representative sanitized observations. Use the decision callback and your own monitoring to review normal activity in OBSERVE.
7. To enforce, change the policy mode to `ENFORCE`, define `canActOnSource` to exclude management and other protected addresses, restart the application, and test with a noncritical source. Use `createExpressNodeGuard` or `createNextRouteGuard` to apply the resulting application restriction. If behavior is unexpected, revert to OBSERVE and restart; `guard.release(ip)` removes a specific local restriction in a running process.
8. Treat each worker as independent. A restart clears in-memory state. There is no shared quota or durable audit store in this alpha.

## Express outline

```js
import express from 'express';
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import { createExpressNodeGuard } from '@network-decode/node-guard/express';
import { createTrustedSourceResolver } from '@network-decode/node-guard/trusted-source';
import policy from './nodeguard.policy.json' with { type: 'json' };

const app = express();
const source = createTrustedSourceResolver({ trustedProxyIps: ['127.0.0.1'] });
const guard = createPolicyGuardV1({ policy, canActOnSource: (ip) => !protectedIps.has(ip) });
app.use(createExpressNodeGuard({ guard, getVerifiedSourceIp: source }));
// In the login handler, after verifying a failed login, record an observation.
// See examples/auth-observations.json for its complete v1 shape.
```

Replace `protectedIps` with your own explicit protected-source set and `trustedProxyIps` with the actual immediate proxies. The sample proxy IP is illustrative. `createExpressNodeGuard` replies `429` for THROTTLE and `403` for DENY and includes `Retry-After`.

## Recovery

Application restrictions are local and temporary. On an unexpected restriction, call `guard.release(verifiedIp)` from an authenticated operator path or switch back to OBSERVE and restart. Never expose release without authentication. HoneyMesh host enforcement, when separately installed, has its own recovery procedure.
