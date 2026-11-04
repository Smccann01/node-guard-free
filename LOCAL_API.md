# Optional local API candidate

The `@network-decode/node-guard/local-api` module coordinates up to 32 application guards in one unprivileged Node.js process. It listens only on an operator-chosen Unix socket. The parent directory must be owned by that process and must not be group or world writable; the socket is set to mode `0600`. No TCP listener or public management endpoint is created.

This API is experimental. It accepts v1 source-scoped policy guards only; the v2 identity object cannot be submitted as JSON. It uses in-memory guards and an in-memory, bounded management audit ring. Restart clears restrictions and audit entries. It does not verify Linux peer UID. The default `0600` socket admits only processes running as the coordinator's Unix user; separate application tokens still isolate their policy scopes. Give each trusted application its own random 32-256 byte bearer credential and use a distinct random management credential. Store credentials outside source control and send them only over the local socket. The application remains responsible for verifying a source IP before submitting an observation or evaluation.

| Method and path | Credential | Behavior |
| --- | --- | --- |
| `POST /v1/observations` | Application token | Submit one v1 observation for that token's application only |
| `POST /v1/decisions/evaluate` | Application token | Evaluate one verified public source for that token's application; return `ALLOW`, `THROTTLE`, or `DENY` with bounded expiry information |
| `GET /v1/health` | Management token | Return local process status |
| `GET /v1/restrictions` | Management token | List up to 1,000 active restrictions |
| `POST /v1/restrictions/release` | Management token | Release one application's source restriction and audit it |
| `POST /v1/policies/simulate` | Management token | Run the pure v1 simulator without changing live state |
| `GET /v1/audit` | Management token | Read up to 1,000 recent in-memory decision and release records, with a truncation flag |

All methods return JSON with `Cache-Control: no-store`. Request bodies are capped at 64 KiB. Authentication failures do not reveal whether an application exists.

Workers under the coordinator's Unix user can use `createLocalNodeGuardClient` from `@network-decode/node-guard/local-client` to submit observations and evaluate the shared coordinator state. An unavailable coordinator rejects the client promise; the application must decide its own explicit unavailable behavior and monitor it. The client does not infer source identity, does not open TCP, and does not turn an API response into an HTTP status automatically. The coordinator itself remains one process; restart loses state. This is one-host multi-worker coordination, not a shared store across hosts or serverless replicas.

An application worker can call the client after its own trusted ingress has identified the source. For example, an Express handler can map a coordinator decision to an application response:

```js
import { createLocalNodeGuardClient } from '@network-decode/node-guard/local-client';

const client = createLocalNodeGuardClient({
  socketPath: '/run/nodeguard/guard.sock',
  applicationId: 'billing-api',
  token: process.env.NODE_GUARD_APP_TOKEN,
});

app.use(async (req, res, next) => {
  try {
    const sourceIp = getVerifiedSourceIp(req); // Your reviewed ingress resolver.
    const result = await client.evaluate(sourceIp);
    if (result.decision === 'ALLOW') return next();
    res.set('Retry-After', String(result.restriction.retry_after_seconds));
    return res.status(result.decision === 'DENY' ? 403 : 429).json({ error: 'node_guard_restricted' });
  } catch (error) {
    // Explicit availability policy for this example: stop this request and alert the operator.
    return res.status(503).json({ error: 'node_guard_unavailable' });
  }
});
```

The example assumes the application has already reviewed `getVerifiedSourceIp` and supplied the credential securely. It does not automatically convert arbitrary HTTP events into hostile observations. Separate application code decides which authenticated events to submit with `client.record(observation)`.

Rollback is a reviewed policy file change to OBSERVE and application restart, or a scoped release through the management API. A durable audit store, Linux peer UID verification, and a browser console require separate qualification.
