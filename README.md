# Node Guard Free

Node Guard Free is a local application protection SDK for Node.js. It requires no account, license key, HoneyMesh agent, root access, or subscription. It does not attach XDP, enforce host firewall rules, or participate in Exchange.

**Status:** alpha source candidate. The npm package is not published yet. The standalone SDK is being prepared for a public release; the current source is not a promise of production support.

## Supported scope

- Node.js 20 or newer, one persistent Node.js process.
- Express adapter and Next.js App Router Route Handler adapter in the Node.js runtime.
- Explicit source verification and application-level observe, throttle, or deny decisions.
- In-memory state. Restart clears restrictions; workers and replicas do not share state.
- Only explicitly recorded observations count. The SDK does not infer hostile behavior from every HTTP response.

## Quick start

For local evaluation, clone this repository, run `npm ci`, `npm test`, and `npm run smoke:package`. When the npm package is published, the installation path will be:

```sh
npm install @honeymesh/node-guard
npx nodeguard init
npx nodeguard doctor nodeguard.policy.json
npx nodeguard policy validate nodeguard.policy.json
```

`init` writes an OBSERVE policy with permissions `0600` and refuses to overwrite an existing file. Review the application ID, route, source trust, and exclusions before enabling ENFORCE.

A direct application decision can be created with the v1 engine:

```js
import { createPolicyGuardV1 } from '@honeymesh/node-guard/policy-runtime';

const policy = {
  schema_version: 1, policy_id: 'login-v1', application_id: 'billing-api',
  mode: 'OBSERVE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 5, action: 'THROTTLE', restriction_seconds: 60,
};
const guard = createPolicyGuardV1({ policy, canActOnSource: (ip) => !protectedIps.has(ip) });
// After your application verifies the source and detects a failed login:
// guard.record({ schema_version: 1, application_id: 'billing-api',
//   event_id: crypto.randomUUID(), observed_at: new Date().toISOString(),
//   route_id: 'auth.login', reason_code: 'authentication_failure',
//   source_ip: verifiedSourceIp, protocol: 'HTTPS' });
```

See [developer setup](DEVELOPER_SETUP.md) and [Next route guide](NEXT_ROUTE_GUIDE.md) for complete integration rules. `nodeguard policy test` simulates decisions at a specified timestamp.

## Security model

The application owns authentication and supplies verified client identity. Only trust forwarding headers from explicitly named proxy IPs. The enforcement mode requires a `canActOnSource` callback so operators can protect management addresses. Never derive `source_ip` or a subject from an untrusted request body or arbitrary header. The application must call `record` only after it has verified an event, such as an authentication failure.

This package stores no request bodies, tokens, or passwords. The default state is local to one process and bounded by `maxSources` and `maxObservations`. A full state store, management API, and console are later phases. The private HoneyMesh bridge remains a separate paid host integration and is not present in this package.

## Commands

- `nodeguard init [--output file]`
- `nodeguard doctor [policy.json]`
- `nodeguard policy validate policy.json`
- `nodeguard policy test policy.json observations.json --at 2026-11-03T18:00:00Z`
- `nodeguard inspect policy.json`
- `nodeguard export policy.json --output sanitized-policy.json`

`export` includes validated policy fields only, no observations or runtime events. It refuses to overwrite files.

## License and reporting

Apache-2.0. See [LICENSE](LICENSE). Report suspected security issues privately using [SECURITY.md](SECURITY.md).
