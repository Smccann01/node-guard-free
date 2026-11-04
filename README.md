# Node Guard Free

> Development branch note: the `0.2.0-alpha.8` source adds experimental identity-scoped policy v2 modules. This branch also adds local v1 policy replay. The public npm `alpha` release remains `0.2.0-alpha.6` until a reviewed candidate passes publishing. See [identity scopes v2](IDENTITY_SCOPES_V2.md) and [local replay](REPLAY.md) for their limits.

Node Guard Free is a local application protection SDK for Node.js. It requires no account, license key, HoneyMesh agent, root access, or subscription. It does not attach XDP, enforce host firewall rules, or participate in Exchange.

**Status:** experimental alpha for evaluation. This release is not a promise of production support.

## Supported scope

- Node.js 20 or newer, one persistent Node.js process.
- Express adapter and Next.js App Router Route Handler adapter in the Node.js runtime.
- Explicit source verification and application-level observe, throttle, or deny decisions.
- In-memory state. Restart clears restrictions; workers and replicas do not share state.
- Only explicitly recorded observations count. The SDK does not infer hostile behavior from every HTTP response.

## Quick start

Install the published alpha with:

```sh
npm install @network-decode/node-guard@0.2.0-alpha.6
npx nodeguard init
npx nodeguard doctor nodeguard.policy.json
npx nodeguard policy validate nodeguard.policy.json
```

For source evaluation, clone this repository, run `npm ci`, `npm test`, `npm run typecheck`, and `npm run smoke:package`. `init` writes an OBSERVE policy with permissions `0600` and refuses to overwrite an existing file. Review the application ID, route, source trust, and exclusions before enabling ENFORCE.

A direct application decision can be created with the v1 engine:

```js
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';

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

See [developer setup](DEVELOPER_SETUP.md), [Next route guide](NEXT_ROUTE_GUIDE.md), and [independent alpha check](REPRODUCE.md) for integration and reproduction steps. `nodeguard policy test` simulates decisions at a specified timestamp.

The source candidate's `nodeguard replay` command shows each v1 observation, decision, and simulated restriction in time order. It does not inspect a running application. See the [replay guide](REPLAY.md).

## Security model

The application owns authentication and supplies verified client identity. Only trust forwarding headers from explicitly named proxy IPs. The enforcement mode requires a `canActOnSource` callback so operators can protect management addresses. Never derive `source_ip` or a subject from an untrusted request body or arbitrary header. The application must call `record` only after it has verified an event, such as an authentication failure.

The basic guard and v1 policy runtime normalize eligible IPv6 addresses before counting, consulting `canActOnSource`, checking a restriction, or releasing it. Configure protected sources in canonical IP form; equivalent IPv6 spellings are treated as the same source.

This package stores no request bodies, tokens, or passwords in the standalone engine. The default state is local to one process and bounded by `maxSources` and `maxObservations`. An [optional local API candidate](LOCAL_API.md) has separate app and management credentials; its audit ring is in memory. A durable shared state store and console are later phases. The private HoneyMesh bridge remains a separate paid host integration and is not present in this package.

## Commands

- `nodeguard init [--output file]`
- `nodeguard doctor [policy.json]`
- `nodeguard policy validate policy.json`
- `nodeguard policy test policy.json observations.json --at 2026-11-03T18:00:00Z`
- `nodeguard replay policy.json observations.json --at 2026-11-03T18:00:00Z [--protected source-ips.json] [--redact]` (source candidate)
- `nodeguard inspect policy.json`
- `nodeguard export policy.json --output sanitized-policy.json`

`export` includes validated policy fields only, no observations or runtime events. It refuses to overwrite files.

## License and reporting

Apache-2.0. See [LICENSE](LICENSE). Report suspected security issues privately using [SECURITY.md](SECURITY.md).
