# Optional local API candidate

The `@network-decode/node-guard/local-api` module coordinates up to 32 application guards in one unprivileged Node.js process. It listens only on an operator-chosen Unix socket. The parent directory must be owned by that process and must not be group or world writable; the socket is set to mode `0600`. No TCP listener or public management endpoint is created.

This API is experimental. It uses in-memory guards and an in-memory, bounded management audit ring. Restart clears restrictions and audit entries. It does not verify Linux peer UID. Give each trusted application its own random 32-256 byte bearer credential and use a distinct random management credential. Store credentials outside source control and send them only over the local socket. The application remains responsible for verifying a source IP before submitting an observation.

| Method and path | Credential | Behavior |
| --- | --- | --- |
| `POST /v1/observations` | Application token | Submit one v1 observation for that token's application only |
| `GET /v1/health` | Management token | Return local process status |
| `GET /v1/restrictions` | Management token | List up to 1,000 active restrictions |
| `POST /v1/restrictions/release` | Management token | Release one application's source restriction and audit it |
| `POST /v1/policies/simulate` | Management token | Run the pure v1 simulator without changing live state |
| `GET /v1/audit` | Management token | Read bounded in-memory release audit entries |

All methods return JSON with `Cache-Control: no-store`. Request bodies are capped at 64 KiB. Authentication failures do not reveal whether an application exists.

Rollback is a reviewed policy file change to OBSERVE and application restart, or a scoped release through the management API. Because state is in memory, this API is limited to one process. A durable audit store, multi-process consistency, Linux peer UID verification, and a browser console require separate qualification.
