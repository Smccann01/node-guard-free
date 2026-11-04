# Policy review candidate

`nodeguard policy diff` compares two validated policy files and prints every changed field, stable fingerprints, and review reasons for changes that can broaden or strengthen enforcement. It never changes an active policy or application state.

```sh
node bin/nodeguard.mjs policy diff current-policy.json proposed-policy.json
```

Both files must have the same schema version, application ID, and policy ID. A schema migration or a new policy needs its own review. Route exclusions are compared as sets, since their order has no policy meaning. A matching fingerprint identifies validated policy content, not the running application's configuration. Keep the generated report with the reviewed policy files, test fixture results, source revision, and operator approval record before manually applying a change.

`review_reasons` is a conservative prompt for human review. An empty list does not assert that a change is safe; for example, changing a route ID or reason code can still affect which traffic is covered. The tool does not simulate workload or authorize activation.
