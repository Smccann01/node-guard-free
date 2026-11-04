# Policy review candidate

`nodeguard policy diff` compares two validated policy files and prints every changed field, stable fingerprints, and review reasons for changes that can broaden or strengthen enforcement. It never changes an active policy or application state.

```sh
node bin/nodeguard.mjs policy diff current-policy.json proposed-policy.json
node bin/nodeguard.mjs policy compare current-policy.json proposed-policy.json observations.json --at 2026-11-04T10:00:00Z
node bin/nodeguard.mjs policy compare current-policy.json proposed-policy.json observations.json --at 2026-11-04T10:00:00Z --redact
```

Both files must have the same schema version, application ID, and policy ID. A schema migration or a new policy needs its own review. Route exclusions are compared as sets, since their order has no policy meaning. A matching fingerprint identifies validated policy content, not the running application's configuration. Keep the generated report with the reviewed policy files, test fixture results, source revision, and operator approval record before manually applying a change.

`policy compare` runs both policies against the same observation fixtures at the same UTC time and lists differing decisions. V2 identity scopes must match so fixture interpretation remains consistent. Inputs for identity scopes other than `source_ip` use only synthetic `fixture_identity` values. This is a point-in-time simulation, not a replay of actual runtime state. Simulated expiry is calculated from the requested comparison time; it is not the actual expiry of a live restriction. Keep sensitive raw observations local.

Use `--redact` when exporting a comparison. It replaces source-IP values with one random-key HMAC alias per source within that report, including nested before and after decisions. Aliases are intentionally different across separate runs. Other policy metadata and synthetic fixture identifiers remain visible; review those fields before sharing a report.

`review_reasons` is a conservative prompt for human review. An empty list does not assert that a change is safe; for example, changing a route ID or reason code can still affect which traffic is covered. The tool never authorizes activation.
