# Builder starter kit

Builder helps administrators create and review application security tools on systems they control. The starter kit is free and runs locally. It sends no configuration or events to Network Decode.

## Create and check a project

With this repository checked out, run:

```sh
node bin/nodeguard.mjs builder init my-security-tool
node bin/nodeguard.mjs builder check my-security-tool
```

From a package release that includes Builder, use `npx nodeguard builder ...` instead. The published `0.2.0-alpha.11` package does **not** include these new commands.

`init` creates a new directory and refuses to overwrite an existing one. It writes a manifest, current and proposed v1 policies, two synthetic observations, and a local README. `check` validates the event and policy files, compares decisions at the manifest's fixed UTC time, redacts source addresses in its output, and reports file hashes. It never activates a policy or host rule.

## Event format for this first kit

The `observations.json` file is an array of Node Guard [ObservationV1](policy.d.ts) records. Each record carries a schema version, application ID, event ID, UTC observation time, route ID, reason code, verified source IP, and protocol. The application is responsible for verifying source identity and for recording only events it actually detected. This is an application event format; it does not claim to represent HoneyMesh kernel events or prove packet drops.

The manifest declares only `policy_simulation`. Future adapters can add separately versioned event kinds with explicit provenance and trust rules. An extension cannot turn this manifest into host enforcement authority.

## Adapt the example

1. Replace the sample application and route IDs in both policies and observations.
2. Keep the current policy in `OBSERVE` while testing your proposed policy.
3. Add synthetic cases for legitimate traffic, repeated failures, excluded routes, and protected sources.
4. Run `builder check`, then use `nodeguard policy compare` and `nodeguard replay` for deeper review.
5. Store real evidence in your own systems. Keep secrets, private IPs, and customer identifiers out of source control.

The starter kit is an experimental local review tool. It does not deploy software, operate hosts, or integrate with the HoneyMesh enforcement engine.
