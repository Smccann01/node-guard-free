# Local policy replay candidate

`nodeguard replay` is an experimental, local-only v1 policy analysis tool. It evaluates an ordered observation file with the same in-memory v1 policy engine used by Node Guard. It returns a timeline and active restrictions at the requested UTC time. It never connects to HoneyMesh, Exchange, a socket, or the network.

For the bundled OBSERVE example:

```sh
node bin/nodeguard.mjs replay examples/auth-policy.json examples/auth-observations.json --at 2026-11-03T18:00:00Z
```

For an ENFORCE policy, supply the public source addresses protected by the deployment in a JSON array using `--protected protected-sources.json`. The CLI requires this file even when the reviewed list is `[]`. It uses the list only for simulation. It does not inspect a live application's ingress, policies, or protected-source configuration.

The input must be an array of at most 10,000 valid v1 observations in nondecreasing `observed_at` order. Each input file is capped at 1 MiB by the CLI. Duplicate event IDs, policy mismatch, and protected sources appear as rejected timeline entries. Malformed input, out-of-order timestamps, and future events fail the command. Replaying at a later time shows whether an in-memory restriction would have naturally expired.

The output contains source IPs. Keep it local or sanitize it before sharing. Node Guard does not collect request bodies, tokens, or passwords for this replay; it rejects those fields if they appear in an observation. The tool cannot reconstruct events that were never recorded, state lost on restart, other processes' counters, or decisions from a different policy version. Its timeline is a simulation, not evidence that a real HTTP response was sent or a host rule was applied.

Equivalent public IPv6 spellings are normalized before replay and protected-source matching. This matches the candidate's basic and v1 policy guards; it does not repair historical records produced by a different release.
