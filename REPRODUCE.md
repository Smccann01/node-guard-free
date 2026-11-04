# Independent Node Guard Free alpha check

An operator who did not build the package can run this on a disposable, unprivileged Node.js 20+ environment. Record the operator, UTC time, OS, Node version, exact npm version, and the console output. No HoneyMesh account, key, agent, or root access is required.

## Registry package currently offered to customers

Create an empty application directory. Run:

```sh
node --version
npm view @network-decode/node-guard dist-tags --json
npm install --ignore-scripts @network-decode/node-guard@0.2.0-alpha.6
npm ls @network-decode/node-guard
npx nodeguard init
npx nodeguard doctor nodeguard.policy.json
npx nodeguard policy validate nodeguard.policy.json
cp node_modules/@network-decode/node-guard/examples/auth-observations.json observations.json
npx nodeguard policy test nodeguard.policy.json observations.json --at 2026-11-03T18:00:00Z
```

Expected: `doctor` reports `one_process` and `source_trust: not checked`; the policy is OBSERVE; the simulator returns one source with `hit_count: 2`, `decision: OBSERVE`, and no expiration. `init` must refuse to overwrite the policy on a second run. These commands do not send traffic or enable enforcement.

To validate the candidate source before an npm release, clone the repository at the intended release commit and run `npm ci`, `npm test`, `npm run typecheck`, `npm run smoke:package`, and `npm run smoke:next`. Compare `npm pack --dry-run --json` with the approved package file list. The next alpha must be installed again from the registry after publishing; a source checkout alone cannot prove what customers receive.

## Stage a reviewed alpha

The `publish.yml` GitHub Actions workflow checks a reviewed `v0.2.0-alpha.N` tag, runs the checks above, and submits the exact package with `npm stage publish --tag alpha --access public`. A maintainer must inspect the staged tarball and approve it with npm two-factor authentication before the version becomes public. The workflow can also be dispatched against an existing reviewed tag after a failed staging attempt; it must not build from an untagged branch. The npm trusted publisher must match `Smccann01/node-guard-free` and `publish.yml` exactly, with staging allowed. After approval, verify the registry version, tarball integrity, provenance status, and clean installation before changing website install instructions. Until then, this page keeps customers pinned to the published alpha.6.

## Review the trust boundary

Before any app-level ENFORCE pilot, an operator must identify the trusted ingress that supplies the real client IP, protect management sources, choose a noncritical test source, and verify release or restart recovery. Do not use a request body or an arbitrary forwarding header as trusted identity. One process has its own counters; workers and replicas do not share restrictions. Record a separate field result for the real app integration. A passing registry smoke does not qualify host XDP, Node Pro, Exchange, or production performance.
