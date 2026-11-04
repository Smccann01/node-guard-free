# Node Guard Free changes

## 0.2.0-alpha.9 (development branch)

- Add a route-aware v2 policy set with exact-route precedence, one optional wildcard, explicit exclusions, cross-policy event replay protection, and policy-specific release.
- Add Express and Next.js Node adapters, type declarations, and a clean Next.js package integration check for the route set.
- This is not a published registry release. State is still process-local, and host XDP and Exchange remain separate.

## 0.2.0-alpha.8 (candidate)

- Add an experimental v2 application policy with server-verified subject, tenant, or API-key identity. A source-IP scope remains available. The v1 API and published `0.2.0-alpha.6` behavior are unchanged.
- Add route exclusions, synthetic identity-policy simulation, and Express and Next.js Node Route Handler adapters for v2.
- Add an experimental local Unix-socket API for v1 guards, with separate application and management credentials, bounded request bodies, scoped submission, simulation, release, and an in-memory audit ring.
- Add a tag-only npm trusted-publisher workflow and release checks. No npm provenance is claimed until the registry artifact is published and verified.

All restrictions remain application-level and process-local. The local API has no durable state or peer-UID binding. The SDK does not add host firewall, XDP, Exchange, or automatic attack classification.

## 0.2.0-alpha.6

- First public `@network-decode/node-guard` alpha with local observation, source-scoped temporary limits, Express and Next.js Node adapters, trusted-proxy source resolution, CLI tools, and a no-agent install path.
