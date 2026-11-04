# Node Guard security tools integration candidate

This branch combines the separate Security Replay, Policy Studio, and Webhook Shield source candidates against the published alpha.10 base. Its package version is `0.2.0-alpha.11-dev.0` to distinguish the combined source tree from the immutable public alpha.10 artifact. It is **not** an npm release.

| Tool | Current scope | Excluded behavior |
| --- | --- | --- |
| Security Replay | Ordered local v1 and synthetic v2 observations; redacted source references; simulated restriction lifecycle | No live traffic, host enforcement, or durable state |
| Policy Studio | Read-only policy diff and deterministic fixture comparison | No activation, approval workflow, or browser editor |
| Webhook Shield | Customer-controlled raw-body HMAC envelope with bounded replay storage in one process | No Stripe/GitHub signature compatibility or shared replay store |

The combined tree passed 63 source tests, TypeScript checks, clean tarball installation, and a clean Next.js 16.4.3 Node Route Handler smoke. `npm pack --json --dry-run` listed 47 files with no secret or private-key path. These checks exercise the combined package locally; they do not establish independent review, customer workload behavior, production suitability, or a published artifact.

Before a public alpha containing these tools, review the combined API and security boundaries, run both supported Node versions in CI, check the exact staged tarball and provenance, and obtain the approval required for that later release. The one-person exception for alpha.10 did not authorize this candidate.
