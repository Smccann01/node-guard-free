# Node Guard security tools integration candidate

This release combines Security Replay, Policy Studio, and Webhook Shield against the alpha.10 base. `0.2.0-alpha.11` is published under npm's `alpha` tag. The registry tarball matched the reviewed 48-file stage, and its signature, provenance, and clean installation were verified.

| Tool | Current scope | Excluded behavior |
| --- | --- | --- |
| Security Replay | Ordered local v1 and synthetic v2 observations; redacted source references; simulated restriction lifecycle | No live traffic, host enforcement, or durable state |
| Policy Studio | Read-only policy diff and deterministic fixture comparison | No activation, approval workflow, or browser editor |
| Webhook Shield | Customer-controlled raw-body HMAC envelope with bounded replay storage in one process | No Stripe/GitHub signature compatibility or shared replay store |

The combined tree passed 65 source tests, TypeScript checks, clean tarball installation, and a clean Next.js 16.4.3 Node Route Handler smoke. `npm pack --json --dry-run` listed 48 files with no secret or private-key path. These checks exercise the combined package locally; they do not establish independent review, customer workload behavior, production suitability, or a published artifact.

Run `node examples/security-tools-workflow.mjs` to see a local sender sign synthetic observations, Webhook Shield verify the exact bytes, Policy Studio compare OBSERVE with proposed ENFORCE using redacted source aliases, and Security Replay simulate the proposed policy. The example uses a fresh in-process HMAC key and never sends a network request or installs a live restriction. A valid signature authenticates the sender's bytes; a real integration must separately establish that the sender verified the client IP and event before treating either as security evidence. Redacted aliases are random per report and cannot be joined across the comparison and replay output.

The combined API and security boundaries were reviewed; both supported Node versions passed CI. The owner approved a new one-person exception scoped to the exact alpha.11 npm stage, and the maintainer approved publication with 2FA. Independent review remains unmet and must not be claimed for this release or a later one.
