# Node Guard Free changes

## 0.2.0-alpha.12 (release candidate)

- Add four local Builder templates: login abuse, API probing, webhook replay response, and tenant API isolation with the v2 identity policy model.
- Add an unaffected control fixture to each template and report whether a proposed policy changes the selected decision while preserving the control.
- Add `builder review` to save a redacted local change record with canonical policy fingerprints and explicit unverified source, identity, and production gates. It never activates enforcement.
- Reject symlinked Builder fixture files and refuse to overwrite a project or report. Include Builder in clean package smoke checks.

Builder remains a local simulation tool. The SDK still has one-process state and no HoneyMesh host authority.

## 0.2.0-alpha.11 (release candidate)

- Add deterministic local replay of ordered v1 and synthetic v2 policy observations. Timelines show decision transitions and bounded state without network or host enforcement. ENFORCE CLI replay requires an explicit protected-source file.
- Add read-only policy diff and deterministic shared-fixture comparison for local review. This does not activate a policy.
- Add a customer-controlled raw-body HMAC Webhook Shield verifier with bounded size, signed timestamp and event ID, one-process replay protection, and a fail-closed clock check. It is not compatible with third-party webhook signatures without a dedicated adapter.
- Add redacted Policy Studio comparisons and a packaged local workflow that verifies a synthetic signed delivery before policy review and replay. All output remains simulation-only.

## 0.2.0-alpha.10 (public alpha)

- Include the canonical IPv6 source correction merged after the alpha.9 tag. Equivalent public IPv6 spellings now map to the same source for the standalone and v1 policy guards and local management API.
- Keep Security Replay, Policy Studio, and Webhook Shield out of this published maintenance package. The exact staged tarball was reviewed and approved under a scoped one-person exception for this free experimental alpha; that exception does not authorize later releases.

## 0.2.0-alpha.9 (staging candidate)

- Carry the same application and local API code as the alpha.8 candidate. This maintenance candidate tests the tag-triggered npm OIDC staging path; it does not include Security Replay or Policy Studio source branches.
- The immutable alpha.9 tag failed npm staging authorization and lacks the later IPv6 source correction; it must not be approved as a public package.

## 0.2.0-alpha.8 (candidate)

- Add an experimental v2 application policy with server-verified subject, tenant, or API-key identity. A source-IP scope remains available. The v1 API and published `0.2.0-alpha.6` behavior are unchanged.
- Add route exclusions, synthetic identity-policy simulation, and Express and Next.js Node Route Handler adapters for v2.
- Add an experimental local Unix-socket API for v1 guards, with separate application and management credentials, bounded request bodies, scoped submission, simulation, release, and an in-memory audit ring.
- Add release checks for an npm trusted-publisher candidate. No npm provenance is claimed until the registry artifact is published and verified.

All restrictions remain application-level and process-local. The local API has no durable state or peer-UID binding. The SDK does not add host firewall, XDP, Exchange, or automatic attack classification.

## 0.2.0-alpha.6

- First public `@network-decode/node-guard` alpha with local observation, source-scoped temporary limits, Express and Next.js Node adapters, trusted-proxy source resolution, CLI tools, and a no-agent install path.
