# Node Guard alpha release

The public package is published only from a version tag after tests and package review. The current npm `alpha` release is `0.2.0-alpha.10`; `latest` remains `0.2.0-alpha.6`. Install the exact alpha version for evaluation.

The alpha.9 tag failed npm staging authorization and predates the canonical IPv6 source correction. Do not approve or publish alpha.9. Alpha.10 was staged through the stage-only trusted publisher and approved with npm 2FA after the owner accepted a scoped one-person review exception. The exact public tarball and provenance were verified. The normal release procedure below still calls for a separate operator.

## First-time trusted publisher setup

In npm package settings for `@network-decode/node-guard`, add a GitHub Actions trusted publisher with these exact values:

- Owner: `Smccann01`
- Repository: `node-guard-free`
- Workflow filename: `publish.yml`
- Allowed action: `npm stage publish` (direct `npm publish` can remain disabled)

The workflow is `.github/workflows/publish.yml`. The package-side stage-only relationship was configured for alpha.10; verify it remains exact before each later release. No npm write token belongs in GitHub secrets. The workflow runs on a GitHub-hosted runner with `id-token: write`, Node.js 24, and npm CLI 11.21.1. It stages an `alpha` release; a maintainer then inspects and approves the staged package with 2FA. The runner does not use `setup-node`'s registry authentication configuration, so npm can request its OIDC trust token. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) and [staged publishing](https://docs.npmjs.com/staged-publishing/).

## Release procedure

1. Review source, dependency licenses, package file list, and [the change log](CHANGELOG.md). Run `npm ci`, `npm test`, `npm run typecheck`, `npm run smoke:package`, and `npm run smoke:next` on the exact commit.
2. Merge only reviewed changes to `main`. Set `package.json` and lockfile to the intended new alpha version. Confirm `git status` is clean.
3. Configure or verify the matching npm trusted publisher. Create and push an annotated `v<package-version>` tag from `main`. The staging workflow runs on the tag push; manual workflow dispatch is not used because npm may match a manually invoked workflow against a different identity.
4. Check the GitHub Actions staging job. Inspect the stage ID, staged metadata, tarball contents, and source revision. Ask a second operator to follow [the reproduction guide](REPRODUCE.md) against the staged artifact without unpublished local files. A successful staging job is not a public release.
5. Have the package maintainer approve that exact staged version with 2FA in npm. Verify `npm view @network-decode/node-guard@<version> dist --json`, the `alpha` dist-tag, provenance, and a clean registry install. Do not infer publication from the Git push or staging result alone.
6. Only after the registry package is verified, update website install commands, supported-scope copy, and the phase checkpoint. Deploy and smoke-test the live site.

If staging or approval fails, leave the website on the last verified package. Fix a changed source or workflow on a new commit and version rather than moving the same tag to different source. If a future build differs from the reviewed tarball, re-review its file list before publication.
