# Node Guard alpha release

The public package is published only from a version tag after tests and package review. The current npm `alpha` release remains `0.2.0-alpha.6` until a later tag succeeds.

## First-time trusted publisher setup

In npm package settings for `@network-decode/node-guard`, add a GitHub Actions trusted publisher with these exact values:

- Owner: `Smccann01`
- Repository: `node-guard-free`
- Workflow filename: `publish.yml`
- Allowed action: direct `npm publish`

The workflow is `.github/workflows/publish.yml`. Configure this shortly before the next release: npm requires the first successful trusted publish within two days of creating the connection. No npm write token belongs in GitHub secrets. The workflow runs on a GitHub-hosted runner with `id-token: write`, Node.js 24, and npm CLI 11.5.1. It publishes an `alpha` dist-tag so pre-releases do not become `latest`.

## Release procedure

1. Review source, dependency licenses, package file list, and [the change log](CHANGELOG.md). Run `npm ci`, `npm test`, `npm run typecheck`, `npm run smoke:package`, and `npm run smoke:next` on the exact commit.
2. Merge only reviewed changes to `main`. Set `package.json` and lockfile to the intended new alpha version. Confirm `git status` is clean.
3. Configure or verify the matching npm trusted publisher. Create and push an annotated `v<package-version>` tag from `main`.
4. Check the GitHub Actions publish job. Verify `npm view @network-decode/node-guard@<version> dist --json`, the `alpha` dist-tag, provenance, and a clean registry install. Do not infer success from the Git push alone.
5. Only after the registry package is verified, update website install commands, supported-scope copy, and the phase checkpoint. Deploy and smoke-test the live site.

If the publish job fails, leave the website on the last verified package. Fix the cause on a new commit and version rather than moving the same tag to different source. If a future build differs from the reviewed tarball, re-review its file list before publishing.
