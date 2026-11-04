import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await mkdtemp(path.join(tmpdir(), "nodeguard-clean-install-"));

try {
  const tarball = execFileSync("npm", ["pack", "--pack-destination", temporaryRoot, "--silent"],
    { cwd: packageRoot, encoding: "utf8" }).trim();
  const appRoot = path.join(temporaryRoot, "app");
  await mkdir(appRoot);
  execFileSync("npm", ["install", "--ignore-scripts", "--offline", "--no-audit", "--no-fund",
    "--prefix", appRoot, path.join(temporaryRoot, tarball)], { stdio: "pipe" });

  const cli = path.join(appRoot, "node_modules", ".bin", "nodeguard");
  const policyPath = path.join(appRoot, "nodeguard.policy.json");
  execFileSync(cli, ["init", "--output", policyPath], { stdio: "pipe" });
  const policy = JSON.parse(await readFile(policyPath, "utf8"));
  if (policy.mode !== "OBSERVE") throw new Error("clean install did not start in OBSERVE");
  const doctor = JSON.parse(execFileSync(cli, ["doctor", policyPath], { encoding: "utf8" }));
  if (doctor.source_trust !== "not checked" || doctor.state_scope !== "one_process") {
    throw new Error("clean install diagnostics overstated the deployment scope");
  }

  const smokePath = path.join(appRoot, "smoke.mjs");
  await writeFile(smokePath, `
import { createNodeGuard } from '@network-decode/node-guard';
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import { createTrustedSourceResolver } from '@network-decode/node-guard/trusted-source';
import { createNextRouteGuard } from '@network-decode/node-guard/next-route';
import { createVerifiedIdentity, createIdentityGuardV2 } from '@network-decode/node-guard/identity-policy';
import { createLocalNodeGuardClient } from '@network-decode/node-guard/local-client';
import { createLocalExpressNodeGuard } from '@network-decode/node-guard/local-express';
if (typeof createLocalNodeGuardClient({ socketPath: '/tmp/nodeguard-smoke.sock', applicationId: 'billing-api', token: 'a'.repeat(32) }).evaluate !== 'function') process.exit(6);
if (typeof createLocalExpressNodeGuard({ client: { evaluate: async () => ({ decision: 'ALLOW' }) },
  getVerifiedSourceIp: () => '8.8.8.8', getVerifiedRouteId: () => 'auth.login' }) !== 'function') process.exit(7);
const source = createTrustedSourceResolver({ trustedProxyIps: ['127.0.0.1'] });
if (source({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '1.1.1.1, 8.8.8.8' } }) !== '8.8.8.8') process.exit(1);
const free = createNodeGuard({ mode: 'enforce', thresholds: { replay_burst: 2 }, canActOnSource: () => true });
free.record({ sourceIp: '8.8.8.8', reasonCode: 'replay_burst' });
free.record({ sourceIp: '8.8.8.8', reasonCode: 'replay_burst' });
if (!free.isBlocked('8.8.8.8')) process.exit(2);
const policy = { schema_version: 1, policy_id: 'auth-login-v1', application_id: 'billing-api', mode: 'ENFORCE', route_id: 'auth.login', reason_code: 'authentication_failure', window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60 };
const at = Date.parse('2026-11-03T18:00:00Z');
const guard = createPolicyGuardV1({ policy, now: () => at, canActOnSource: () => true });
for (const event_id of ['event-001', 'event-002']) guard.record({ schema_version: 1, application_id: 'billing-api', event_id, observed_at: '2026-11-03T18:00:00Z', route_id: 'auth.login', reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS' });
if (!guard.isBlocked('8.8.8.8')) process.exit(3);
const routeCheck = createNextRouteGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
if ((await routeCheck(new Request('https://example.test/api/login')))?.status !== 429) process.exit(4);
const identity = createVerifiedIdentity({ subjectId: 'member-01' });
const v2 = createIdentityGuardV2({ policy: { ...policy, schema_version: 2, identity_scope: 'subject_id' }, now: () => at, canActOnSource: () => true });
for (const event_id of ['event-003', 'event-004']) v2.record({ schema_version: 2, application_id: 'billing-api', event_id, observed_at: '2026-11-03T18:00:00Z', route_id: 'auth.login', reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS' }, identity);
if (!v2.isBlocked({ sourceIp: '8.8.8.8', routeId: 'auth.login', identity })) process.exit(5);
`);
  execFileSync(process.execPath, [smokePath], { stdio: "pipe" });
  process.stdout.write("Clean tarball install passed: CLI, OBSERVE default, local Guard, v1 and v2 runtimes, trusted source, local client, local Express adapter, Next route export.\n");
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
