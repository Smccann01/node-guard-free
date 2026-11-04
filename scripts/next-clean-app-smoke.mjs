import { execFileSync, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = await mkdtemp(path.join(tmpdir(), 'nodeguard-next-smoke-'));
let server;

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = createServer();
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', () => {
      const { port } = listener.address();
      listener.close(() => resolve(port));
    });
  });
}

try {
  execFileSync('npm', ['pack', '--pack-destination', root, '--silent'], { cwd: sourceRoot, stdio: 'pipe' });
  const tarball = (await readdir(root)).find((name) => name.endsWith('.tgz'));
  if (!tarball) throw new Error('npm pack did not produce a tarball');
  const routeDir = path.join(root, 'app', 'api', 'check');
  const identityRouteDir = path.join(root, 'app', 'api', 'identity');
  const setRouteDir = path.join(root, 'app', 'api', 'policy-set');
  await mkdir(routeDir, { recursive: true });
  await mkdir(identityRouteDir, { recursive: true });
  await mkdir(setRouteDir, { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'nodeguard-next-smoke', private: true, type: 'module', scripts: { build: 'next build --webpack' } }));
  await writeFile(path.join(root, 'app', 'layout.js'), 'export default function RootLayout({ children }) { return <html><body>{children}</body></html>; }\n');
  await writeFile(path.join(root, 'app', 'page.js'), 'export default function Page() { return <main>Node Guard smoke</main>; }\n');
  await writeFile(path.join(routeDir, 'route.js'), `
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import { createNextRouteGuard } from '@network-decode/node-guard/next-route';
const policy = { schema_version: 1, policy_id: 'login-v1', application_id: 'smoke-app', mode: 'ENFORCE', route_id: 'auth.login', reason_code: 'authentication_failure', window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60 };
const guard = createPolicyGuardV1({ policy, canActOnSource: () => true });
// Fixed source is test-only. A real deployment must verify the ingress boundary.
const check = createNextRouteGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
export async function POST(request) {
  const at = new Date().toISOString();
  for (const event_id of ['smoke-event-001', 'smoke-event-002']) guard.record({ schema_version: 1, application_id: 'smoke-app', event_id, observed_at: at, route_id: 'auth.login', reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS' });
  return (await check(request)) ?? Response.json({ ok: true });
}
`);
  await writeFile(path.join(setRouteDir, 'route.js'), `
import { createVerifiedIdentity } from '@network-decode/node-guard/identity-policy';
import { createIdentityPolicySetV2 } from '@network-decode/node-guard/identity-policy-set';
import { createNextIdentityPolicySetV2 } from '@network-decode/node-guard/identity-policy-set-next';
const base = { schema_version: 2, application_id: 'smoke-app', mode: 'ENFORCE', reason_code: 'replay_burst', identity_scope: 'subject_id', window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60 };
const set = createIdentityPolicySetV2({ policies: [
  { ...base, policy_id: 'exact', route_id: 'auth.login' },
  { ...base, policy_id: 'wildcard', route_id: '*', excluded_route_ids: ['health.check'] },
], canActOnSource: () => true });
const identity = createVerifiedIdentity({ subjectId: 'fixture-authenticated-user' });
const check = createNextIdentityPolicySetV2({ policySet: set, getVerifiedSourceIp: () => '8.8.8.8',
  getRouteId: (request) => request.method === 'GET' ? 'health.check' : 'auth.login',
  getVerifiedIdentity: (request) => request.method === 'GET' ? (() => { throw new Error('excluded route requested identity'); })() : identity });
function record(route, prefix) {
  const at = new Date().toISOString();
  for (const suffix of ['001', '002']) set.record({ schema_version: 2, application_id: 'smoke-app',
    event_id: prefix + '-event-' + suffix, observed_at: at, route_id: route,
    reason_code: 'replay_burst', source_ip: '8.8.8.8', protocol: 'HTTPS' }, identity);
}
export async function GET(request) { return (await check(request)) ?? Response.json({ ok: true }); }
export async function POST(request) { record('api.transfer', 'wildcard'); return (await check(request)) ?? Response.json({ ok: true }); }
export async function PUT(request) { record('auth.login', 'exact'); return (await check(request)) ?? Response.json({ ok: true }); }
`);
  await writeFile(path.join(identityRouteDir, 'route.js'), `
import { createIdentityGuardV2, createVerifiedIdentity } from '@network-decode/node-guard/identity-policy';
import { createNextIdentityGuardV2 } from '@network-decode/node-guard/identity-next-route';
const policy = { schema_version: 2, policy_id: 'user-replay-v2', application_id: 'smoke-app', mode: 'ENFORCE', route_id: '*', excluded_route_ids: ['health.check'], reason_code: 'replay_burst', identity_scope: 'subject_id', window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60 };
const guard = createIdentityGuardV2({ policy, canActOnSource: () => true });
const identity = createVerifiedIdentity({ subjectId: 'fixture-authenticated-user' });
// The fixed identity represents a server-verified session in this isolated fixture.
const check = createNextIdentityGuardV2({ guard, getVerifiedSourceIp: () => '8.8.8.8',
  getRouteId: (request) => request.method === 'GET' ? 'health.check' : 'auth.login',
  getVerifiedIdentity: (request) => request.method === 'GET' ? (() => { throw new Error('excluded route requested identity'); })() : identity });
export async function GET(request) { return (await check(request)) ?? Response.json({ ok: true }); }
export async function POST(request) {
  const at = new Date().toISOString();
  for (const event_id of ['identity-event-001', 'identity-event-002']) guard.record({ schema_version: 2, application_id: 'smoke-app', event_id, observed_at: at, route_id: 'auth.login', reason_code: 'replay_burst', source_ip: '8.8.8.8', protocol: 'HTTPS' }, identity);
  return (await check(request)) ?? Response.json({ ok: true });
}
`);

  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', 'next@16.4.3', 'react@19.3.1', 'react-dom@19.3.1', path.join(root, tarball)], { cwd: root, stdio: 'pipe' });
  execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'pipe', env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' } });
  const port = await freePort();
  server = spawn(path.join(root, 'node_modules', '.bin', 'next'), ['start', '-p', String(port), '-H', '127.0.0.1'], { cwd: root, stdio: 'ignore' });
  let response;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.exitCode !== null) throw new Error('Next server exited before becoming ready');
    try {
      response = await fetch(`http://127.0.0.1:${port}/api/check`, { method: 'POST' });
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  if (!response) throw new Error('Next server did not become ready');
  if (response.status !== 429 || response.headers.get('retry-after') !== '60') {
    throw new Error(`unexpected Next decision: ${response.status} ${await response.text()}`);
  }
  const body = await response.json();
  if (body.error !== 'node_guard_restricted') throw new Error('unexpected Next response body');
  const excluded = await fetch(`http://127.0.0.1:${port}/api/identity`);
  if (excluded.status !== 200) throw new Error(`excluded identity route returned ${excluded.status}`);
  const identityResponse = await fetch(`http://127.0.0.1:${port}/api/identity`, { method: 'POST' });
  if (identityResponse.status !== 429 || identityResponse.headers.get('retry-after') !== '60') {
    throw new Error(`unexpected identity decision: ${identityResponse.status} ${await identityResponse.text()}`);
  }
  const excludedSet = await fetch(`http://127.0.0.1:${port}/api/policy-set`);
  if (excludedSet.status !== 200) throw new Error(`excluded policy-set route returned ${excludedSet.status}`);
  const wildcardOnly = await fetch(`http://127.0.0.1:${port}/api/policy-set`, { method: 'POST' });
  if (wildcardOnly.status !== 200) throw new Error(`wildcard restriction overrode exact route: ${wildcardOnly.status}`);
  const exactSet = await fetch(`http://127.0.0.1:${port}/api/policy-set`, { method: 'PUT' });
  if (exactSet.status !== 429) throw new Error(`exact policy-set route returned ${exactSet.status}`);
  process.stdout.write('Clean Next.js 16.4.3 app build and v1/v2 and route-set decisions passed.\n');
} finally {
  if (server && server.exitCode === null) {
    server.kill('SIGTERM');
    await new Promise((resolve) => server.once('exit', resolve));
  }
  await rm(root, { recursive: true, force: true });
}
