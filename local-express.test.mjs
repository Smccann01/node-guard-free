import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import express from 'express';
import { createLocalNodeGuardApi } from './local-api.mjs';
import { createLocalNodeGuardClient } from './local-client.mjs';
import { createLocalExpressNodeGuard } from './local-express.mjs';
import { createPolicyGuardV1 } from './policy-runtime.mjs';

test('local Express middleware scopes a coordinator restriction to the verified source and route, then recovers', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-local-express-'));
  const socketPath = path.join(dir, 'guard.sock');
  const applicationId = 'billing-api';
  const token = 'a'.repeat(32);
  let at = Date.parse('2026-11-04T08:00:00Z');
  let verifiedSourceIp = '8.8.8.8';
  const guard = createPolicyGuardV1({ policy: { schema_version: 1, policy_id: 'login-v1',
    application_id: applicationId, mode: 'ENFORCE', route_id: 'auth.login',
    reason_code: 'authentication_failure', window_seconds: 60, threshold: 2,
    action: 'THROTTLE', restriction_seconds: 60 }, canActOnSource: () => true, now: () => at });
  const api = createLocalNodeGuardApi({ socketPath, managementToken: 'm'.repeat(32),
    applications: [{ applicationId, token, guard }], now: () => at });
  const client = createLocalNodeGuardClient({ socketPath, applicationId, token });
  const app = express();
  app.use(createLocalExpressNodeGuard({ client, getVerifiedSourceIp: () => verifiedSourceIp,
    getVerifiedRouteId: (request) => request.path === '/login' ? 'auth.login' : 'health.check' }));
  app.get('/login', (_request, response) => response.json({ ok: true }));
  app.get('/health', (_request, response) => response.json({ ok: true }));
  let server;
  try {
    await api.start();
    server = await new Promise((resolve) => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(`${base}/login`)).status, 200);
    const event = (eventId) => ({ schema_version: 1, application_id: applicationId, event_id: eventId,
      observed_at: new Date(at).toISOString(), route_id: 'auth.login', reason_code: 'authentication_failure',
      source_ip: '8.8.8.8', protocol: 'HTTPS' });
    assert.equal((await client.record(event('event-001'))).action, 'recorded');
    assert.equal((await client.record(event('event-002'))).action, 'THROTTLE');
    const blocked = await fetch(`${base}/login`, { headers: { 'x-forwarded-for': '9.9.9.9' } });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('retry-after'), '60');
    assert.equal(blocked.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(`${base}/health`)).status, 200);
    verifiedSourceIp = '9.9.9.9';
    assert.equal((await fetch(`${base}/login`)).status, 200);
    verifiedSourceIp = undefined;
    assert.equal((await fetch(`${base}/login`)).status, 503);
    verifiedSourceIp = '8.8.8.8';
    at += 60_001;
    assert.equal((await fetch(`${base}/login`)).status, 200);
    await api.stop();
    const unavailable = await fetch(`${base}/login`);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { error: 'node_guard_unavailable' });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    await api.stop();
    await rm(dir, { recursive: true, force: true });
  }
});
