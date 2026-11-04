import assert from 'node:assert/strict';
import { request } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createLocalNodeGuardApi } from './local-api.mjs';
import { createPolicyGuardV1 } from './policy-runtime.mjs';
import { createIdentityGuardV2 } from './identity-policy.mjs';

const at = Date.parse('2026-11-03T18:00:00Z');
const appAToken = 'a'.repeat(32);
const appBToken = 'b'.repeat(32);
const adminToken = 'm'.repeat(32);
function guardFor(applicationId) {
  return createPolicyGuardV1({ policy: { schema_version: 1, policy_id: `${applicationId}-login`, application_id: applicationId,
    mode: 'ENFORCE', route_id: 'auth.login', reason_code: 'authentication_failure', window_seconds: 60,
    threshold: 2, action: 'THROTTLE', restriction_seconds: 60 }, canActOnSource: () => true, now: () => at });
}
function call(socketPath, method, route, token, body, contentType = 'application/json') {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const req = request({ socketPath, method, path: route, headers: {
      authorization: `Bearer ${token}`, ...(data ? { 'content-type': contentType, 'content-length': Buffer.byteLength(data) } : {})
    } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(data);
  });
}
function observation(applicationId, eventId) {
  return { schema_version: 1, application_id: applicationId, event_id: eventId,
    observed_at: new Date(at).toISOString(), route_id: 'auth.login', reason_code: 'authentication_failure',
    source_ip: '8.8.8.8', protocol: 'HTTPS' };
}

function callInChild(socketPath, token, body) {
  const script = `
    const http = require('node:http');
    const [socketPath, token, raw] = process.argv.slice(1);
    const data = JSON.stringify(JSON.parse(raw));
    const request = http.request({ socketPath, path: '/v1/observations', method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json',
        'content-length': Buffer.byteLength(data) } }, (response) => {
      let output = '';
      response.on('data', (chunk) => output += chunk);
      response.on('end', () => process.stdout.write(JSON.stringify({ status: response.statusCode, body: JSON.parse(output) })));
    });
    request.on('error', (error) => { process.stderr.write(error.message); process.exitCode = 1; });
    request.end(data);
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script, socketPath, token, JSON.stringify(body)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; let errors = '';
    child.stdout.on('data', (chunk) => output += chunk);
    child.stderr.on('data', (chunk) => errors += chunk);
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolve(JSON.parse(output)) : reject(new Error(errors || `child exited ${code}`)));
  });
}

test('local API scopes two app tokens, separates management, audits release, and binds private socket', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-api-'));
  const socketPath = path.join(dir, 'guard.sock');
  const a = guardFor('app-a');
  const b = guardFor('app-b');
  const api = createLocalNodeGuardApi({ socketPath, managementToken: adminToken,
    applications: [{ applicationId: 'app-a', token: appAToken, guard: a }, { applicationId: 'app-b', token: appBToken, guard: b }], now: () => at });
  try {
    await api.start();
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    assert.equal((await call(socketPath, 'GET', '/v1/restrictions', appAToken)).status, 401);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', adminToken, observation('app-a', 'event-001'))).status, 401);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', appAToken, observation('app-b', 'event-001'))).status, 403);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', appAToken, observation('app-a', 'event-001'), 'application/jsonp')).status, 400);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', appAToken,
      { ...observation('app-a', 'event-001'), subject_id: 'alice' })).status, 400);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', appAToken, observation('app-a', 'event-001'))).status, 200);
    assert.equal((await call(socketPath, 'POST', '/v1/observations', appAToken, observation('app-a', 'event-002'))).body.action, 'THROTTLE');
    assert.equal(a.isBlocked('8.8.8.8'), true);
    assert.equal(b.isBlocked('8.8.8.8'), false);
    const restrictions = await call(socketPath, 'GET', '/v1/restrictions', adminToken);
    assert.equal(restrictions.status, 200);
    assert.equal(restrictions.body.restrictions.length, 1);
    assert.equal(restrictions.body.restrictions[0].application_id, 'app-a');
    const released = await call(socketPath, 'POST', '/v1/restrictions/release', adminToken, { application_id: 'app-a', source_ip: '8.8.8.8' });
    assert.equal(released.body.affected, 1);
    assert.equal(a.isBlocked('8.8.8.8'), false);
    const audit = await call(socketPath, 'GET', '/v1/audit', adminToken);
    assert.deepEqual(audit.body.entries.map((entry) => entry.action), ['THROTTLE', 'release']);
    assert.equal(audit.body.entries[0].policy_id, 'app-a-login');
    assert.doesNotMatch(JSON.stringify(audit.body), /test-only-bridge-secret|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
    const simulated = await call(socketPath, 'POST', '/v1/policies/simulate', adminToken,
      { policy: a.policy, observations: [observation('app-a', 'event-001'), observation('app-a', 'event-002')], at: new Date(at).toISOString() });
    assert.equal(simulated.status, 200);
    assert.equal(simulated.body.results[0].decision, 'THROTTLE');
  } finally {
    await api.stop();
    await rm(dir, { recursive: true, force: true });
  }
});

test('local API rejects reused credentials and existing socket paths', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-api-'));
  try {
    const socketPath = path.join(dir, 'guard.sock');
    assert.throws(() => createLocalNodeGuardApi({ socketPath, managementToken: appAToken,
      applications: [{ applicationId: 'app-a', token: appAToken, guard: guardFor('app-a') }] }));
    const v2 = createIdentityGuardV2({ policy: { ...guardFor('app-a').policy, schema_version: 2, identity_scope: 'subject_id' },
      now: () => at, canActOnSource: () => true });
    assert.throws(() => createLocalNodeGuardApi({ socketPath, managementToken: adminToken,
      applications: [{ applicationId: 'app-a', token: appAToken, guard: v2 }] }), /matching policy guard/);
    const first = createLocalNodeGuardApi({ socketPath, managementToken: adminToken,
      applications: [{ applicationId: 'app-a', token: appAToken, guard: guardFor('app-a') }] });
    const second = createLocalNodeGuardApi({ socketPath, managementToken: adminToken,
      applications: [{ applicationId: 'app-a', token: appAToken, guard: guardFor('app-a') }] });
    await first.start();
    await assert.rejects(second.start());
    await first.stop();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('two independent client processes cannot submit or release each other\'s application state', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'nodeguard-api-processes-'));
  const socketPath = path.join(dir, 'guard.sock');
  const a = guardFor('app-a');
  const b = guardFor('app-b');
  const api = createLocalNodeGuardApi({ socketPath, managementToken: adminToken,
    applications: [{ applicationId: 'app-a', token: appAToken, guard: a },
      { applicationId: 'app-b', token: appBToken, guard: b }], now: () => at });
  try {
    await api.start();
    assert.equal((await callInChild(socketPath, appAToken, observation('app-b', 'event-001'))).status, 403);
    const first = await Promise.all([
      callInChild(socketPath, appAToken, observation('app-a', 'event-001')),
      callInChild(socketPath, appBToken, observation('app-b', 'event-002')),
    ]);
    assert.deepEqual(first.map((entry) => entry.body.action), ['recorded', 'recorded']);
    const second = await Promise.all([
      callInChild(socketPath, appAToken, observation('app-a', 'event-003')),
      callInChild(socketPath, appBToken, observation('app-b', 'event-004')),
    ]);
    assert.deepEqual(second.map((entry) => entry.body.action), ['THROTTLE', 'THROTTLE']);
    assert.equal(a.isBlocked('8.8.8.8'), true);
    assert.equal(b.isBlocked('8.8.8.8'), true);
    assert.equal((await call(socketPath, 'POST', '/v1/restrictions/release', appAToken,
      { application_id: 'app-b', source_ip: '8.8.8.8' })).status, 401);
    assert.equal((await call(socketPath, 'POST', '/v1/restrictions/release', adminToken,
      { application_id: 'app-a', source_ip: '8.8.8.8' })).body.affected, 1);
    assert.equal(a.isBlocked('8.8.8.8'), false);
    assert.equal(b.isBlocked('8.8.8.8'), true);
  } finally {
    await api.stop();
    await rm(dir, { recursive: true, force: true });
  }
});
