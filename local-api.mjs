import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { lstat, stat, chmod, unlink } from 'node:fs/promises';
import path from 'node:path';
import { isEligibleSource } from './index.mjs';
import { simulatePolicyV1 } from './policy.mjs';

const MAX_BODY_BYTES = 65_536;
const MAX_APPS = 32;
class BodyTooLargeError extends Error {}

function credentialHash(value, name) {
  if (typeof value !== 'string' || Buffer.byteLength(value) < 32 || Buffer.byteLength(value) > 256) {
    throw new TypeError(`${name} must be a separate 32-256 byte credential`);
  }
  return createHash('sha256').update(value).digest();
}

function matches(header, expected) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const supplied = createHash('sha256').update(header.slice(7)).digest();
  return timingSafeEqual(supplied, expected);
}

async function jsonBody(request) {
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType)) {
    throw new TypeError('Content-Type must be application/json');
  }
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw new BodyTooLargeError('request body exceeds 64 KiB');
    chunks.push(chunk);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('JSON body must be an object');
  return parsed;
}

function reply(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  response.end(JSON.stringify(payload));
}

/** Local Unix-socket API. Application credentials can only submit observations for their own guard. */
export function createLocalNodeGuardApi({ socketPath, applications, managementToken, maxAuditEntries = 1000, now = Date.now } = {}) {
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || Buffer.byteLength(socketPath) > 100) {
    throw new TypeError('socketPath must be an absolute path no longer than 100 bytes');
  }
  if (!Array.isArray(applications) || applications.length < 1 || applications.length > MAX_APPS) {
    throw new RangeError(`applications must contain 1-${MAX_APPS} entries`);
  }
  if (!Number.isSafeInteger(maxAuditEntries) || maxAuditEntries < 1 || maxAuditEntries > 10_000) {
    throw new RangeError('maxAuditEntries must be 1-10000');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a function');
  const managementHash = credentialHash(managementToken, 'managementToken');
  const apps = new Map();
  const tokenHashes = [];
  for (const app of applications) {
    if (!app || typeof app.applicationId !== 'string' || !/^[a-z][a-z0-9._-]{1,63}$/.test(app.applicationId) ||
        app.guard?.policy?.schema_version !== 1 || app.guard.policy.application_id !== app.applicationId || typeof app.guard.record !== 'function' ||
        typeof app.guard.restriction !== 'function' || typeof app.guard.release !== 'function' ||
        typeof app.guard.snapshot !== 'function' || apps.has(app.applicationId)) {
      throw new TypeError('each application needs a unique ID and matching policy guard');
    }
    const tokenHash = credentialHash(app.token, `application ${app.applicationId} token`);
    if (timingSafeEqual(tokenHash, managementHash) || tokenHashes.some((other) => timingSafeEqual(tokenHash, other))) {
      throw new TypeError('application and management credentials must be distinct');
    }
    tokenHashes.push(tokenHash);
    apps.set(app.applicationId, { guard: app.guard, tokenHash });
  }

  const audit = [];
  let server;
  let socketIdentity;
  function auditAction(action, applicationId, sourceIp, affected) {
    audit.push(Object.freeze({ at: new Date(now()).toISOString(), action, application_id: applicationId,
      policy_id: apps.get(applicationId).guard.policy.policy_id, source_ip: sourceIp, affected }));
    if (audit.length > maxAuditEntries) audit.shift();
  }

  async function handle(request, response) {
    try {
      const pathname = new URL(request.url, 'http://localhost').pathname;
      const authorization = request.headers.authorization;
      if (pathname === '/v1/observations' && request.method === 'POST') {
        const app = [...apps.entries()].find(([, value]) => matches(authorization, value.tokenHash));
        if (!app) return reply(response, 401, { error: 'unauthorized' });
        const body = await jsonBody(request);
        if (body.application_id !== app[0]) return reply(response, 403, { error: 'application_scope' });
        const result = app[1].guard.record(body);
        if (!result.accepted) return reply(response, 422, { error: result.reason });
        if (result.action !== 'recorded') auditAction(result.action, app[0], body.source_ip, 1);
        return reply(response, 200, result);
      }
      if (pathname === '/v1/decisions/evaluate' && request.method === 'POST') {
        const app = [...apps.entries()].find(([, value]) => matches(authorization, value.tokenHash));
        if (!app) return reply(response, 401, { error: 'unauthorized' });
        const body = await jsonBody(request);
        if (body.application_id !== app[0]) return reply(response, 403, { error: 'application_scope' });
        if (Object.keys(body).some((key) => !['application_id', 'source_ip'].includes(key)) ||
            !isEligibleSource(body.source_ip)) return reply(response, 400, { error: 'invalid_source' });
        const restriction = app[1].guard.restriction(body.source_ip);
        return reply(response, 200, { application_id: app[0], source_ip: body.source_ip,
          decision: restriction?.action ?? 'ALLOW',
          restriction: restriction ? { policy_id: restriction.policyId,
            expires_at: restriction.expiresAt, retry_after_seconds: restriction.retryAfterSeconds } : null });
      }
      if (!matches(authorization, managementHash)) return reply(response, 401, { error: 'unauthorized' });
      if (pathname === '/v1/health' && request.method === 'GET') {
        return reply(response, 200, { status: 'ok', state_scope: 'one_process', applications: apps.size });
      }
      if (pathname === '/v1/restrictions' && request.method === 'GET') {
        const restrictions = [];
        let truncated = false;
        for (const [applicationId, app] of apps) {
          for (const entry of app.guard.snapshot()) {
            if (restrictions.length >= 1000) { truncated = true; break; }
            restrictions.push({ application_id: applicationId, ...entry });
          }
          if (truncated) break;
        }
        return reply(response, 200, { restrictions, truncated });
      }
      if (pathname === '/v1/restrictions/release' && request.method === 'POST') {
        const body = await jsonBody(request);
        if (Object.keys(body).some((key) => !['application_id', 'source_ip'].includes(key)) ||
            typeof body.application_id !== 'string' || !apps.has(body.application_id) || !isEligibleSource(body.source_ip)) {
          return reply(response, 400, { error: 'invalid_release' });
        }
        const affected = apps.get(body.application_id).guard.release(body.source_ip);
        auditAction('release', body.application_id, body.source_ip, affected);
        return reply(response, 200, { affected });
      }
      if (pathname === '/v1/policies/simulate' && request.method === 'POST') {
        const body = await jsonBody(request);
        const results = simulatePolicyV1(body.policy, body.observations, { at: body.at });
        return reply(response, 200, { results });
      }
      if (pathname === '/v1/audit' && request.method === 'GET') {
        return reply(response, 200, { entries: audit.slice(-1000), truncated: audit.length > 1000 });
      }
      return reply(response, 404, { error: 'not_found' });
    } catch (error) {
      const invalid = error instanceof SyntaxError || error instanceof TypeError || error instanceof RangeError;
      return reply(response, error instanceof BodyTooLargeError ? 413 : invalid ? 400 : 500,
        { error: error instanceof BodyTooLargeError ? 'request_too_large' : invalid ? 'invalid_request' : 'internal_error' });
    }
  }

  async function start() {
    if (server) throw new Error('local API already started');
    const directory = await stat(path.dirname(socketPath));
    if (!directory.isDirectory() || (process.getuid && directory.uid !== process.getuid()) || (directory.mode & 0o022) !== 0) {
      throw new Error('socket directory must be owned by this process and not group or world writable');
    }
    try { await lstat(socketPath); throw new Error('socket path already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const candidate = createServer((request, response) => { void handle(request, response); });
    candidate.requestTimeout = 10_000;
    candidate.headersTimeout = 5_000;
    candidate.maxHeadersCount = 32;
    try {
      await new Promise((resolve, reject) => { candidate.once('error', reject); candidate.listen(socketPath, resolve); });
      await chmod(socketPath, 0o600);
      const identity = await lstat(socketPath);
      socketIdentity = { dev: identity.dev, ino: identity.ino };
      server = candidate;
    } catch (error) {
      candidate.close();
      throw error;
    }
  }

  async function stop() {
    if (!server) return;
    const active = server;
    server = undefined;
    await new Promise((resolve, reject) => active.close((error) => error ? reject(error) : resolve()));
    try {
      const current = await lstat(socketPath);
      if (current.isSocket() && current.dev === socketIdentity?.dev && current.ino === socketIdentity?.ino) await unlink(socketPath);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    socketIdentity = undefined;
  }

  return Object.freeze({ start, stop });
}
