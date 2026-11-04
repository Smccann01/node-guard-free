import { request } from 'node:http';
import path from 'node:path';
import { isEligibleSource } from './guard-core.mjs';

const MAX_RESPONSE_BYTES = 65_536;

/** App-scoped client for the optional local Unix-socket coordinator. */
export function createLocalNodeGuardClient({ socketPath, applicationId, token, timeoutMs = 2_000 } = {}) {
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || Buffer.byteLength(socketPath) > 100) {
    throw new TypeError('socketPath must be an absolute path no longer than 100 bytes');
  }
  if (typeof applicationId !== 'string' || !/^[a-z][a-z0-9._-]{1,63}$/.test(applicationId)) {
    throw new TypeError('applicationId must be a valid application identifier');
  }
  if (typeof token !== 'string' || Buffer.byteLength(token) < 32 || Buffer.byteLength(token) > 256) {
    throw new TypeError('token must be a 32-256 byte application credential');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new RangeError('timeoutMs must be 100-10000');
  }

  function post(route, body) {
    const data = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const outgoing = request({ socketPath, path: route, method: 'POST', agent: false, headers: {
        authorization: `Bearer ${token}`, 'content-type': 'application/json', 'content-length': Buffer.byteLength(data),
      } }, (incoming) => {
        let bytes = 0;
        const chunks = [];
        incoming.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) incoming.destroy(new Error('coordinator response too large'));
          else chunks.push(chunk);
        });
        incoming.on('error', reject);
        incoming.on('end', () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (incoming.statusCode !== 200) throw new Error(`coordinator returned HTTP ${incoming.statusCode}`);
            resolve(parsed);
          } catch (error) { reject(error); }
        });
      });
      outgoing.setTimeout(timeoutMs, () => outgoing.destroy(new Error('coordinator timed out')));
      outgoing.on('error', reject);
      outgoing.end(data);
    });
  }

  function evaluate(sourceIp) {
    if (!isEligibleSource(sourceIp)) throw new TypeError('evaluate requires a verified eligible public source IP');
    return post('/v1/decisions/evaluate', { application_id: applicationId, source_ip: sourceIp }).then((result) => {
      if (!result || result.application_id !== applicationId || result.source_ip !== sourceIp ||
          !['ALLOW', 'THROTTLE', 'DENY'].includes(result.decision) ||
          (result.decision === 'ALLOW' && result.restriction !== null) ||
          (result.decision !== 'ALLOW' && (!result.restriction ||
            typeof result.restriction.policy_id !== 'string' ||
            typeof result.restriction.expires_at !== 'string' ||
            !Number.isSafeInteger(result.restriction.retry_after_seconds) ||
            result.restriction.retry_after_seconds < 1 || result.restriction.retry_after_seconds > 300))) {
        throw new Error('invalid coordinator decision');
      }
      return result;
    });
  }

  function record(observation) {
    if (!observation || typeof observation !== 'object' || Array.isArray(observation) ||
        observation.application_id !== applicationId) throw new TypeError('observation must match this application');
    return post('/v1/observations', observation);
  }

  return Object.freeze({ evaluate, record });
}
