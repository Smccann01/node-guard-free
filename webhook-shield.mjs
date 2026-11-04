import { createHmac, timingSafeEqual } from 'node:crypto';

const MAX_SECRET_BYTES = 256;
const MAX_BODY_BYTES = 1_048_576;
const MAX_EVENTS = 100_000;
const MAX_TOLERANCE_SECONDS = 900;
const EVENT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const TIMESTAMP = /^(?:0|[1-9][0-9]{0,12})$/;
const SIGNATURE = /^[a-f0-9]{64}$/;
const PREFIX = Buffer.from('nodeguard-webhook-v1\n');

function positiveInteger(value, name, max) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new RangeError(`${name} must be an integer from 1 to ${max}`);
  }
  return value;
}

function secretBytes(input) {
  if (typeof input !== 'string' && !Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    throw new TypeError('secret must be a string or byte array');
  }
  const key = Buffer.from(input);
  if (key.length < 32 || key.length > MAX_SECRET_BYTES) {
    throw new RangeError(`secret must be 32-${MAX_SECRET_BYTES} bytes`);
  }
  return key;
}

function signedBytes(key, timestamp, eventId, rawBody) {
  return createHmac('sha256', key)
    .update(PREFIX).update(timestamp).update('\n').update(eventId).update('\n').update(rawBody)
    .digest();
}

/** Verifies Node Guard's own v1 raw-body HMAC envelope for customer-controlled webhooks. */
export function createWebhookShield({ secret, toleranceSeconds = 300, maxBodyBytes = 262_144,
  maxEvents = 10_000, now = Date.now } = {}) {
  const key = secretBytes(secret);
  positiveInteger(toleranceSeconds, 'toleranceSeconds', MAX_TOLERANCE_SECONDS);
  positiveInteger(maxBodyBytes, 'maxBodyBytes', MAX_BODY_BYTES);
  positiveInteger(maxEvents, 'maxEvents', MAX_EVENTS);
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const seen = new Map();
  const toleranceMs = toleranceSeconds * 1_000;
  let lastNow = 0;
  let verifiedCount = 0;

  function prune(at) {
    for (const [eventId, expiresAt] of seen) {
      if (expiresAt <= at) seen.delete(eventId);
    }
  }

  function verify({ rawBody, timestamp, eventId, signature } = {}) {
    if (!(rawBody instanceof Uint8Array) || rawBody.byteLength > maxBodyBytes) {
      return { accepted: false, reason: 'invalid_body' };
    }
    if (typeof timestamp !== 'string' || !TIMESTAMP.test(timestamp) ||
        typeof eventId !== 'string' || !EVENT_ID.test(eventId) ||
        typeof signature !== 'string' || !SIGNATURE.test(signature)) {
      return { accepted: false, reason: 'invalid_envelope' };
    }
    const observedAt = Number(timestamp) * 1_000;
    const at = now();
    if (!Number.isSafeInteger(at) || at < 0) throw new TypeError('now must return epoch milliseconds');
    if (at < lastNow) return { accepted: false, reason: 'clock_regressed' };
    lastNow = at;
    if (!Number.isSafeInteger(observedAt + toleranceMs) || at < observedAt - toleranceMs ||
        at >= observedAt + toleranceMs) {
      return { accepted: false, reason: 'outside_window' };
    }
    const expected = signedBytes(key, timestamp, eventId, rawBody);
    if (!timingSafeEqual(expected, Buffer.from(signature, 'hex'))) {
      return { accepted: false, reason: 'invalid_signature' };
    }
    verifiedCount += 1;
    if (verifiedCount % 128 === 0 || seen.size >= maxEvents) prune(at);
    if (seen.has(eventId)) return { accepted: false, reason: 'duplicate_event' };
    if (seen.size >= maxEvents) return { accepted: false, reason: 'capacity_exhausted' };
    seen.set(eventId, observedAt + toleranceMs);
    return { accepted: true, eventId, verifiedAt: new Date(at).toISOString() };
  }

  function status() {
    return Object.freeze({ trackedEvents: seen.size, maxEvents, toleranceSeconds,
      maxBodyBytes, stateScope: 'one_process' });
  }

  return Object.freeze({ verify, status });
}
