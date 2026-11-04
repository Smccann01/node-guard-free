import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { once } from 'node:events';
import test from 'node:test';
import express from 'express';
import { createWebhookShield } from './webhook-shield.mjs';

const secret = 'test-only-endpoint-secret-with-at-least-32-bytes';
const start = Date.parse('2026-11-04T12:00:00Z');

function envelope(eventId, body, timestamp = String(start / 1_000)) {
  const rawBody = Buffer.from(body);
  const signature = createHmac('sha256', secret)
    .update('nodeguard-webhook-v1\n').update(timestamp).update('\n')
    .update(eventId).update('\n').update(rawBody).digest('hex');
  return { rawBody, timestamp, eventId, signature };
}

test('signed raw-body envelope is accepted once and binds body, timestamp, and event ID', () => {
  const shield = createWebhookShield({ secret, now: () => start });
  const signed = envelope('event-001', '{"status":"paid"}');
  assert.equal(shield.verify({ ...signed, rawBody: Buffer.from('{"status":"free"}') }).reason, 'invalid_signature');
  assert.equal(shield.verify({ ...signed, timestamp: String(start / 1_000 + 1) }).reason, 'invalid_signature');
  assert.equal(shield.verify({ ...signed, eventId: 'event-002' }).reason, 'invalid_signature');
  assert.equal(shield.verify(signed).accepted, true);
  assert.equal(shield.verify(signed).reason, 'duplicate_event');
  assert.equal(shield.status().trackedEvents, 1);
});

test('stale, future, malformed, oversized, and unsigned requests fail without consuming replay slots', () => {
  const shield = createWebhookShield({ secret, now: () => start, toleranceSeconds: 60, maxBodyBytes: 16, maxEvents: 1 });
  assert.equal(shield.verify(envelope('old', '{}', String(start / 1_000 - 61))).reason, 'outside_window');
  assert.equal(shield.verify(envelope('future', '{}', String(start / 1_000 + 61))).reason, 'outside_window');
  assert.equal(shield.verify({ ...envelope('event-001', '{}'), timestamp: '001' }).reason, 'invalid_envelope');
  assert.equal(shield.verify({ ...envelope('event-001', '{}'), eventId: 'bad\nevent' }).reason, 'invalid_envelope');
  assert.equal(shield.verify({ ...envelope('event-001', '{}'), signature: 'g'.repeat(64) }).reason, 'invalid_envelope');
  assert.equal(shield.verify({ ...envelope('event-001', '{}'), rawBody: '{}' }).reason, 'invalid_body');
  assert.equal(shield.verify(envelope('large', 'x'.repeat(17))).reason, 'invalid_body');
  assert.equal(shield.verify({ ...envelope('event-001', '{}'), signature: '0'.repeat(64) }).reason, 'invalid_signature');
  assert.equal(shield.status().trackedEvents, 0);
  assert.equal(shield.verify(envelope('event-001', '{}')).accepted, true);
  assert.equal(shield.verify(envelope('event-002', '{}')).reason, 'capacity_exhausted');
});

test('replay state expires within one process and a regressed clock fails closed', () => {
  let at = start;
  const shield = createWebhookShield({ secret, now: () => at, toleranceSeconds: 60, maxEvents: 1 });
  assert.equal(shield.verify(envelope('event-001', '{}')).accepted, true);
  at -= 1_000;
  assert.equal(shield.verify(envelope('event-002', '{}')).reason, 'clock_regressed');
  at = start + 61_000;
  assert.equal(shield.verify(envelope('event-002', '{}', String(at / 1_000))).accepted, true);
  assert.equal(shield.status().trackedEvents, 1);
  assert.equal(shield.verify(envelope('event-001', '{}')).reason, 'outside_window');
});

test('future-dated signatures remain replay-protected through their full accepted window', () => {
  let at = start;
  const shield = createWebhookShield({ secret, now: () => at, toleranceSeconds: 300, maxEvents: 1 });
  const signed = envelope('future-001', '{}', String(start / 1_000 + 299));
  assert.equal(shield.verify(signed).accepted, true);
  at += 301_000;
  assert.equal(shield.verify(signed).reason, 'duplicate_event');
  at += 299_000;
  assert.equal(shield.verify(signed).reason, 'outside_window');
});

test('configuration requires a bounded separate secret and bounded memory', () => {
  assert.throws(() => createWebhookShield({ secret: 'short' }), /secret must be/);
  assert.throws(() => createWebhookShield({ secret, maxEvents: 0 }), /maxEvents/);
  assert.throws(() => createWebhookShield({ secret, toleranceSeconds: 901 }), /toleranceSeconds/);
  assert.throws(() => createWebhookShield({ secret, maxBodyBytes: 1_048_577 }), /maxBodyBytes/);
  const shield = createWebhookShield({ secret });
  assert.equal(shield.status().stateScope, 'one_process');
  assert.doesNotMatch(JSON.stringify(shield.status()), /test-only-endpoint-secret/);
});

test('raw HTTP webhook delivery accepts the signed request and rejects replay and body changes', async () => {
  const shield = createWebhookShield({ secret, now: () => start });
  const app = express();
  app.post('/webhook', express.raw({ type: 'application/json', limit: '256kb' }), (request, response) => {
    const result = shield.verify({ rawBody: request.body, timestamp: request.get('x-ng-timestamp'),
      eventId: request.get('x-ng-event-id'), signature: request.get('x-ng-signature') });
    response.sendStatus(result.accepted ? 204 : 401);
  });
  const server = app.listen(0, '127.0.0.1');
  try {
    await once(server, 'listening');
    const url = `http://127.0.0.1:${server.address().port}/webhook`;
    const signed = envelope('http-001', '{"status":"paid"}');
    async function send(rawBody) {
      return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json',
        'x-ng-timestamp': signed.timestamp, 'x-ng-event-id': signed.eventId,
        'x-ng-signature': signed.signature }, body: rawBody });
    }
    assert.equal((await send(signed.rawBody)).status, 204);
    assert.equal((await send(signed.rawBody)).status, 401);
    assert.equal((await send(Buffer.from('{"status":"free"}'))).status, 401);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
