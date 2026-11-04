# Webhook Shield source candidate

Webhook Shield verifies a **Node Guard v1** HMAC envelope for webhooks whose sender you control. It accepts exact request bytes, a decimal epoch-seconds timestamp, a unique event ID, and a lowercase hexadecimal SHA-256 signature. It rejects modified messages, stale timestamps, duplicates inside the accepted window, oversized bodies, and full replay storage. No account, license, or HoneyMesh agent is required.

It is not a drop-in validator for Stripe, GitHub, or another provider's signature format. Those providers define their own signed payload and key-rotation rules. Use their official verifier until a dedicated adapter is implemented and tested.

## Signed envelope

The sender computes HMAC-SHA256 with a separate random secret of at least 32 bytes over the concatenation of:

```text
nodeguard-webhook-v1\n<timestamp>\n<event_id>\n
<raw request bytes>
```

The signature is the 64-character lowercase hex digest. The timestamp and event ID are signed along with the body. Each endpoint needs its own secret and unique event IDs. Protect the secret in your deployment's secret store; do not include it in source or logs.

For a sender you control, sign the exact bytes you transmit:

```js
import { createHmac, randomUUID } from 'node:crypto';

const rawBody = Buffer.from(JSON.stringify({ type: 'order.created', order_id: 'example-123' }));
const timestamp = String(Math.floor(Date.now() / 1000));
const eventId = randomUUID();
const signature = createHmac('sha256', process.env.WEBHOOK_SECRET)
  .update('nodeguard-webhook-v1\n').update(timestamp).update('\n')
  .update(eventId).update('\n').update(rawBody).digest('hex');
await fetch('https://your-receiver.example/webhooks/my-service', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-ng-timestamp': timestamp,
    'x-ng-event-id': eventId, 'x-ng-signature': signature },
  body: rawBody,
});
```

## Receiver example

```js
import express from 'express';
import { createWebhookShield } from '@network-decode/node-guard/webhook-shield';

const app = express();
const shield = createWebhookShield({ secret: process.env.WEBHOOK_SECRET });

app.post('/webhooks/my-service', express.raw({ type: 'application/json', limit: '256kb' }), (req, res) => {
  const result = shield.verify({
    rawBody: req.body,
    timestamp: req.get('x-ng-timestamp'),
    eventId: req.get('x-ng-event-id'),
    signature: req.get('x-ng-signature'),
  });
  if (!result.accepted) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString('utf8'));
  // Handle only the event types this endpoint is authorized to receive.
  res.sendStatus(204);
});
```

This source candidate is not in the public npm alpha. Adapt the example only after a package containing it has been published and verified.

The replay cache is bounded and lives in one process. A restart or another process does not share that cache. For multi-process or durable replay prevention, store verified event IDs in an atomic shared store before performing side effects. The built-in clock-regression check rejects requests if system time moves backward during a process lifetime. Keep time synchronized and monitor rejected requests. Webhook Shield does not parse JSON, send HTTP responses, manage endpoint secrets, or create host-level blocks.
