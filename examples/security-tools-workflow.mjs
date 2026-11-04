import { createHmac, randomBytes } from 'node:crypto';
import { createWebhookShield } from '../webhook-shield.mjs';
import { validateObservationV1 } from '../policy.mjs';
import { comparePolicySimulation } from '../policy-diff.mjs';
import { replayPolicyV1 } from '../replay-policy.mjs';

// Synthetic, local-only example. The sender and receiver use a fresh key in this process.
const at = '2026-11-04T10:00:20Z';
const now = Date.parse(at);
const secret = randomBytes(32);
const timestamp = String(Math.floor(now / 1_000));
const deliveryId = 'demo-delivery-001';
const observations = ['2026-11-04T10:00:00Z', '2026-11-04T10:00:01Z'].map((observed_at, index) => ({
  schema_version: 1,
  application_id: 'billing-api',
  event_id: `demo-event-00${index + 1}`,
  observed_at,
  route_id: 'auth.login',
  reason_code: 'authentication_failure',
  source_ip: '8.8.8.8',
  protocol: 'HTTPS',
}));
const rawBody = Buffer.from(JSON.stringify({ observations }));
const signature = createHmac('sha256', secret)
  .update('nodeguard-webhook-v1\n').update(timestamp).update('\n')
  .update(deliveryId).update('\n').update(rawBody).digest('hex');
const shield = createWebhookShield({ secret, now: () => now });
const delivery = shield.verify({ rawBody, timestamp, eventId: deliveryId, signature });
if (!delivery.accepted) throw new Error(`demo delivery rejected: ${delivery.reason}`);

// A valid HMAC authenticates delivery. Validate the event schema and trust the sender's
// source assertion only because this synthetic sender is the application itself.
const parsed = JSON.parse(rawBody.toString('utf8'));
if (!parsed || !Array.isArray(parsed.observations)) throw new TypeError('invalid demo payload');
const verifiedObservations = parsed.observations.map(validateObservationV1);
const current = {
  schema_version: 1, policy_id: 'auth-login-v1', application_id: 'billing-api',
  mode: 'OBSERVE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60,
};
const proposed = { ...current, mode: 'ENFORCE' };
const comparison = comparePolicySimulation(current, proposed, verifiedObservations,
  { at, redactSources: true });
const replay = replayPolicyV1({ policy: proposed, observations: verifiedObservations,
  at, protectedSources: ['1.1.1.1'], redactSources: true });

process.stdout.write(`${JSON.stringify({
  delivery: { accepted: delivery.accepted, event_id: delivery.eventId },
  policy_review: comparison,
  replay,
}, null, 2)}\n`);
