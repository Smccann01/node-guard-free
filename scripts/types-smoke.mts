import { createNodeGuard, type GuardInstance } from '@network-decode/node-guard';
import { createExpressNodeGuard } from '@network-decode/node-guard/express';
import { createNextRouteGuard } from '@network-decode/node-guard/next-route';
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import type { PolicyV1, ObservationV1 } from '@network-decode/node-guard/policy';
import { createTrustedSourceResolver } from '@network-decode/node-guard/trusted-source';

const guard: GuardInstance = createNodeGuard({ mode: 'observe' });
const policy: PolicyV1 = {
  schema_version: 1, policy_id: 'login-v1', application_id: 'billing-api',
  mode: 'OBSERVE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60,
};
const observation: ObservationV1 = {
  schema_version: 1, application_id: 'billing-api', event_id: 'event-001',
  observed_at: new Date().toISOString(), route_id: 'auth.login',
  reason_code: 'authentication_failure', source_ip: '8.8.8.8', protocol: 'HTTPS',
};
const runtime = createPolicyGuardV1({ policy });
runtime.record(observation);
const resolveSource = createTrustedSourceResolver();
const express = createExpressNodeGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
const next = createNextRouteGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
void [express, next, resolveSource];
