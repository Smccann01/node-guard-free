import { createNodeGuard, type GuardInstance } from '@network-decode/node-guard';
import { createExpressNodeGuard } from '@network-decode/node-guard/express';
import { createNextRouteGuard } from '@network-decode/node-guard/next-route';
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import { replayIdentityPolicyV2, replayPolicyV1 } from '@network-decode/node-guard/replay-policy';
import type { PolicyV1, ObservationV1 } from '@network-decode/node-guard/policy';
import { createTrustedSourceResolver } from '@network-decode/node-guard/trusted-source';
import { createVerifiedIdentity, createIdentityGuardV2, type IdentityPolicyV2 } from '@network-decode/node-guard/identity-policy';
import { createExpressIdentityGuardV2 } from '@network-decode/node-guard/identity-express';
import { createNextIdentityGuardV2 } from '@network-decode/node-guard/identity-next-route';
import { createLocalNodeGuardApi } from '@network-decode/node-guard/local-api';

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
const replay = replayPolicyV1({ policy, observations: [observation], at: observation.observed_at });
void replay.enforcement_scope;
const identityReplay = replayIdentityPolicyV2({ policy: { ...policy, schema_version: 2,
  identity_scope: 'subject_id' }, entries: [], at: observation.observed_at });
void identityReplay.enforcement_scope;
const resolveSource = createTrustedSourceResolver();
const express = createExpressNodeGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
const next = createNextRouteGuard({ guard, getVerifiedSourceIp: () => '8.8.8.8' });
void [express, next, resolveSource];
const identityPolicy: IdentityPolicyV2 = { ...policy, schema_version: 2, identity_scope: 'subject_id' };
const identity = createVerifiedIdentity({ subjectId: 'member-01' });
const identityGuard = createIdentityGuardV2({ policy: identityPolicy });
identityGuard.record({ ...observation, schema_version: 2 }, identity);
identityGuard.restriction({ sourceIp: '8.8.8.8', routeId: 'auth.login', identity });
const identityExpress = createExpressIdentityGuardV2({ guard: identityGuard,
  getVerifiedSourceIp: () => '8.8.8.8', getRouteId: () => 'auth.login', getVerifiedIdentity: () => identity });
const identityNext = createNextIdentityGuardV2({ guard: identityGuard,
  getVerifiedSourceIp: () => '8.8.8.8', getRouteId: () => 'auth.login', getVerifiedIdentity: () => identity });
void [identityExpress, identityNext];
const api = createLocalNodeGuardApi({ socketPath: '/tmp/nodeguard-types-smoke.sock', managementToken: 'm'.repeat(32),
  applications: [{ applicationId: 'billing-api', token: 'a'.repeat(32), guard: runtime }] });
void api;
