import type { ObservationV1, PolicyV1 } from './policy.js';

export type ReplayEventV1 = Readonly<{
  event_id: string;
  observed_at: string;
  source_ip: string;
  accepted: boolean;
  record_action: 'recorded' | 'OBSERVE' | 'THROTTLE' | 'DENY' | 'REJECTED';
  rejection_reason?: string;
  effective_action: 'ALLOW' | 'THROTTLE' | 'DENY';
  restriction_expires_at: string | null;
}>;

export declare function replayPolicyV1(options: {
  policy: PolicyV1;
  observations: ObservationV1[];
  at: string;
  protectedSources?: string[];
}): Readonly<{
  schema_version: 1;
  policy_id: string;
  application_id: string;
  policy_mode: 'OBSERVE' | 'ENFORCE';
  replay_at: string;
  event_count: number;
  timeline: ReplayEventV1[];
  active_restrictions: Array<{ source_ip: string; action: 'THROTTLE' | 'DENY'; expires_at: string }>;
  enforcement_scope: 'simulation_only';
}>;
