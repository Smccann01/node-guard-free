import type { ObservationV1, PolicyV1 } from "./policy.js";

export type PolicyRuntimeDecision = Readonly<{
  schema_version: 1;
  policy_id: string;
  application_id: string;
  route_id: string;
  source_ip: string;
  reason_code: string;
  action: "OBSERVE" | "THROTTLE" | "DENY";
  hit_count: number;
  observed_at: string;
  restriction_expires_at: string | null;
}>;
export declare function createPolicyGuardV1(options: {
  policy: PolicyV1;
  canActOnSource?: (verifiedSourceIp: string) => boolean;
  onDecision?: (decision: PolicyRuntimeDecision) => void | Promise<void>;
  now?: () => number;
  maxSources?: number;
  maxObservations?: number;
}): Readonly<{
  policy: Readonly<PolicyV1>;
  record(observation: ObservationV1):
    | { accepted: false; reason: "policy_mismatch" | "source_excluded" | "outside_window" | "capacity_exhausted" | "duplicate_event" }
    | { accepted: true; action: "recorded" | "OBSERVE" | "THROTTLE" | "DENY"; decision?: PolicyRuntimeDecision };
  restriction(sourceIp: string): { action: "THROTTLE" | "DENY"; policyId: string; expiresAt: string; retryAfterSeconds: number } | null;
  isBlocked(sourceIp: string): boolean;
  release(sourceIp: string): number;
  snapshot(): Array<{ sourceIp: string; action: "THROTTLE" | "DENY"; policyId: string; expiresAt: string; retryAfterSeconds: number }>;
}>;
