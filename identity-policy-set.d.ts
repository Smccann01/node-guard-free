import type { VerifiedIdentity, IdentityPolicyV2, IdentityObservationV2, IdentityDecisionV2,
  IdentityScopeV2 } from "./identity-policy.js";

export type IdentityRestrictionV2 = { action: "THROTTLE" | "DENY"; policyId: string;
  identityScope: IdentityScopeV2; expiresAt: string; retryAfterSeconds: number };
export declare function createIdentityPolicySetV2(options: {
  policies: IdentityPolicyV2[];
  canActOnSource?: (verifiedSourceIp: string) => boolean;
  onDecision?: (decision: IdentityDecisionV2) => void | Promise<void>;
  now?: () => number;
  maxSeenEvents?: number;
  maxIdentitiesPerPolicy?: number;
  maxObservationsPerPolicy?: number;
}): Readonly<{
  policies: readonly IdentityPolicyV2[];
  matches(routeId: string): boolean;
  record(observation: IdentityObservationV2, identity?: VerifiedIdentity):
    | { accepted: false; reason: string }
    | { accepted: true; action: "recorded" | "OBSERVE" | "THROTTLE" | "DENY"; decision?: IdentityDecisionV2 };
  restriction(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }): IdentityRestrictionV2 | null;
  isBlocked(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }): boolean;
  release(context: { policyId: string; sourceIp: string; identity?: VerifiedIdentity }): number;
  snapshot(): Array<{ identity_scope: IdentityScopeV2; identity_ref: string; action: "THROTTLE" | "DENY";
    expires_at: string; policy_id: string }>;
}>;
