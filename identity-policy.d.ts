declare const identityBrand: unique symbol;
export type VerifiedIdentity = Readonly<{ [identityBrand]: true }>;
export declare function createVerifiedIdentity(input: {
  subjectId?: string;
  tenantId?: string;
  apiKeyId?: string;
}): VerifiedIdentity;

export type IdentityScopeV2 = "source_ip" | "subject_id" | "tenant_id" | "api_key_id";
export type IdentityPolicyV2 = Readonly<{
  schema_version: 2;
  policy_id: string;
  application_id: string;
  mode: "OBSERVE" | "ENFORCE";
  route_id: string;
  excluded_route_ids?: string[];
  reason_code: string;
  identity_scope: IdentityScopeV2;
  window_seconds: number;
  threshold: number;
  action: "THROTTLE" | "DENY";
  restriction_seconds: number;
}>;
export type IdentityObservationV2 = Readonly<{
  schema_version: 2;
  application_id: string;
  event_id: string;
  observed_at: string;
  route_id: string;
  reason_code: string;
  source_ip: string;
  protocol: "HTTP" | "HTTPS";
}>;
export type IdentityDecisionV2 = Readonly<{
  schema_version: 2;
  policy_id: string;
  application_id: string;
  route_id: string;
  reason_code: string;
  identity_scope: IdentityScopeV2;
  identity_ref: string;
  source_ip: string;
  action: "OBSERVE" | "THROTTLE" | "DENY";
  hit_count: number;
  observed_at: string;
  restriction_expires_at: string | null;
}>;
export declare function validateIdentityPolicyV2(input: unknown): IdentityPolicyV2;
export declare function validateIdentityObservationV2(input: unknown): IdentityObservationV2;
export declare function simulateIdentityPolicyV2(policy: IdentityPolicyV2,
  entries: Array<{ observation: IdentityObservationV2; fixture_identity?: string }>,
  options: { at: string }): Array<{ policy_id: string; identity_scope: IdentityScopeV2;
    identity_ref: string; hit_count: number; decision: "NONE" | "OBSERVE" | "THROTTLE" | "DENY";
    restriction_expires_at: string | null }>;
export declare function createIdentityGuardV2(options: {
  policy: IdentityPolicyV2;
  canActOnSource?: (verifiedSourceIp: string) => boolean;
  onDecision?: (decision: IdentityDecisionV2) => void | Promise<void>;
  now?: () => number;
  maxIdentities?: number;
  maxObservations?: number;
}): Readonly<{
  policy: IdentityPolicyV2;
  record(observation: IdentityObservationV2, identity?: VerifiedIdentity):
    | { accepted: false; reason: string }
    | { accepted: true; action: "recorded" | "OBSERVE" | "THROTTLE" | "DENY"; decision?: IdentityDecisionV2 };
  restriction(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }):
    | { action: "THROTTLE" | "DENY"; policyId: string; identityScope: IdentityScopeV2; expiresAt: string; retryAfterSeconds: number }
    | null;
  isBlocked(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }): boolean;
  release(context: { sourceIp: string; identity?: VerifiedIdentity }): number;
  snapshot(): Array<{ identity_scope: IdentityScopeV2; identity_ref: string; action: "THROTTLE" | "DENY"; expires_at: string; policy_id: string }>;
}>;
