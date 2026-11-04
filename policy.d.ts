export type PolicyReasonCode = import("./index.js").ReasonCode | "authentication_failure";
export type PolicyV1 = {
  schema_version: 1;
  policy_id: string;
  application_id: string;
  mode: "OBSERVE" | "ENFORCE";
  route_id: string;
  reason_code: PolicyReasonCode;
  window_seconds: number;
  threshold: number;
  action: "THROTTLE" | "DENY";
  restriction_seconds: number;
};
export type ObservationV1 = {
  schema_version: 1;
  application_id: string;
  event_id: string;
  observed_at: string;
  route_id: string;
  reason_code: PolicyReasonCode;
  source_ip: string;
  protocol: "HTTP" | "HTTPS";
};
export declare const POLICY_REASON_CODES: readonly PolicyReasonCode[];
export declare function validatePolicyV1(policy: unknown): Readonly<PolicyV1>;
export declare function validateObservationV1(observation: unknown): Readonly<ObservationV1>;
export declare function simulatePolicyV1(policy: unknown, observations: unknown[], options: { at: string }): Array<{
  policy_id: string;
  source_ip: string;
  hit_count: number;
  decision: "NONE" | "OBSERVE" | "THROTTLE" | "DENY";
  restriction_expires_at: string | null;
}>;
