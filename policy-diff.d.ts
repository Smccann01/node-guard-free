import type { PolicyV1 } from './policy.js';
import type { IdentityPolicyV2 } from './identity-policy.js';
import type { ObservationV1 } from './policy.js';
import type { IdentityObservationV2 } from './identity-policy.js';

export type PolicyDiff = {
  schema_version: 1;
  policy_schema_version: 1 | 2;
  application_id: string;
  policy_id: string;
  before_fingerprint_sha256: string;
  after_fingerprint_sha256: string;
  changed: boolean;
  changes: Array<{ field: string; before: string | number | string[] | null; after: string | number | string[] | null }>;
  review_reasons: string[];
  activation: 'none';
};
export declare function diffPolicies(before: PolicyV1 | IdentityPolicyV2, after: PolicyV1 | IdentityPolicyV2): PolicyDiff;
export declare function comparePolicySimulation(
  before: PolicyV1 | IdentityPolicyV2,
  after: PolicyV1 | IdentityPolicyV2,
  observations: ObservationV1[] | Array<{ observation: IdentityObservationV2; fixture_identity?: string }>,
  options: { at: string },
): PolicyDiff & {
  simulation_at: string;
  fixture_count: number;
  decision_changes: Array<Record<string, unknown>>;
  comparison_scope: 'simulation_only';
};
