import type { PolicyV1 } from './policy.js';
import type { IdentityPolicyV2 } from './identity-policy.js';

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
