import type { VerifiedIdentity } from "./identity-policy.js";
import type { createIdentityPolicySetV2 } from "./identity-policy-set.js";

export declare function createNextIdentityPolicySetV2<RequestType = globalThis.Request>(options: {
  policySet: ReturnType<typeof createIdentityPolicySetV2>;
  getVerifiedSourceIp: (request: RequestType) => string | Promise<string>;
  getRouteId: (request: RequestType) => string | Promise<string>;
  getVerifiedIdentity?: (request: RequestType) => VerifiedIdentity | Promise<VerifiedIdentity>;
}): (request: RequestType) => Promise<Response | null>;
