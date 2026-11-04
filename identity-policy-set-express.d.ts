import type { VerifiedIdentity } from "./identity-policy.js";
import type { createIdentityPolicySetV2 } from "./identity-policy-set.js";

export declare function createExpressIdentityPolicySetV2<Request = unknown>(options: {
  policySet: ReturnType<typeof createIdentityPolicySetV2>;
  getVerifiedSourceIp: (request: Request) => string;
  getRouteId: (request: Request) => string;
  getVerifiedIdentity?: (request: Request) => VerifiedIdentity;
}): (request: Request, response: {
  set(field: string, value: string): unknown;
  status(code: number): { json(body: unknown): unknown };
}, next: (error?: unknown) => void) => unknown;
