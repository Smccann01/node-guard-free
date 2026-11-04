import type { VerifiedIdentity } from "./identity-policy.js";
export declare function createNextIdentityGuardV2<RequestType = globalThis.Request>(options: {
  guard: {
    policy: { schema_version: 2; identity_scope: string };
    restriction(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }): { action: "THROTTLE" | "DENY"; retryAfterSeconds: number } | null;
  };
  getVerifiedSourceIp: (request: RequestType) => string | Promise<string>;
  getRouteId: (request: RequestType) => string | Promise<string>;
  getVerifiedIdentity?: (request: RequestType) => VerifiedIdentity | Promise<VerifiedIdentity>;
}): (request: RequestType) => Promise<Response | null>;
