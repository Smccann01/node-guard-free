import type { VerifiedIdentity } from "./identity-policy.js";
export declare function createExpressIdentityGuardV2<Request = unknown>(options: {
  guard: {
    policy: { schema_version: 2; identity_scope: string };
    restriction(context: { sourceIp: string; routeId: string; identity?: VerifiedIdentity }): { action: "THROTTLE" | "DENY"; retryAfterSeconds: number } | null;
  };
  getVerifiedSourceIp: (request: Request) => string;
  getRouteId: (request: Request) => string;
  getVerifiedIdentity?: (request: Request) => VerifiedIdentity;
}): (request: Request, response: {
  set(field: string, value: string): unknown;
  status(code: number): { json(body: unknown): unknown };
}, next: (error?: unknown) => void) => unknown;
