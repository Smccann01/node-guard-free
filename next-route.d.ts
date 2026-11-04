export declare function createNextRouteGuard<RequestType = Request>(options: {
  guard: {
    restriction(sourceIp: string): {
      expiresAt: string;
      retryAfterSeconds: number;
      action?: "THROTTLE" | "DENY";
    } | null;
  };
  /** Must use a deployment-verified source; never raw client headers. */
  getVerifiedSourceIp: (request: RequestType) => string | Promise<string>;
}): (request: RequestType) => Promise<Response | null>;
