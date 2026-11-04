export declare function createLocalExpressNodeGuard<Request = unknown>(options: {
  client: {
    evaluate(sourceIp: string, routeId: string): Promise<{
      decision: 'ALLOW' | 'THROTTLE' | 'DENY';
      restriction: null | { retry_after_seconds: number };
    }>;
  };
  /** Return an address verified by the application's trusted ingress. */
  getVerifiedSourceIp: (request: Request) => string;
  /** Return a route ID from the application's own route mapping. */
  getVerifiedRouteId: (request: Request) => string;
}): (request: Request, response: {
  set(field: string, value: string): unknown;
  status(code: number): { json(body: unknown): unknown };
}, next: (error?: unknown) => void) => Promise<unknown>;
