export declare function createExpressNodeGuard<Request = unknown>(options: {
  guard: {
    restriction(sourceIp: string): {
      expiresAt: string;
      retryAfterSeconds: number;
      action?: "THROTTLE" | "DENY";
    } | null;
  };
  /** Return only an address verified by the application's trusted ingress. */
  getVerifiedSourceIp: (request: Request) => string;
}): (request: Request, response: {
  set(field: string, value: string): unknown;
  status(code: number): { json(body: unknown): unknown };
}, next: (error?: unknown) => void) => unknown;
