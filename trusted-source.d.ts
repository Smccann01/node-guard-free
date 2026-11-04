export declare function createTrustedSourceResolver(options?: {
  /** Exact proxy addresses. CIDR ranges are intentionally unsupported in v1. */
  trustedProxyIps?: string[];
}): (request: {
  socket?: { remoteAddress?: string };
  headers?: { "x-forwarded-for"?: string | string[] };
}) => string;
