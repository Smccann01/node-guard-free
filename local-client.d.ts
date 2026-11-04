import type { ObservationV1 } from './policy.js';

export declare function createLocalNodeGuardClient(options: {
  socketPath: string;
  applicationId: string;
  token: string;
  timeoutMs?: number;
}): Readonly<{
  evaluate(sourceIp: string): Promise<{
    application_id: string;
    source_ip: string;
    decision: 'ALLOW' | 'THROTTLE' | 'DENY';
    restriction: null | { policy_id: string; expires_at: string; retry_after_seconds: number };
  }>;
  record(observation: ObservationV1): Promise<
    | { accepted: false; reason: string }
    | { accepted: true; action: 'recorded' | 'OBSERVE' | 'THROTTLE' | 'DENY'; decision?: object }
  >;
}>;
