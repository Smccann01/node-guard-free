import type { createPolicyGuardV1 } from './policy-runtime.js';

export declare function createLocalNodeGuardApi(options: {
  socketPath: string;
  applications: Array<{
    applicationId: string;
    token: string;
    guard: ReturnType<typeof createPolicyGuardV1>;
  }>;
  managementToken: string;
  maxAuditEntries?: number;
  now?: () => number;
}): Readonly<{
  start(): Promise<void>;
  stop(): Promise<void>;
}>;
