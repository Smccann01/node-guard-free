export type ReasonCode =
  | "invalid_signature_burst"
  | "replay_burst"
  | "anonymous_rate_burst"
  | "oversized_body_burst"
  | "api_probe_burst";

export type GuardDecision = Readonly<{
  sourceIp: string;
  reasonCode: ReasonCode;
  protocol: "HTTP" | "HTTPS";
  hitCount: number;
  observedAt: string;
  action: "observed" | "limit_armed";
  expiresAt: string | null;
}>;

export type RecordResult =
  | { accepted: false; reason: "ineligible_source" | "unknown_reason" | "invalid_protocol" | "source_excluded" | "capacity_exhausted" }
  | { accepted: true; action: "recorded" | "observed" | "limit_armed"; decision?: GuardDecision };

export declare const REASON_CODES: readonly ReasonCode[];
export declare function isEligibleSource(address: string): boolean;

export type GuardOptions = {
  mode?: "observe" | "enforce";
  thresholds?: Partial<Record<ReasonCode, number>>;
  windowMs?: number;
  blockMs?: number;
  maxSources?: number;
  canActOnSource?: (verifiedClientIp: string) => boolean;
  onDecision?: (decision: GuardDecision) => void | Promise<void>;
  now?: () => number;
};

export type GuardInstance = Readonly<{
  record(event: { sourceIp: string; reasonCode: ReasonCode; protocol?: "HTTP" | "HTTPS" }): RecordResult;
  restriction(sourceIp: string): { expiresAt: string; retryAfterSeconds: number } | null;
  isBlocked(sourceIp: string): boolean;
  release(sourceIp: string): number;
  snapshot(): Array<{ sourceIp: string; reasonCode: ReasonCode; protocol: "HTTP" | "HTTPS"; expiresAt: string }>;
}>;

/** License-free, in-process application protection; no host-level enforcement. */
export declare function createNodeGuard(options?: GuardOptions): GuardInstance;
