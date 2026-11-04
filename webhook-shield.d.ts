export interface WebhookVerificationInput {
  /** The exact received request bytes, before text decoding or JSON parsing. */
  rawBody: Uint8Array;
  /** Canonical epoch seconds supplied by the sender as decimal text. */
  timestamp: string;
  eventId: string;
  /** Lowercase hex SHA-256 HMAC over the Node Guard v1 signing envelope. */
  signature: string;
}

export type WebhookVerificationResult =
  | { accepted: true; eventId: string; verifiedAt: string }
  | { accepted: false; reason: 'invalid_body' | 'invalid_envelope' | 'clock_regressed' |
      'outside_window' | 'invalid_signature' | 'duplicate_event' | 'capacity_exhausted' };

export interface WebhookShieldOptions {
  /** A separate 32-256 byte secret for this endpoint. */
  secret: string | Uint8Array;
  toleranceSeconds?: number;
  maxBodyBytes?: number;
  maxEvents?: number;
  now?: () => number;
}

export interface WebhookShield {
  verify(input: WebhookVerificationInput): WebhookVerificationResult;
  status(): Readonly<{ trackedEvents: number; maxEvents: number; toleranceSeconds: number;
    maxBodyBytes: number; stateScope: 'one_process' }>;
}

export declare function createWebhookShield(options: WebhookShieldOptions): WebhookShield;
