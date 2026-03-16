import type { RevocationChecker } from "./revocation.js";
import type { SpendStorage } from "./storage.js";

export type { RevocationChecker } from "./revocation.js";
export type { SpendStorage, SpendEntry } from "./storage.js";

export type VerificationResult =
  | { valid: true; grant: GrantInfo; amount: string; currency: string }
  | { valid: false; error: MpcpError };

export interface MpcpError {
  code:
    | "sba_invalid"
    | "grant_revoked"
    | "amount_exceeded"
    | "grant_expired"
    | "destination_not_allowed";
  detail: string;
}

export interface GrantInfo {
  grantId: string;
  policyHash: string;
  sessionId: string;
  actorId: string;
  budgetScope: string;
  maxAmountMinor: string;
  currency: string;
  allowedRails: string[];
  expiresAt: string;
}

export interface MpcpOptions {
  /** Requested payment in minor units (e.g. "1500" = $15.00 for USD). */
  amount: string;
  /** Expected ISO 4217 currency code. */
  currency: string;
  /** If set, checks SBA's destinationAllowlist includes this value. */
  merchantId?: string;
  /** Agent public key PEM. Falls back to MPCP_SBA_SIGNING_PUBLIC_KEY_PEM env var. */
  signingKeyPem?: string;
  /** Expected key ID. Falls back to MPCP_SBA_SIGNING_KEY_ID env var. */
  signingKeyId?: string;
  /** Override clock for testing (ms since epoch). */
  nowMs?: number;

  // PR2 — revocation
  /** Explicit revocation endpoint; overrides the grant's revocationEndpoint. */
  revocationEndpoint?: string;
  /** Revocation cache TTL in ms. Default: 60_000. */
  revocationTtl?: number;
  /** Skip revocation check entirely. Default: false. */
  skipRevocationCheck?: boolean;
  /** Provide a pre-configured RevocationChecker instance. */
  revocationChecker?: RevocationChecker;

  // PR3 — spend tracking
  /** Enable cumulative spend tracking against the grant ceiling. Default: false. */
  trackSpend?: boolean;
  /** Pluggable spend storage. Defaults to MemorySpendStorage when trackSpend is true. */
  spendStorage?: SpendStorage;
  /** Idempotency key for deduplication. Same key is never counted twice. */
  idempotencyKey?: string;
}
