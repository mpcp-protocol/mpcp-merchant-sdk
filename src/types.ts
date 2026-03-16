import type { Rail } from "mpcp-service/sdk";
import type { RevocationChecker } from "./revocation.js";
import type { SpendStorage } from "./storage.js";

export type { Rail } from "mpcp-service/sdk";
export type { RevocationChecker } from "./revocation.js";
export type { SpendStorage, SpendEntry } from "./storage.js";

/** Mirrors mpcp-reference's BudgetScope union. */
export type BudgetScope = "SESSION" | "DAY" | "VEHICLE" | "FLEET" | "TRIP";

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
  budgetScope: BudgetScope;
  maxAmountMinor: string;
  currency: string;
  allowedRails: Rail[];
  expiresAt: string;
}

export interface MpcpOptions {
  /** Requested payment in minor units (e.g. "1500" = $15.00 for USD). */
  amount: string;
  /** Expected ISO 4217 currency code. Must match the SBA's currency. */
  currency: string;
  /** If set, checks SBA's destinationAllowlist includes this value. */
  merchantId?: string;
  /** Agent public key PEM. Falls back to MPCP_SBA_SIGNING_PUBLIC_KEY_PEM env var. */
  signingKeyPem?: string;
  /** Expected key ID. Falls back to MPCP_SBA_SIGNING_KEY_ID env var. */
  signingKeyId?: string;
  /** Override clock for testing (ms since epoch). */
  nowMs?: number;
  /**
   * Payment rail being used (e.g. "stripe", "xrpl").
   * When set, verified against the SBA's allowedRails.
   * Strongly recommended — omitting it skips rail enforcement.
   */
  paymentRail?: Rail;

  // PR2 — revocation
  /**
   * Revocation endpoint URL to check before accepting payment.
   * The SBA artifact itself does not carry a revocationEndpoint;
   * this must be configured by the merchant.
   */
  revocationEndpoint?: string;
  /** Revocation cache TTL in ms. Default: 60_000. */
  revocationTtl?: number;
  /** Skip revocation check entirely. Default: false. */
  skipRevocationCheck?: boolean;
  /** Provide a pre-configured RevocationChecker instance (shared across calls). */
  revocationChecker?: RevocationChecker;

  // PR3 — spend tracking
  /**
   * Enable cumulative spend tracking against the grant ceiling. Default: false.
   *
   * WARNING: When true, you MUST provide a shared `spendStorage` instance that
   * persists across calls. Without it a new in-memory store is created per call,
   * making cumulative enforcement a no-op.
   */
  trackSpend?: boolean;
  /** Pluggable spend storage. Must be a shared instance when trackSpend is true. */
  spendStorage?: SpendStorage;
  /** Idempotency key for deduplication. Same key is never counted twice. */
  idempotencyKey?: string;
}
