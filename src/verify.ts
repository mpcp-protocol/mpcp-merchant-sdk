import { verifySignedBudgetAuthorization } from "mpcp-service/sdk";
import type { SignedBudgetAuthorization, PaymentPolicyDecision } from "mpcp-service/sdk";
import type { Rail } from "mpcp-service/sdk";
import type { GrantInfo, MpcpOptions, VerificationResult } from "./types.js";
import { RevocationChecker } from "./revocation.js";
import { MemorySpendStorage } from "./adapters/memory.js";

/** Matches ISO 8601 timestamps for safe interpolation into response bodies. */
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T[\d:.Z+\-]+$/;

function isSignedSba(value: unknown): value is SignedBudgetAuthorization {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (!v.authorization || typeof v.authorization !== "object") return false;
  const auth = v.authorization as Record<string, unknown>;
  return (
    typeof v.signature === "string" &&
    typeof v.issuerKeyId === "string" &&
    typeof auth.version === "string" &&
    typeof auth.budgetId === "string" &&
    typeof auth.grantId === "string" &&
    typeof auth.sessionId === "string" &&
    typeof auth.actorId === "string" &&
    typeof auth.policyHash === "string" &&
    typeof auth.currency === "string" &&
    typeof auth.maxAmountMinor === "string" &&
    typeof auth.budgetScope === "string" &&
    typeof auth.minorUnit === "number" &&
    typeof auth.expiresAt === "string" &&
    Array.isArray(auth.allowedRails) &&
    Array.isArray(auth.allowedAssets) &&
    Array.isArray(auth.destinationAllowlist)
  );
}

function syntheticDecision(
  sba: SignedBudgetAuthorization,
  amount: string,
  rail?: Rail,
): PaymentPolicyDecision {
  const decision: PaymentPolicyDecision = {
    action: "ALLOW",
    reasons: [],
    policyHash: sba.authorization.policyHash,
    expiresAtISO: sba.authorization.expiresAt,
    decisionId: sba.authorization.budgetId,
    sessionGrantId: sba.authorization.grantId,
    priceFiat: { amountMinor: amount, currency: sba.authorization.currency },
  };
  if (rail !== undefined) decision.rail = rail;
  return decision;
}

/**
 * Run verifySignedBudgetAuthorization synchronously with temporarily-set env vars.
 *
 * `verifySignedBudgetAuthorization` reads the signing key from process.env.
 * This helper sets the env, calls the synchronous verifier, then restores the env
 * — all without yielding to the event loop — making concurrent async calls safe.
 */
function runVerifySync(
  sba: SignedBudgetAuthorization,
  input: Parameters<typeof verifySignedBudgetAuthorization>[1],
  signingKeyPem: string | undefined,
  signingKeyId: string | undefined,
): ReturnType<typeof verifySignedBudgetAuthorization> {
  const prevPublicKey = process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
  const prevKeyId = process.env.MPCP_SBA_SIGNING_KEY_ID;
  if (signingKeyPem !== undefined) process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM = signingKeyPem;
  if (signingKeyId !== undefined) process.env.MPCP_SBA_SIGNING_KEY_ID = signingKeyId;
  try {
    return verifySignedBudgetAuthorization(sba, input);
  } finally {
    // Restore synchronously — no await between set and restore.
    if (signingKeyPem !== undefined) {
      if (prevPublicKey === undefined) delete process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
      else process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM = prevPublicKey;
    }
    if (signingKeyId !== undefined) {
      if (prevKeyId === undefined) delete process.env.MPCP_SBA_SIGNING_KEY_ID;
      else process.env.MPCP_SBA_SIGNING_KEY_ID = prevKeyId;
    }
  }
}

/**
 * Verify a SignedBudgetAuthorization.
 *
 * @param sba - The signed budget authorization artifact (parsed JSON object).
 * @param options - Verification options including amount, currency, and signing key.
 */
export async function verifyMpcp(
  sba: unknown,
  options: MpcpOptions,
): Promise<VerificationResult> {
  // 1. Shape guard
  if (!isSignedSba(sba)) {
    return { valid: false, error: { code: "sba_invalid", detail: "Not a valid SignedBudgetAuthorization" } };
  }

  const auth = sba.authorization;

  // 2. Currency check — must match before any further processing
  if (options.currency !== auth.currency) {
    return {
      valid: false,
      error: {
        code: "sba_invalid",
        detail: `Currency mismatch: expected ${options.currency}, SBA uses ${auth.currency}`,
      },
    };
  }

  // 3. Cumulative spend (async — done before any env mutation)
  const storage = options.trackSpend
    ? (options.spendStorage ?? new MemorySpendStorage())
    : null;
  const cumulativeSpentMinor = storage
    ? await storage.total(auth.grantId, auth.currency)
    : "0";

  // 4. Verify signature + expiry + budget bounds.
  // runVerifySync sets env vars, calls the synchronous verifier, and restores env
  // atomically (no await between set and restore) — safe under concurrent requests.
  const decision = syntheticDecision(sba, options.amount, options.paymentRail);
  const result = runVerifySync(
    sba,
    { sessionId: auth.sessionId, decision, nowMs: options.nowMs, cumulativeSpentMinor },
    options.signingKeyPem,
    options.signingKeyId,
  );

  if (!result.ok) {
    switch (result.reason) {
      case "invalid_signature":
        return { valid: false, error: { code: "sba_invalid", detail: "Invalid signature or key mismatch" } };
      case "expired":
        return { valid: false, error: { code: "grant_expired", detail: "SBA has expired" } };
      case "budget_exceeded":
        return { valid: false, error: { code: "amount_exceeded", detail: "Amount exceeds authorized budget" } };
      case "mismatch":
        return { valid: false, error: { code: "sba_invalid", detail: "SBA fields do not match decision" } };
      default:
        return { valid: false, error: { code: "sba_invalid", detail: "Verification failed" } };
    }
  }

  // 5. Destination check
  if (
    options.merchantId !== undefined &&
    auth.destinationAllowlist.length > 0 &&
    !auth.destinationAllowlist.includes(options.merchantId)
  ) {
    return {
      valid: false,
      error: { code: "destination_not_allowed", detail: "Merchant ID not in destinationAllowlist" },
    };
  }

  // 6. Revocation check
  if (!options.skipRevocationCheck) {
    const endpoint = options.revocationEndpoint;
    if (endpoint) {
      const checker =
        options.revocationChecker ??
        new RevocationChecker({ ttlMs: options.revocationTtl });
      const revResult = await checker.check(endpoint, auth.grantId);
      if (revResult.revoked) {
        const revokedAtSafe =
          typeof revResult.revokedAt === "string" && ISO_TIMESTAMP_RE.test(revResult.revokedAt)
            ? revResult.revokedAt
            : undefined;
        return {
          valid: false,
          error: {
            code: "grant_revoked",
            detail: revokedAtSafe ? `Revoked at ${revokedAtSafe}` : "Grant has been revoked",
          },
        };
      }
    }
  }

  // 7. Record spend (idempotency-safe). Failure is non-fatal after verification succeeds.
  if (storage) {
    try {
      await storage.record({
        grantId: auth.grantId,
        idempotencyKey: options.idempotencyKey,
        amount: options.amount,
        currency: auth.currency,
        recordedAt: new Date().toISOString(),
      });
    } catch {
      // Storage write failed after a successful verification. The payment may proceed
      // but the spend ceiling will not be decremented. Wire a logger here for production.
    }
  }

  // 8. Return success — use auth.currency (the verified value)
  const grant: GrantInfo = {
    grantId: auth.grantId,
    policyHash: auth.policyHash,
    sessionId: auth.sessionId,
    actorId: auth.actorId,
    budgetScope: auth.budgetScope as GrantInfo["budgetScope"],
    maxAmountMinor: auth.maxAmountMinor,
    currency: auth.currency,
    allowedRails: auth.allowedRails as Rail[],
    expiresAt: auth.expiresAt,
  };

  return { valid: true, grant, amount: options.amount, currency: auth.currency };
}
