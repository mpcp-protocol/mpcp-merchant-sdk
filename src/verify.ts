import { verifySignedBudgetAuthorization } from "mpcp-service/sdk";
import type { SignedBudgetAuthorization } from "mpcp-service/sdk";
import type { GrantInfo, MpcpOptions, VerificationResult } from "./types.js";
import { RevocationChecker } from "./revocation.js";

type Decision = Parameters<typeof verifySignedBudgetAuthorization>[1]["decision"];

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
    typeof auth.expiresAt === "string" &&
    Array.isArray(auth.allowedRails) &&
    Array.isArray(auth.allowedAssets) &&
    Array.isArray(auth.destinationAllowlist)
  );
}

function syntheticDecision(sba: SignedBudgetAuthorization, amount: string): Decision {
  return {
    action: "ALLOW",
    reasons: [],
    policyHash: sba.authorization.policyHash,
    expiresAtISO: sba.authorization.expiresAt,
    decisionId: sba.authorization.budgetId,
    sessionGrantId: sba.authorization.grantId,
    priceFiat: { amountMinor: amount, currency: sba.authorization.currency },
  } as Decision;
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

  // 2. Temporarily set env vars for mpcp-reference's verifier
  const prevPublicKey = process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
  const prevKeyId = process.env.MPCP_SBA_SIGNING_KEY_ID;
  try {
    if (options.signingKeyPem !== undefined) {
      process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM = options.signingKeyPem;
    }
    if (options.signingKeyId !== undefined) {
      process.env.MPCP_SBA_SIGNING_KEY_ID = options.signingKeyId;
    }

    // 3. Verify signature, expiry, amount bounds via mpcp-reference
    const decision = syntheticDecision(sba, options.amount);
    const result = verifySignedBudgetAuthorization(sba, {
      sessionId: auth.sessionId,
      decision,
      nowMs: options.nowMs,
      cumulativeSpentMinor: "0",
    });

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

    // 4. Destination check
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

    // 5. Revocation check
    if (!options.skipRevocationCheck) {
      const endpoint = options.revocationEndpoint;
      if (endpoint) {
        const checker =
          options.revocationChecker ??
          new RevocationChecker({ ttlMs: options.revocationTtl });
        const revResult = await checker.check(endpoint, auth.grantId);
        if (revResult.revoked) {
          return {
            valid: false,
            error: {
              code: "grant_revoked",
              detail: revResult.revokedAt ? `Revoked at ${revResult.revokedAt}` : "Grant has been revoked",
            },
          };
        }
      }
    }

    // 6. Return success
    const grant: GrantInfo = {
      grantId: auth.grantId,
      policyHash: auth.policyHash,
      sessionId: auth.sessionId,
      actorId: auth.actorId,
      budgetScope: auth.budgetScope,
      maxAmountMinor: auth.maxAmountMinor,
      currency: auth.currency,
      allowedRails: auth.allowedRails,
      expiresAt: auth.expiresAt,
    };

    return { valid: true, grant, amount: options.amount, currency: options.currency };
  } finally {
    // Restore env vars
    if (options.signingKeyPem !== undefined) {
      if (prevPublicKey === undefined) {
        delete process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
      } else {
        process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM = prevPublicKey;
      }
    }
    if (options.signingKeyId !== undefined) {
      if (prevKeyId === undefined) {
        delete process.env.MPCP_SBA_SIGNING_KEY_ID;
      } else {
        process.env.MPCP_SBA_SIGNING_KEY_ID = prevKeyId;
      }
    }
  }
}
