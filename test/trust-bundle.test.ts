import { describe, it, expect, afterEach } from "vitest";
import crypto from "node:crypto";
import { createSignedBudgetAuthorization, signTrustBundle } from "mpcp-service/sdk";
import type { KeyWithKid, UnsignedTrustBundle } from "mpcp-service/sdk";
import { verifyMpcp } from "../src/verify.js";

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();

function generateEd25519(kid: string) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const jwk = { ...publicKey.export({ format: "jwk" }), kid } as KeyWithKid;
  return { privateKeyPem, jwk };
}

function makeUnsignedBundle(issuer: string, issuerJwk: KeyWithKid, expiresAt?: string): UnsignedTrustBundle {
  return {
    version: "1.0",
    bundleId: `bundle-${Math.random().toString(36).slice(2)}`,
    bundleIssuer: "ba.example.com",
    bundleKeyId: "bundle-key-1",
    category: "payment-policy",
    approvedIssuers: [issuer],
    issuers: [{ issuer, keys: [issuerJwk] }],
    expiresAt: expiresAt ?? new Date(Date.now() + 86_400_000).toISOString(),
  };
}

/** Creates a signed SBA with the given private key, then clears env vars. */
function makeSba(sbaPrivateKeyPem: string, sbaKeyId: string, issuer: string) {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = sbaPrivateKeyPem;
  process.env.MPCP_SBA_SIGNING_KEY_ID = sbaKeyId;
  const sba = createSignedBudgetAuthorization({
    sessionId: "sess-tb",
    actorId: "agent-1",
    grantId: "grant-tb-1",
    policyHash: "abc123def456",
    currency: "USD",
    maxAmountMinor: "5000",
    allowedRails: ["stripe"] as never,
    allowedAssets: [],
    destinationAllowlist: [],
    expiresAt: FUTURE,
    issuer,
  });
  delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_KEY_ID;
  return sba;
}

afterEach(() => {
  delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_KEY_ID;
});

describe("verifyMpcp — trust bundles (PR9)", () => {
  it("verifies SBA using trust bundle key — no env var or signingKeyPem needed", async () => {
    const bundleKeys = generateEd25519("bundle-key-1");
    const sbaKeys = generateEd25519("sba-key-1");

    const sba = makeSba(sbaKeys.privateKeyPem, "sba-key-1", "pa.example.com");
    expect(sba).not.toBeNull();

    const trustBundle = signTrustBundle(
      makeUnsignedBundle("pa.example.com", sbaKeys.jwk),
      bundleKeys.privateKeyPem,
    );

    const result = await verifyMpcp(sba!, {
      amount: "1000",
      currency: "USD",
      trustBundles: [trustBundle],
    });
    expect(result.valid).toBe(true);
  });

  it("baseline: no trustBundles and no signingKeyPem → sba_invalid", async () => {
    const sbaKeys = generateEd25519("sba-key-1");
    const sba = makeSba(sbaKeys.privateKeyPem, "sba-key-1", "pa.example.com");
    expect(sba).not.toBeNull();

    const result = await verifyMpcp(sba!, {
      amount: "1000",
      currency: "USD",
      // no trustBundles, no signingKeyPem, no env var
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("expired bundle falls through to env var — sba_invalid when no env var set", async () => {
    const bundleKeys = generateEd25519("bundle-key-1");
    const sbaKeys = generateEd25519("sba-key-1");

    const sba = makeSba(sbaKeys.privateKeyPem, "sba-key-1", "pa.example.com");
    expect(sba).not.toBeNull();

    const expiredBundle = signTrustBundle(
      makeUnsignedBundle("pa.example.com", sbaKeys.jwk, new Date(Date.now() - 1000).toISOString()),
      bundleKeys.privateKeyPem,
    );

    const result = await verifyMpcp(sba!, {
      amount: "1000",
      currency: "USD",
      trustBundles: [expiredBundle],
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("trust bundle with wrong key embedded → sba_invalid", async () => {
    const bundleKeys = generateEd25519("bundle-key-1");
    const sbaKeys = generateEd25519("sba-key-1");
    const wrongKeys = generateEd25519("sba-key-1"); // same kid, different key material

    const sba = makeSba(sbaKeys.privateKeyPem, "sba-key-1", "pa.example.com");
    expect(sba).not.toBeNull();

    const wrongBundle = signTrustBundle(
      makeUnsignedBundle("pa.example.com", wrongKeys.jwk),
      bundleKeys.privateKeyPem,
    );

    const result = await verifyMpcp(sba!, {
      amount: "1000",
      currency: "USD",
      trustBundles: [wrongBundle],
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });
});
