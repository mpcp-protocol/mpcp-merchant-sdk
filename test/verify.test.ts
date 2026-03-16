import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createSignedBudgetAuthorization } from "mpcp-service/sdk";
import { verifyMpcp } from "../src/verify.js";

// Generate a real EC key pair for testing
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_KEY_PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" }) as string;
const KEY_ID = "test-key-1";

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();
const PAST = new Date(Date.now() - 1000).toISOString();

function makeSba(overrides: {
  maxAmountMinor?: string;
  expiresAt?: string;
  destinationAllowlist?: string[];
  grantId?: string;
} = {}) {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = PRIVATE_KEY_PEM;
  process.env.MPCP_SBA_SIGNING_KEY_ID = KEY_ID;
  const sba = createSignedBudgetAuthorization({
    sessionId: "sess-001",
    actorId: "agent-001",
    grantId: overrides.grantId ?? "grant-001",
    policyHash: "abc123",
    currency: "USD",
    maxAmountMinor: overrides.maxAmountMinor ?? "5000",
    allowedRails: ["stripe"],
    allowedAssets: [],
    destinationAllowlist: overrides.destinationAllowlist ?? [],
    expiresAt: overrides.expiresAt ?? FUTURE,
  });
  delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_KEY_ID;
  return sba;
}

const defaultOptions = {
  amount: "1000",
  currency: "USD",
  signingKeyPem: PUBLIC_KEY_PEM,
  signingKeyId: KEY_ID,
};

describe("verifyMpcp — core", () => {
  it("valid SBA within budget → valid: true", async () => {
    const sba = makeSba();
    const result = await verifyMpcp(sba, defaultOptions);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.grant.grantId).toBe("grant-001");
      expect(result.grant.currency).toBe("USD");
      expect(result.amount).toBe("1000");
      expect(result.currency).toBe("USD");
    }
  });

  it("invalid signature → sba_invalid", async () => {
    const sba = makeSba();
    // Corrupt the signature
    const bad = { ...sba, signature: "invalidsig==" };
    const result = await verifyMpcp(bad, defaultOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("expired SBA → grant_expired", async () => {
    const sba = makeSba({ expiresAt: PAST });
    const result = await verifyMpcp(sba, defaultOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("grant_expired");
  });

  it("amount > maxAmountMinor → amount_exceeded", async () => {
    const sba = makeSba({ maxAmountMinor: "500" });
    const result = await verifyMpcp(sba, { ...defaultOptions, amount: "1000" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("amount_exceeded");
  });

  it("merchantId not in destinationAllowlist → destination_not_allowed", async () => {
    const sba = makeSba({ destinationAllowlist: ["merchant-A"] });
    const result = await verifyMpcp(sba, { ...defaultOptions, merchantId: "merchant-B" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("destination_not_allowed");
  });

  it("merchantId in destinationAllowlist → valid: true", async () => {
    const sba = makeSba({ destinationAllowlist: ["merchant-A"] });
    const result = await verifyMpcp(sba, { ...defaultOptions, merchantId: "merchant-A" });
    expect(result.valid).toBe(true);
  });

  it("empty destinationAllowlist + any merchantId → valid: true", async () => {
    const sba = makeSba({ destinationAllowlist: [] });
    const result = await verifyMpcp(sba, { ...defaultOptions, merchantId: "any-merchant" });
    expect(result.valid).toBe(true);
  });

  it("non-object input → sba_invalid", async () => {
    const result = await verifyMpcp("not-an-object", defaultOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("null input → sba_invalid", async () => {
    const result = await verifyMpcp(null, defaultOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("missing required SBA fields → sba_invalid", async () => {
    const result = await verifyMpcp({ authorization: { grantId: "x" }, signature: "y" }, defaultOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("signingKeyPem in options (not env) → works", async () => {
    const sba = makeSba();
    // Clear env vars, pass via options
    const prev = process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
    delete process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM;
    const result = await verifyMpcp(sba, {
      amount: "1000",
      currency: "USD",
      signingKeyPem: PUBLIC_KEY_PEM,
      signingKeyId: KEY_ID,
    });
    if (prev !== undefined) process.env.MPCP_SBA_SIGNING_PUBLIC_KEY_PEM = prev;
    expect(result.valid).toBe(true);
  });

  it("wrong signing key → sba_invalid", async () => {
    const { publicKey: wrongKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const wrongPem = wrongKey.export({ type: "spki", format: "pem" }) as string;
    const sba = makeSba();
    const result = await verifyMpcp(sba, {
      ...defaultOptions,
      signingKeyPem: wrongPem,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });
});
