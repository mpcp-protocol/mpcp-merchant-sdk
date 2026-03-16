import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createSignedBudgetAuthorization } from "mpcp-service/sdk";
import { verifyMpcp } from "../src/verify.js";

// Generate two independent EC key pairs for concurrency and cross-key tests
const { privateKey: privA, publicKey: pubA } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { privateKey: privB, publicKey: pubB } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_KEY_PEM = privA.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC_KEY_PEM = pubA.export({ type: "spki", format: "pem" }) as string;
const PUBLIC_KEY_PEM_B = pubB.export({ type: "spki", format: "pem" }) as string;
const KEY_ID = "test-key-1";
const KEY_ID_B = "test-key-2";

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();
const PAST = new Date(Date.now() - 1000).toISOString();

function makeSba(overrides: {
  maxAmountMinor?: string;
  expiresAt?: string;
  destinationAllowlist?: string[];
  grantId?: string;
  currency?: string;
  allowedRails?: string[];
  privateKeyPem?: string;
  keyId?: string;
} = {}) {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = overrides.privateKeyPem ?? PRIVATE_KEY_PEM;
  process.env.MPCP_SBA_SIGNING_KEY_ID = overrides.keyId ?? KEY_ID;
  const sba = createSignedBudgetAuthorization({
    sessionId: "sess-001",
    actorId: "agent-001",
    grantId: overrides.grantId ?? "grant-001",
    policyHash: "abc123",
    currency: overrides.currency ?? "USD",
    maxAmountMinor: overrides.maxAmountMinor ?? "5000",
    allowedRails: (overrides.allowedRails ?? ["stripe"]) as any,
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
    const sba = makeSba();
    const result = await verifyMpcp(sba, {
      ...defaultOptions,
      signingKeyPem: PUBLIC_KEY_PEM_B,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });
});

describe("verifyMpcp — currency check", () => {
  it("options.currency matches SBA currency → valid: true", async () => {
    const sba = makeSba({ currency: "EUR" });
    const result = await verifyMpcp(sba, { ...defaultOptions, currency: "EUR" });
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.currency).toBe("EUR");
  });

  it("options.currency does not match SBA currency → sba_invalid", async () => {
    const sba = makeSba({ currency: "USD" });
    const result = await verifyMpcp(sba, { ...defaultOptions, currency: "EUR" });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error.code).toBe("sba_invalid");
      expect(result.error.detail).toMatch(/currency mismatch/i);
    }
  });

  it("result.currency comes from the SBA, not options", async () => {
    const sba = makeSba({ currency: "USD" });
    const result = await verifyMpcp(sba, defaultOptions);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.currency).toBe("USD");
  });
});

describe("verifyMpcp — rail enforcement", () => {
  it("paymentRail in allowedRails → valid: true", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcp(sba, { ...defaultOptions, paymentRail: "stripe" });
    expect(result.valid).toBe(true);
  });

  it("paymentRail not in allowedRails → sba_invalid", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcp(sba, { ...defaultOptions, paymentRail: "xrpl" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("paymentRail omitted → allowedRails check is skipped", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcp(sba, defaultOptions); // no paymentRail
    expect(result.valid).toBe(true);
  });
});

describe("verifyMpcp — concurrency safety", () => {
  it("concurrent calls with different signing keys each verify correctly", async () => {
    const privKeyB = privB.export({ type: "pkcs8", format: "pem" }) as string;

    const sbaA = makeSba({ grantId: "grant-A" });
    const sbaB = makeSba({ grantId: "grant-B", privateKeyPem: privKeyB, keyId: KEY_ID_B });

    // Both should pass with their respective keys
    const [resA, resB] = await Promise.all([
      verifyMpcp(sbaA, { ...defaultOptions, signingKeyPem: PUBLIC_KEY_PEM, signingKeyId: KEY_ID }),
      verifyMpcp(sbaB, { ...defaultOptions, signingKeyPem: PUBLIC_KEY_PEM_B, signingKeyId: KEY_ID_B }),
    ]);
    expect(resA.valid).toBe(true);
    expect(resB.valid).toBe(true);

    // Cross-verification should fail
    const [crossA, crossB] = await Promise.all([
      verifyMpcp(sbaA, { ...defaultOptions, signingKeyPem: PUBLIC_KEY_PEM_B, signingKeyId: KEY_ID_B }),
      verifyMpcp(sbaB, { ...defaultOptions, signingKeyPem: PUBLIC_KEY_PEM, signingKeyId: KEY_ID }),
    ]);
    expect(crossA.valid).toBe(false);
    expect(crossB.valid).toBe(false);
  });
});
