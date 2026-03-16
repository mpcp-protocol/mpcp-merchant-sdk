import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createSignedBudgetAuthorization } from "mpcp-service/sdk";
import { verifyMpcp } from "../src/verify.js";
import { MemorySpendStorage } from "../src/adapters/memory.js";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_KEY_PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" }) as string;
const KEY_ID = "test-key-spend";
const FUTURE = new Date(Date.now() + 3_600_000).toISOString();

function makeSba(opts: { maxAmountMinor?: string; grantId?: string } = {}) {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = PRIVATE_KEY_PEM;
  process.env.MPCP_SBA_SIGNING_KEY_ID = KEY_ID;
  const sba = createSignedBudgetAuthorization({
    sessionId: "sess-spend",
    actorId: "agent-spend",
    grantId: opts.grantId ?? "grant-spend-001",
    policyHash: "hash-spend",
    currency: "USD",
    maxAmountMinor: opts.maxAmountMinor ?? "3000",
    allowedRails: ["stripe"],
    allowedAssets: [],
    destinationAllowlist: [],
    expiresAt: FUTURE,
  });
  delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_KEY_ID;
  return sba;
}

const baseOpts = {
  currency: "USD",
  signingKeyPem: PUBLIC_KEY_PEM,
  signingKeyId: KEY_ID,
  skipRevocationCheck: true,
  trackSpend: true,
};

describe("verifyMpcp — spend tracking", () => {
  it("first payment → valid: true, recorded", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba();
    const result = await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage });
    expect(result.valid).toBe(true);
    expect(await storage.total("grant-spend-001", "USD")).toBe("1000");
  });

  it("second payment within budget → valid: true, cumulative enforced", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba({ maxAmountMinor: "3000" });

    await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage });
    const result = await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage });
    expect(result.valid).toBe(true);
    expect(await storage.total("grant-spend-001", "USD")).toBe("2000");
  });

  it("payment that would exceed cumulative budget → amount_exceeded", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba({ maxAmountMinor: "1500" });

    await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage });
    const result = await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("amount_exceeded");
    // Should not have recorded the failed payment
    expect(await storage.total("grant-spend-001", "USD")).toBe("1000");
  });

  it("same idempotency key twice → counts once", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba({ maxAmountMinor: "3000" });

    await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage, idempotencyKey: "idem-1" });
    await verifyMpcp(sba, { ...baseOpts, amount: "1000", spendStorage: storage, idempotencyKey: "idem-1" });

    expect(await storage.total("grant-spend-001", "USD")).toBe("1000");
  });

  it("trackSpend: false → no recording", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba();
    const result = await verifyMpcp(sba, {
      ...baseOpts,
      trackSpend: false,
      amount: "1000",
      spendStorage: storage,
    });
    expect(result.valid).toBe(true);
    expect(await storage.total("grant-spend-001", "USD")).toBe("0");
  });

  it("custom spendStorage injection works", async () => {
    const storage = new MemorySpendStorage();
    const sba = makeSba({ grantId: "grant-custom" });
    const result = await verifyMpcp(sba, { ...baseOpts, amount: "500", spendStorage: storage });
    expect(result.valid).toBe(true);
    expect(await storage.total("grant-custom", "USD")).toBe("500");
  });
});
