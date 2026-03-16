import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createSignedBudgetAuthorization } from "mpcp-service/sdk";
import { verifyMpcp } from "../src/verify.js";
import { RevocationChecker } from "../src/revocation.js";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_KEY_PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" }) as string;
const KEY_ID = "test-key-rev";
const REVOCATION_ENDPOINT = "https://example.com/revoke";
const FUTURE = new Date(Date.now() + 3_600_000).toISOString();

function makeSba(grantId = "grant-rev-001") {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = PRIVATE_KEY_PEM;
  process.env.MPCP_SBA_SIGNING_KEY_ID = KEY_ID;
  const sba = createSignedBudgetAuthorization({
    sessionId: "sess-rev",
    actorId: "agent-rev",
    grantId,
    policyHash: "hash-rev",
    currency: "USD",
    maxAmountMinor: "5000",
    allowedRails: ["stripe"],
    allowedAssets: [],
    destinationAllowlist: [],
    expiresAt: FUTURE,
  });
  delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
  delete process.env.MPCP_SBA_SIGNING_KEY_ID;
  return sba;
}

const baseOptions = {
  amount: "1000",
  currency: "USD",
  signingKeyPem: PUBLIC_KEY_PEM,
  signingKeyId: KEY_ID,
  revocationEndpoint: REVOCATION_ENDPOINT,
};

describe("verifyMpcp — revocation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("revoked grant → grant_revoked", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ revoked: true, revokedAt: "2024-01-01T00:00:00Z" }),
    }));
    const sba = makeSba();
    const result = await verifyMpcp(sba, baseOptions);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("grant_revoked");
  });

  it("not revoked → valid: true", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ revoked: false }),
    }));
    const sba = makeSba();
    const result = await verifyMpcp(sba, baseOptions);
    expect(result.valid).toBe(true);
  });

  it("second call within TTL → only one fetch call (cache hit)", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true,
      json: async () => ({ revoked: false }),
    }));
    vi.stubGlobal("fetch", fetchSpy);

    const checker = new RevocationChecker({ ttlMs: 60_000 });
    const sba = makeSba("grant-cache-test");

    await verifyMpcp(sba, { ...baseOptions, revocationChecker: checker });
    await verifyMpcp(sba, { ...baseOptions, revocationChecker: checker });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("revocationTtl: 0 → always fetches", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true,
      json: async () => ({ revoked: false }),
    }));
    vi.stubGlobal("fetch", fetchSpy);

    const checker = new RevocationChecker({ ttlMs: 0 });
    const sba = makeSba("grant-no-cache");

    await verifyMpcp(sba, { ...baseOptions, revocationChecker: checker });
    await verifyMpcp(sba, { ...baseOptions, revocationChecker: checker });

    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("skipRevocationCheck: true → no fetch, valid: true", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const sba = makeSba();
    const result = await verifyMpcp(sba, { ...baseOptions, skipRevocationCheck: true });
    expect(result.valid).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("network error → fail-open (valid: true)", async () => {
    vi.stubGlobal("fetch", async () => { throw new Error("network down"); });

    const sba = makeSba();
    const result = await verifyMpcp(sba, baseOptions);
    expect(result.valid).toBe(true);
  });
});
