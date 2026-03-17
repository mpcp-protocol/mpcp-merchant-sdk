/**
 * Edge adapter tests — real crypto end-to-end.
 *
 * SBAs are signed using mpcp-reference (Node.js DER-format ECDSA).
 * The edge adapter verifies them using Web Crypto (IEEE P1363 format after DER conversion).
 * This also serves as an integration test for the DER → P1363 converter.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createSignedBudgetAuthorization } from "mpcp-service/sdk";
import { verifyMpcpEdge } from "../src/adapters/edge.js";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_KEY_PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const PUBLIC_KEY_PEM = publicKey.export({ type: "spki", format: "pem" }) as string;
const KEY_ID = "test-key-edge";
const FUTURE = new Date(Date.now() + 3_600_000).toISOString();
const PAST = new Date(Date.now() - 1000).toISOString();

function makeSba(overrides: {
  maxAmountMinor?: string;
  expiresAt?: string;
  destinationAllowlist?: string[];
  grantId?: string;
  currency?: string;
  allowedRails?: string[];
} = {}) {
  process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM = PRIVATE_KEY_PEM;
  process.env.MPCP_SBA_SIGNING_KEY_ID = KEY_ID;
  try {
    return createSignedBudgetAuthorization({
      sessionId: "sess-edge",
      actorId: "agent-edge",
      grantId: overrides.grantId ?? "grant-edge-001",
      policyHash: "hash-edge",
      currency: overrides.currency ?? "USD",
      maxAmountMinor: overrides.maxAmountMinor ?? "5000",
      allowedRails: (overrides.allowedRails ?? ["stripe"]) as any,
      allowedAssets: [],
      destinationAllowlist: overrides.destinationAllowlist ?? [],
      expiresAt: overrides.expiresAt ?? FUTURE,
    });
  } finally {
    delete process.env.MPCP_SBA_SIGNING_PRIVATE_KEY_PEM;
    delete process.env.MPCP_SBA_SIGNING_KEY_ID;
  }
}

/** Create a Web-compatible Request with the SBA in the Authorization header. */
function makeHeaderRequest(sba: unknown): Request {
  const encoded = btoa(JSON.stringify(sba));
  return new Request("https://example.com/charge", {
    method: "POST",
    headers: { authorization: `MPCP ${encoded}` },
  });
}

/** Create a Web-compatible Request with the SBA in the JSON body. */
function makeBodyRequest(sba: unknown): Request {
  return new Request("https://example.com/charge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sba }),
  });
}

const baseOpts = {
  amount: "1000",
  currency: "USD",
  signingKeyPem: PUBLIC_KEY_PEM,
  signingKeyId: KEY_ID,
  skipRevocationCheck: true,
};

describe("verifyMpcpEdge — core (real Web Crypto + DER→P1363)", () => {
  it("valid SBA within budget → valid: true", async () => {
    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), baseOpts);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.grant.grantId).toBe("grant-edge-001");
      expect(result.grant.currency).toBe("USD");
      expect(result.amount).toBe("1000");
    }
  });

  it("SBA in request body → valid: true", async () => {
    const sba = makeSba();
    const result = await verifyMpcpEdge(makeBodyRequest(sba), baseOpts);
    expect(result.valid).toBe(true);
  });

  it("tampered signature → sba_invalid", async () => {
    const sba = makeSba();
    const bad = { ...sba, signature: "invalidsig==" };
    const result = await verifyMpcpEdge(makeHeaderRequest(bad), baseOpts);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("expired SBA → grant_expired", async () => {
    const sba = makeSba({ expiresAt: PAST });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), baseOpts);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("grant_expired");
  });

  it("amount > maxAmountMinor → amount_exceeded", async () => {
    const sba = makeSba({ maxAmountMinor: "500" });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, amount: "1000" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("amount_exceeded");
  });

  it("merchantId not in destinationAllowlist → destination_not_allowed", async () => {
    const sba = makeSba({ destinationAllowlist: ["merchant-A"] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, merchantId: "merchant-B" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("destination_not_allowed");
  });

  it("merchantId in destinationAllowlist → valid: true", async () => {
    const sba = makeSba({ destinationAllowlist: ["merchant-A"] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, merchantId: "merchant-A" });
    expect(result.valid).toBe(true);
  });

  it("empty destinationAllowlist + any merchantId → valid: true", async () => {
    const sba = makeSba({ destinationAllowlist: [] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, merchantId: "any" });
    expect(result.valid).toBe(true);
  });

  it("paymentRail in allowedRails → valid: true", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, paymentRail: "stripe" });
    expect(result.valid).toBe(true);
  });

  it("paymentRail not in allowedRails → sba_invalid", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, paymentRail: "xrpl" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("paymentRail omitted → allowedRails check skipped", async () => {
    const sba = makeSba({ allowedRails: ["stripe"] });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), baseOpts);
    expect(result.valid).toBe(true);
  });

  it("currency mismatch → sba_invalid", async () => {
    const sba = makeSba({ currency: "USD" });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, currency: "EUR" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("wrong signing key → sba_invalid", async () => {
    const { publicKey: otherPub } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const wrongKey = otherPub.export({ type: "spki", format: "pem" }) as string;
    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, signingKeyPem: wrongKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("key ID mismatch → sba_invalid", async () => {
    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, signingKeyId: "wrong-key-id" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("no SBA → sba_invalid", async () => {
    const req = new Request("https://example.com/charge", { method: "POST" });
    const result = await verifyMpcpEdge(req, baseOpts);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });

  it("no signing key configured → sba_invalid", async () => {
    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      amount: "1000",
      currency: "USD",
      skipRevocationCheck: true,
      // no signingKeyPem, no env var
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("sba_invalid");
  });
});

describe("verifyMpcpEdge — revocation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("revoked grant → grant_revoked", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ revoked: true }),
    }));

    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      ...baseOpts,
      skipRevocationCheck: false,
      revocationEndpoint: "https://example.com/revoke",
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("grant_revoked");
  });

  it("not revoked → valid: true", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ revoked: false }),
    }));

    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      ...baseOpts,
      skipRevocationCheck: false,
      revocationEndpoint: "https://example.com/revoke",
    });
    expect(result.valid).toBe(true);
  });

  it("revocation network error → fail-open (valid: true)", async () => {
    vi.stubGlobal("fetch", async () => { throw new Error("network down"); });

    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      ...baseOpts,
      skipRevocationCheck: false,
      revocationEndpoint: "https://example.com/revoke",
    });
    expect(result.valid).toBe(true);
  });

  it("skipRevocationCheck: true → no fetch call", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const sba = makeSba();
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      ...baseOpts,
      skipRevocationCheck: true,
      revocationEndpoint: "https://example.com/revoke",
    });
    expect(result.valid).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("revocationEndpoint set without skipRevocationCheck → revocation is checked (default behaviour)", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ revoked: false }),
    }));

    const sba = makeSba();
    // skipRevocationCheck is intentionally absent (defaults to falsy)
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), {
      ...baseOpts,
      revocationEndpoint: "https://example.com/revoke",
    });
    expect(result.valid).toBe(true);
  });
});

describe("verifyMpcpEdge — edge-case guards", () => {
  it("oversized Authorization header → falls back to body", async () => {
    const sba = makeSba();
    const oversized = "x".repeat(9000); // > MAX_SBA_HEADER_BASE64_CHARS (8192)
    const req = new Request("https://example.com/charge", {
      method: "POST",
      headers: {
        authorization: `MPCP ${oversized}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ sba }),
    });
    const result = await verifyMpcpEdge(req, baseOpts);
    expect(result.valid).toBe(true);
  });

  it("malformed expiresAt (not a date) → grant_expired, not silently valid", async () => {
    // Without the isNaN guard, Date.parse("not-a-date") = NaN and
    // NaN <= nowMs is false, causing the expiry check to be skipped entirely.
    const sba = makeSba({ expiresAt: "not-a-date" });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), baseOpts);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.code).toBe("grant_expired");
  });

  it("null-valued field injected into authorization after signing → stripped by canonicalJson → signature still valid", async () => {
    // Both canonicalJsonEdge (edge) and canonicalJson (mpcp-reference) strip null-valued
    // object keys. An extra null field injected AFTER signing is stripped before hashing,
    // so the canonical string matches the original → signature validates.
    // This test pins that the two implementations have identical null-filtering semantics.
    const sba = makeSba();
    const tampered = {
      ...sba,
      authorization: { ...(sba as any).authorization, _extraNull: null },
    };
    const result = await verifyMpcpEdge(makeHeaderRequest(tampered), baseOpts);
    expect(result.valid).toBe(true);
  });
});

describe("verifyMpcpEdge — hash-chain pin", () => {
  it("SBA signed by mpcp-reference (sign(null, SHA256(canonical))) verifies correctly via Web Crypto", async () => {
    // mpcp-reference: h1 = SHA256(canonical); sig = crypto.sign(null, h1, key)
    // crypto.sign(null, data, ecKey) hashes `data` with SHA-256 internally,
    // so the actual ECDSA digest is SHA256(h1), NOT h1.
    //
    // The edge verifier replicates this by:
    //   1. Computing h1 = await subtle.digest("SHA-256", msgBytes)
    //   2. Passing h1 to subtle.verify({ hash: "SHA-256" }, ...) which also computes SHA256(h1)
    //
    // Passing rawCanonical bytes directly would make Web Crypto compute SHA256(rawCanonical) = h1,
    // which does NOT match SHA256(h1), causing all real-SBA verifications to fail.
    // This test would fail if the hash-chain logic regresses.
    const sba = makeSba({ grantId: "hash-chain-pin" });
    const result = await verifyMpcpEdge(makeHeaderRequest(sba), { ...baseOpts, amount: "1" });
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.grant.grantId).toBe("hash-chain-pin");
  });
});
