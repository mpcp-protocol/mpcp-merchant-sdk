import { describe, it, expect, vi, beforeEach } from "vitest";
import Fastify from "fastify";

// Stub verifyMpcp before importing the plugin
vi.mock("../src/verify.js", () => ({
  verifyMpcp: vi.fn(),
}));

import { verifyMpcp } from "../src/verify.js";
import { fastifyMpcp } from "../src/adapters/fastify.js";
import type { GrantInfo } from "../src/types.js";

const mockVerify = vi.mocked(verifyMpcp);

const FAKE_GRANT: GrantInfo = {
  grantId: "g-1",
  policyHash: "h-1",
  sessionId: "s-1",
  actorId: "a-1",
  budgetScope: "SESSION",
  maxAmountMinor: "5000",
  currency: "USD",
  allowedRails: ["stripe"],
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
};

const VALID_SBA_OBJ = { authorization: { grantId: "g-1" }, signature: "sig" };
const ENCODED_SBA = Buffer.from(JSON.stringify(VALID_SBA_OBJ)).toString("base64");

const pluginOpts = {
  signingKeyPem: "pem",
  signingKeyId: "kid",
  skipRevocationCheck: true,
  getAmount: () => "1000",
  getCurrency: () => "USD",
};

async function buildApp(opts = pluginOpts) {
  const app = Fastify({ logger: false });
  await app.register(fastifyMpcp, opts);
  app.post("/test", async (req) => req.mpcp);
  await app.ready();
  return app;
}

describe("fastifyMpcp plugin", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("SBA in Authorization header → handler called, request.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const app = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ valid: true, amount: "1000" });
  });

  it("SBA in request.body.sba → handler called, request.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const app = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sba: VALID_SBA_OBJ }),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().valid).toBe(true);
  });

  it("no SBA provided → 402 with error body", async () => {
    const app = await buildApp();
    const res = await app.inject({ method: "POST", url: "/test" });

    expect(res.statusCode).toBe(402);
    expect(res.json()).toMatchObject({ error: "sba_invalid" });
  });

  it("verifyMpcp returns valid: false → 402 with error body", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "grant_revoked", detail: "Grant was revoked" },
    });

    const app = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(402);
    expect(res.json()).toEqual({ error: "grant_revoked", detail: "Grant was revoked" });
  });

  it("strict: false → handler called even on failure, request.mpcp.valid is false", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "sba_invalid", detail: "bad" },
    });

    const app = Fastify({ logger: false });
    await app.register(fastifyMpcp, { ...pluginOpts, strict: false });
    app.post("/test", async (req) => req.mpcp);
    await app.ready();

    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().valid).toBe(false);
  });

  it("malformed base64 in Authorization header → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const app = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: {
        authorization: "MPCP !!!not-valid-base64!!!",
        "content-type": "application/json",
      },
      body: JSON.stringify({ sba: VALID_SBA_OBJ }),
    });

    expect(res.statusCode).toBe(200);
  });

  it("Authorization header payload exceeding size limit → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const oversized = Buffer.alloc(9000, "x").toString("base64");
    const app = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: {
        authorization: `MPCP ${oversized}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ sba: VALID_SBA_OBJ }),
    });

    expect(res.statusCode).toBe(200);
  });

  it("getAmount throws → 402 with sba_invalid", async () => {
    const app = Fastify({ logger: false });
    await app.register(fastifyMpcp, {
      ...pluginOpts,
      getAmount: () => { throw new Error("missing amount param"); },
    });
    app.post("/test", async (req) => req.mpcp);
    await app.ready();

    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(402);
    expect(res.json()).toMatchObject({ error: "sba_invalid" });
  });

  it("getCurrency throws → 402 with sba_invalid", async () => {
    const app = Fastify({ logger: false });
    await app.register(fastifyMpcp, {
      ...pluginOpts,
      getCurrency: () => { throw new Error("missing currency param"); },
    });
    app.post("/test", async (req) => req.mpcp);
    await app.ready();

    const res = await app.inject({
      method: "POST",
      url: "/test",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(402);
    expect(res.json()).toMatchObject({ error: "sba_invalid" });
  });

  it("plugin is non-encapsulated via fp() — decorator visible outside registration scope", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const app = Fastify({ logger: false });
    await app.register(fastifyMpcp, pluginOpts);

    // Route registered at the root level (outside plugin scope) can still access request.mpcp
    app.post("/outside", async (req) => req.mpcp);
    await app.ready();

    const res = await app.inject({
      method: "POST",
      url: "/outside",
      headers: { authorization: `MPCP ${ENCODED_SBA}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().valid).toBe(true);
  });
});
