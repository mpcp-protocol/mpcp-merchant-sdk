import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";

// Stub verifyMpcp before importing middleware
vi.mock("../src/verify.js", () => ({
  verifyMpcp: vi.fn(),
}));

import { verifyMpcp } from "../src/verify.js";
import { mpcp } from "../src/adapters/express.js";
import type { GrantInfo } from "../src/types.js";

const mockVerify = vi.mocked(verifyMpcp);

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    body: {},
    ...overrides,
  } as unknown as Request;
}

function makeRes(): { res: Response; status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> } {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

const FAKE_GRANT: GrantInfo = {
  grantId: "g-1",
  policyHash: "h-1",
  sessionId: "s-1",
  actorId: "a-1",
  budgetScope: "SESSION",
  maxAmountMinor: "5000",
  currency: "USD",
  allowedRails: ["stripe"],
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
};

const VALID_SBA_OBJ = { authorization: { grantId: "g-1" }, signature: "sig" };
const ENCODED_SBA = Buffer.from(JSON.stringify(VALID_SBA_OBJ)).toString("base64");

const middlewareOpts = {
  signingKeyPem: "pem",
  signingKeyId: "kid",
  skipRevocationCheck: true,
  getAmount: (_req: Request) => "1000",
  getCurrency: (_req: Request) => "USD",
};

describe("mpcp() Express middleware", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("SBA in Authorization header → next() called, req.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const middleware = mpcp(middlewareOpts);
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as any).mpcp).toMatchObject({ valid: true, amount: "1000" });
  });

  it("SBA in req.body.sba → next() called, req.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const middleware = mpcp(middlewareOpts);
    const req = makeReq({ body: { sba: VALID_SBA_OBJ } });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((req as any).mpcp.valid).toBe(true);
  });

  it("no SBA provided → 402 with error body", async () => {
    const middleware = mpcp(middlewareOpts);
    const req = makeReq({ headers: {}, body: {} });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(next).not.toHaveBeenCalled();
  });

  it("verifyMpcp returns valid: false → 402 with error body", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "grant_revoked", detail: "Grant was revoked" },
    });

    const middleware = mpcp(middlewareOpts);
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith({ error: "grant_revoked", detail: "Grant was revoked" });
    expect(next).not.toHaveBeenCalled();
  });

  it("strict: false → next() called even on failure", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "sba_invalid", detail: "bad" },
    });

    const middleware = mpcp({ ...middlewareOpts, strict: false });
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
    expect((req as any).mpcp.valid).toBe(false);
  });

  it("malformed base64 in Authorization header → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const middleware = mpcp(middlewareOpts);
    const req = makeReq({
      headers: { authorization: "MPCP !!!not-valid-base64!!!" },
      body: { sba: VALID_SBA_OBJ },
    });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it("Authorization header payload exceeding size limit → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const oversized = Buffer.alloc(9000, "x").toString("base64");
    const middleware = mpcp(middlewareOpts);
    const req = makeReq({
      headers: { authorization: `MPCP ${oversized}` },
      body: { sba: VALID_SBA_OBJ },
    });
    const { res } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it("getAmount throws → 402 with sba_invalid", async () => {
    const middleware = mpcp({
      ...middlewareOpts,
      getAmount: () => { throw new Error("missing amount param"); },
    });
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(next).not.toHaveBeenCalled();
  });

  it("getCurrency throws → 402 with sba_invalid", async () => {
    const middleware = mpcp({
      ...middlewareOpts,
      getCurrency: () => { throw new Error("missing currency param"); },
    });
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();
    const next = vi.fn() as unknown as NextFunction;

    await middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(next).not.toHaveBeenCalled();
  });
});
