import { describe, it, expect, vi, beforeEach } from "vitest";
import type { IncomingMessage } from "node:http";

// Stub verifyMpcp before importing the HOC
vi.mock("../src/verify.js", () => ({
  verifyMpcp: vi.fn(),
}));

import { verifyMpcp } from "../src/verify.js";
import { withMpcp } from "../src/adapters/nextjs.js";
import type { GrantInfo } from "../src/types.js";
import type { NextApiLikeRequest, NextApiLikeResponse } from "../src/adapters/nextjs.js";

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

function makeReq(overrides: Partial<NextApiLikeRequest> = {}): NextApiLikeRequest {
  return {
    headers: {},
    body: {},
    ...overrides,
  } as unknown as NextApiLikeRequest;
}

function makeRes(): {
  res: NextApiLikeResponse;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as NextApiLikeResponse;
  return { res, status, json };
}

const handlerOpts = {
  signingKeyPem: "pem",
  signingKeyId: "kid",
  skipRevocationCheck: true,
  getAmount: () => "1000",
  getCurrency: () => "USD",
};

describe("withMpcp() Next.js HOC", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("SBA in Authorization header → handler called, req.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
    expect((req as any).mpcp).toMatchObject({ valid: true, amount: "1000" });
    // Verify the extracted SBA object (not raw base64) was passed to verifyMpcp
    expect(mockVerify).toHaveBeenCalledWith(VALID_SBA_OBJ, expect.objectContaining({ amount: "1000", currency: "USD" }));
  });

  it("SBA in req.body.sba → handler called, req.mpcp set", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({ body: { sba: VALID_SBA_OBJ } });
    const { res } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
    expect((req as any).mpcp.valid).toBe(true);
    // Verify the extracted SBA object was passed to verifyMpcp (not undefined or raw body)
    expect(mockVerify).toHaveBeenCalledWith(VALID_SBA_OBJ, expect.objectContaining({ amount: "1000" }));
  });

  it("no SBA provided → 402 with error body, handler NOT called", async () => {
    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({ headers: {}, body: {} });
    const { res, status, json } = makeRes();

    await wrapped(req, res);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(handler).not.toHaveBeenCalled();
  });

  it("verifyMpcp returns valid: false → 402 with error body", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "grant_revoked", detail: "Grant was revoked" },
    });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();

    await wrapped(req, res);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith({ error: "grant_revoked", detail: "Grant was revoked" });
    expect(handler).not.toHaveBeenCalled();
  });

  it("strict: false → handler called even on failure", async () => {
    mockVerify.mockResolvedValue({
      valid: false,
      error: { code: "sba_invalid", detail: "bad" },
    });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, { ...handlerOpts, strict: false });
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
    expect((req as any).mpcp.valid).toBe(false);
  });

  it("strict: false + no SBA → handler called with req.mpcp.valid === false", async () => {
    const handler = vi.fn();
    const wrapped = withMpcp(handler, { ...handlerOpts, strict: false });
    const req = makeReq({ headers: {}, body: {} });
    const { res, status } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
    expect((req as any).mpcp.valid).toBe(false);
    expect((req as any).mpcp.error.code).toBe("sba_invalid");
  });

  it("malformed base64 in Authorization header → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({
      headers: { authorization: "MPCP !!!not-valid-base64!!!" },
      body: { sba: VALID_SBA_OBJ },
    });
    const { res } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
  });

  it("Authorization header payload exceeding size limit → falls back to body", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const oversized = Buffer.alloc(9000, "x").toString("base64");
    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({
      headers: { authorization: `MPCP ${oversized}` },
      body: { sba: VALID_SBA_OBJ },
    });
    const { res } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
  });

  it("getAmount throws → 402 with sba_invalid", async () => {
    const handler = vi.fn();
    const wrapped = withMpcp(handler, {
      ...handlerOpts,
      getAmount: () => { throw new Error("missing amount"); },
    });
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();

    await wrapped(req, res);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(handler).not.toHaveBeenCalled();
  });

  it("verifyMpcp throws unexpectedly → 402 with sba_invalid (not an uncaught exception)", async () => {
    mockVerify.mockRejectedValue(new Error("unexpected failure"));

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    const req = makeReq({ headers: { authorization: `MPCP ${ENCODED_SBA}` } });
    const { res, status, json } = makeRes();

    await wrapped(req, res);

    expect(status).toHaveBeenCalledWith(402);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: "sba_invalid" }));
    expect(handler).not.toHaveBeenCalled();
  });

  it("array Authorization header → uses first value", async () => {
    mockVerify.mockResolvedValue({ valid: true, grant: FAKE_GRANT, amount: "1000", currency: "USD" });

    const handler = vi.fn();
    const wrapped = withMpcp(handler, handlerOpts);
    // node:http allows headers to be arrays
    const req = makeReq({
      headers: { authorization: [`MPCP ${ENCODED_SBA}`, "extra"] } as unknown as IncomingMessage["headers"],
    });
    const { res } = makeRes();

    await wrapped(req, res);

    expect(handler).toHaveBeenCalledOnce();
  });
});
