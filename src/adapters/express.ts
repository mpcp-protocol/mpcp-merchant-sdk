import type { Request, Response, NextFunction, RequestHandler } from "express";
import { verifyMpcp } from "../verify.js";
import { RevocationChecker } from "../revocation.js";
import { MemorySpendStorage } from "./memory.js";
import type { MpcpContext, MpcpOptions } from "../types.js";
import type { SpendStorage } from "../storage.js";

export type { MpcpContext } from "../types.js";

/**
 * Base64 character limit for the Authorization header SBA payload.
 * Base64 encodes 3 bytes as 4 chars, so this allows ~6 KB of decoded JSON.
 */
const MAX_SBA_HEADER_BASE64_CHARS = 8192;

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      mpcp: MpcpContext;
    }
  }
}

export interface MpcpMiddlewareOptions extends Omit<MpcpOptions, "amount" | "currency"> {
  /** Extract amount from the request. */
  getAmount: (req: Request) => string;
  /** Extract currency from the request. */
  getCurrency: (req: Request) => string;
  /** If true, returns 402 on failure; if false, attaches result to req.mpcp and calls next. Default: true. */
  strict?: boolean;
}

/**
 * Factory that returns an Express middleware for MPCP verification.
 *
 * Extracts the SBA from:
 *   1. `Authorization: MPCP <base64-encoded-json>` header (max ~6 KB decoded)
 *   2. `req.body.sba` fallback
 *
 * On valid: attaches req.mpcp and calls next().
 * On invalid (strict mode, default): responds 402 with structured error body.
 */
export function mpcp(options: MpcpMiddlewareOptions): RequestHandler {
  // Destructure adapter-only fields so they are never forwarded to verifyMpcp.
  const { getAmount, getCurrency, strict: strictOpt, ...mpcpOptions } = options;

  // Create shared instances once per factory call, not per request.
  const sharedChecker = mpcpOptions.skipRevocationCheck
    ? undefined
    : (mpcpOptions.revocationChecker ?? new RevocationChecker({ ttlMs: mpcpOptions.revocationTtl }));

  const sharedStorage: SpendStorage | undefined = mpcpOptions.trackSpend
    ? (mpcpOptions.spendStorage ?? new MemorySpendStorage())
    : undefined;

  const strict = strictOpt !== false;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Extract SBA
    let sba: unknown = undefined;

    const authHeader = req.headers["authorization"];
    if (authHeader && authHeader.startsWith("MPCP ")) {
      const encoded = authHeader.slice(5).trim();
      if (encoded.length <= MAX_SBA_HEADER_BASE64_CHARS) {
        try {
          sba = JSON.parse(Buffer.from(encoded, "base64").toString("utf-8"));
        } catch {
          // fall through to body fallback
        }
      }
    }

    if (sba === undefined && req.body && typeof req.body === "object") {
      sba = (req.body as Record<string, unknown>).sba;
    }

    if (sba === undefined) {
      const context: MpcpContext = {
        valid: false,
        error: { code: "sba_invalid", detail: "No SBA provided in Authorization header or request body" },
      };
      req.mpcp = context;
      if (strict) {
        res.status(402).json({ error: context.error.code, detail: context.error.detail });
        return;
      }
      next();
      return;
    }

    let amount: string;
    let currency: string;
    try {
      amount = getAmount(req);
      currency = getCurrency(req);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to extract amount or currency from request";
      const context: MpcpContext = { valid: false, error: { code: "sba_invalid", detail } };
      req.mpcp = context;
      if (strict) {
        res.status(402).json({ error: "sba_invalid", detail });
        return;
      }
      next();
      return;
    }

    const result = await verifyMpcp(sba, {
      ...mpcpOptions,
      amount,
      currency,
      revocationChecker: sharedChecker,
      spendStorage: sharedStorage,
    });

    if (result.valid) {
      req.mpcp = { valid: true, grant: result.grant, amount: result.amount, currency: result.currency };
      next();
    } else {
      req.mpcp = { valid: false, error: result.error };
      if (strict) {
        res.status(402).json({ error: result.error.code, detail: result.error.detail });
        return;
      }
      next();
    }
  };
}
