import type { IncomingMessage, ServerResponse } from "node:http";
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

/**
 * Minimal Next.js Pages Router compatible request interface.
 * Structurally compatible with `NextApiRequest` from the `next` package.
 * The `next` package must be installed as a peer dependency by consumers.
 */
export interface NextApiLikeRequest extends IncomingMessage {
  body?: unknown;
  query?: Partial<Record<string, string | string[]>>;
  cookies?: Partial<Record<string, string>>;
}

/**
 * Minimal Next.js Pages Router compatible response interface.
 * Structurally compatible with `NextApiResponse` from the `next` package.
 */
export interface NextApiLikeResponse extends ServerResponse {
  status(code: number): this;
  json(body: unknown): void;
}

/** Next.js API route request augmented with MPCP verification context. */
export type MpcpNextApiRequest = NextApiLikeRequest & { mpcp: MpcpContext };

export interface MpcpNextApiOptions extends Omit<MpcpOptions, "amount" | "currency"> {
  /** Extract the payment amount (minor units) from the request. */
  getAmount: (req: NextApiLikeRequest) => string;
  /** Extract the ISO 4217 currency code from the request. */
  getCurrency: (req: NextApiLikeRequest) => string;
  /** If true, returns 402 on failure; if false, calls the handler regardless. Default: true. */
  strict?: boolean;
}

/**
 * Higher-order function that wraps a Next.js Pages Router API handler with
 * MPCP payment authorization verification.
 *
 * Extracts the SBA from:
 *   1. `Authorization: MPCP <base64-encoded-json>` header (~6 KB decoded limit)
 *   2. `req.body.sba` fallback (requires a body parser such as Next.js's built-in one)
 *
 * On valid: calls the inner handler with `req.mpcp` set.
 * On invalid (strict mode, default): responds 402 with structured error body.
 *
 * @example
 * ```ts
 * import { withMpcp } from "@mpcp/merchant-sdk/nextjs";
 *
 * export default withMpcp(
 *   async (req, res) => {
 *     res.json({ grantId: req.mpcp.grant.grantId });
 *   },
 *   {
 *     signingKeyPem: process.env.MPCP_SIGNING_PUBLIC_KEY_PEM,
 *     signingKeyId: process.env.MPCP_SIGNING_KEY_ID,
 *     getAmount: (req) => (req.body as { amount: string }).amount,
 *     getCurrency: () => "USD",
 *   },
 * );
 * ```
 */
export function withMpcp(
  handler: (req: MpcpNextApiRequest, res: NextApiLikeResponse) => void | Promise<void>,
  options: MpcpNextApiOptions,
): (req: NextApiLikeRequest, res: NextApiLikeResponse) => Promise<void> {
  // Destructure adapter-only fields so they are never forwarded to verifyMpcp.
  const { getAmount, getCurrency, strict: strictOpt, ...mpcpOptions } = options;

  // Create shared instances once per HOC call, not per request.
  const sharedChecker = mpcpOptions.skipRevocationCheck
    ? undefined
    : (mpcpOptions.revocationChecker ?? new RevocationChecker({ ttlMs: mpcpOptions.revocationTtl }));

  const sharedStorage: SpendStorage | undefined = mpcpOptions.trackSpend
    ? (mpcpOptions.spendStorage ?? new MemorySpendStorage())
    : undefined;

  const strict = strictOpt !== false;

  return async (req: NextApiLikeRequest, res: NextApiLikeResponse): Promise<void> => {
    // --- Extract SBA ---
    let sba: unknown = undefined;

    const authHeader = req.headers["authorization"];
    const authStr = Array.isArray(authHeader) ? authHeader[0] : authHeader;
    if (authStr && authStr.startsWith("MPCP ")) {
      const encoded = authStr.slice(5).trim();
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
      (req as MpcpNextApiRequest).mpcp = context;
      if (strict) {
        res.status(402).json({ error: context.error.code, detail: context.error.detail });
        return;
      }
      await handler(req as MpcpNextApiRequest, res);
      return;
    }

    // --- Extract amount / currency ---
    let amount: string;
    let currency: string;
    try {
      amount = getAmount(req);
      currency = getCurrency(req);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to extract amount or currency from request";
      const context: MpcpContext = { valid: false, error: { code: "sba_invalid", detail } };
      (req as MpcpNextApiRequest).mpcp = context;
      if (strict) {
        res.status(402).json({ error: "sba_invalid", detail });
        return;
      }
      await handler(req as MpcpNextApiRequest, res);
      return;
    }

    // --- Verify ---
    let result;
    try {
      result = await verifyMpcp(sba, {
        ...mpcpOptions,
        amount,
        currency,
        revocationChecker: sharedChecker,
        spendStorage: sharedStorage,
      });
    } catch {
      const context: MpcpContext = { valid: false, error: { code: "sba_invalid", detail: "Verification error" } };
      (req as MpcpNextApiRequest).mpcp = context;
      if (strict) {
        res.status(402).json({ error: "sba_invalid", detail: "Verification error" });
        return;
      }
      await handler(req as MpcpNextApiRequest, res);
      return;
    }

    if (result.valid) {
      (req as MpcpNextApiRequest).mpcp = {
        valid: true,
        grant: result.grant,
        amount: result.amount,
        currency: result.currency,
      };
    } else {
      (req as MpcpNextApiRequest).mpcp = { valid: false, error: result.error };
      if (strict) {
        res.status(402).json({ error: result.error.code, detail: result.error.detail });
        return;
      }
    }

    await handler(req as MpcpNextApiRequest, res);
  };
}
