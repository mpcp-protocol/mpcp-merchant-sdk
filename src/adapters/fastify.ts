import fp from "fastify-plugin";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { verifyMpcp } from "../verify.js";
import { RevocationChecker } from "../revocation.js";
import { MemorySpendStorage } from "./memory.js";
import type { GrantInfo, MpcpError, MpcpOptions } from "../types.js";
import type { SpendStorage } from "../storage.js";

/** Maximum allowed byte length for the base64 SBA payload in the Authorization header. */
const MAX_SBA_HEADER_BYTES = 8192;

export interface MpcpContext {
  valid: boolean;
  grant?: GrantInfo;
  amount?: string;
  currency?: string;
  error?: MpcpError;
}

// Extend FastifyRequest type
declare module "fastify" {
  interface FastifyRequest {
    mpcp: MpcpContext;
  }
}

export interface FastifyMpcpOptions extends Omit<MpcpOptions, "amount" | "currency"> {
  /** Extract the payment amount (minor units) from the request. */
  getAmount: (req: FastifyRequest) => string;
  /** Extract the ISO 4217 currency code from the request. */
  getCurrency: (req: FastifyRequest) => string;
  /** If true, returns 402 on failure; if false, sets request.mpcp and calls the handler. Default: true. */
  strict?: boolean;
}

const fastifyMpcpPlugin: FastifyPluginAsync<FastifyMpcpOptions> = async (fastify, options) => {
  // Create shared instances once per plugin registration, not per request.
  const sharedChecker = options.skipRevocationCheck
    ? undefined
    : (options.revocationChecker ?? new RevocationChecker({ ttlMs: options.revocationTtl }));

  const sharedStorage: SpendStorage | undefined = options.trackSpend
    ? (options.spendStorage ?? new MemorySpendStorage())
    : undefined;

  const strict = options.strict !== false;

  fastify.decorateRequest("mpcp", null as unknown as MpcpContext);

  fastify.addHook("preHandler", async (request, reply) => {
    // --- Extract SBA ---
    let sba: unknown = undefined;

    const authHeader = request.headers["authorization"];
    if (authHeader && authHeader.startsWith("MPCP ")) {
      const encoded = authHeader.slice(5).trim();
      if (encoded.length <= MAX_SBA_HEADER_BYTES) {
        try {
          sba = JSON.parse(Buffer.from(encoded, "base64").toString("utf-8"));
        } catch {
          // fall through to body fallback
        }
      }
    }

    if (sba === undefined && request.body && typeof request.body === "object") {
      sba = (request.body as Record<string, unknown>).sba;
    }

    if (sba === undefined) {
      const context: MpcpContext = {
        valid: false,
        error: { code: "sba_invalid", detail: "No SBA provided in Authorization header or request body" },
      };
      request.mpcp = context;
      if (strict) {
        reply.code(402).send({ error: context.error?.code, detail: context.error?.detail });
      }
      return;
    }

    // --- Extract amount / currency ---
    let amount: string;
    let currency: string;
    try {
      amount = options.getAmount(request);
      currency = options.getCurrency(request);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to extract amount or currency from request";
      const context: MpcpContext = { valid: false, error: { code: "sba_invalid", detail } };
      request.mpcp = context;
      if (strict) {
        reply.code(402).send({ error: "sba_invalid", detail });
      }
      return;
    }

    // --- Verify ---
    const result = await verifyMpcp(sba, {
      ...options,
      amount,
      currency,
      revocationChecker: sharedChecker,
      spendStorage: sharedStorage,
    });

    if (result.valid) {
      request.mpcp = { valid: true, grant: result.grant, amount: result.amount, currency: result.currency };
    } else {
      request.mpcp = { valid: false, error: result.error };
      if (strict) {
        reply.code(402).send({ error: result.error.code, detail: result.error.detail });
      }
    }
  });
};

/**
 * Fastify plugin for MPCP payment authorization verification.
 *
 * Registers a `preHandler` hook that extracts and verifies the SBA from:
 *   1. `Authorization: MPCP <base64-encoded-json>` header (max 8 KB)
 *   2. `request.body.sba` fallback
 *
 * On valid: sets `request.mpcp` with grant info and calls the route handler.
 * On invalid (strict mode, default): replies 402 and skips the handler.
 *
 * @example
 * ```ts
 * import { fastifyMpcp } from "@mpcp/merchant-sdk/fastify";
 * await app.register(fastifyMpcp, {
 *   revocationTtl: 60_000,
 *   getAmount: (req) => req.body.amount,
 *   getCurrency: () => "USD",
 * });
 * app.post("/charge", async (req) => {
 *   req.mpcp.grant  // typed
 * });
 * ```
 */
export const fastifyMpcp = fp(fastifyMpcpPlugin, {
  fastify: ">=4.0.0",
  name: "fastify-mpcp",
});
