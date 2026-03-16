// allowSyntheticDefaultImports is required in tsconfig for this default import because
// fastify-plugin uses `export = fastifyPlugin` (CJS-style), not `export default`.
import fp from "fastify-plugin";
import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { verifyMpcp } from "../verify.js";
import { RevocationChecker } from "../revocation.js";
import { MemorySpendStorage } from "./memory.js";
import type { MpcpContext, MpcpOptions, VerificationResult } from "../types.js";
import type { SpendStorage } from "../storage.js";

export type { MpcpContext } from "../types.js";

/**
 * Base64 character limit for the Authorization header SBA payload.
 * Base64 encodes 3 bytes as 4 chars, so this allows ~6 KB of decoded JSON.
 */
const MAX_SBA_HEADER_BASE64_CHARS = 8192;

// Extend FastifyRequest type — module augmentation is visible to all consumers
// that import from "@mpcp/merchant-sdk/fastify".
// The type is MpcpContext | null because the decorator starts as null; the
// preHandler hook always sets it to a MpcpContext before route handlers run.
declare module "fastify" {
  interface FastifyRequest {
    mpcp: MpcpContext | null;
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
  // Destructure adapter-only fields so they are never forwarded to verifyMpcp.
  const { getAmount, getCurrency, strict: strictOpt, ...mpcpOptions } = options;

  // Create shared instances once per plugin registration, not per request.
  const sharedChecker = mpcpOptions.skipRevocationCheck
    ? undefined
    : (mpcpOptions.revocationChecker ?? new RevocationChecker({ ttlMs: mpcpOptions.revocationTtl }));

  const sharedStorage: SpendStorage | undefined = mpcpOptions.trackSpend
    ? (mpcpOptions.spendStorage ?? new MemorySpendStorage())
    : undefined;

  const strict = strictOpt !== false;

  // Initial value is null; the preHandler hook always sets request.mpcp before
  // any route handler runs. The module augmentation above provides the public type.
  fastify.decorateRequest("mpcp", null);

  /**
   * NOTE on Fastify hook lifecycle:
   *   - Calling `reply.send()` is what prevents the route handler from running —
   *     not `return`. The `return` after `reply.send()` simply exits the hook function.
   *   - Returning from the hook WITHOUT calling `reply.send()` always proceeds to the
   *     next lifecycle step (i.e., the route handler is called).
   *   - Body-parse errors (malformed JSON Content-Type) cause Fastify to skip this hook
   *     entirely, leaving `request.mpcp` as null. Routes that depend on `request.mpcp`
   *     should not be reachable without a valid body or Authorization header.
   */
  fastify.addHook("preHandler", async (request, reply) => {
    // --- Extract SBA ---
    let sba: unknown = undefined;

    const authHeader = request.headers["authorization"];
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

    if (sba === undefined && request.body && typeof request.body === "object") {
      sba = (request.body as Record<string, unknown>).sba;
    }

    if (sba === undefined) {
      request.mpcp = {
        valid: false,
        error: { code: "sba_invalid", detail: "No SBA provided in Authorization header or request body" },
      };
      if (strict) {
        reply.code(402).send({ error: request.mpcp.error.code, detail: request.mpcp.error.detail });
      }
      return;
    }

    // --- Extract amount / currency ---
    let amount: string;
    let currency: string;
    try {
      amount = getAmount(request);
      currency = getCurrency(request);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to extract amount or currency from request";
      request.mpcp = { valid: false, error: { code: "sba_invalid", detail } };
      if (strict) {
        reply.code(402).send({ error: "sba_invalid", detail });
      }
      return;
    }

    // --- Verify ---
    let result: VerificationResult;
    try {
      result = await verifyMpcp(sba, {
        ...mpcpOptions,
        amount,
        currency,
        revocationChecker: sharedChecker,
        spendStorage: sharedStorage,
      });
    } catch {
      // Unexpected internal error — treat as sba_invalid to return a structured 402
      // rather than letting Fastify's default error handler produce a 500.
      request.mpcp = { valid: false, error: { code: "sba_invalid", detail: "Verification error" } };
      if (strict) {
        reply.code(402).send({ error: "sba_invalid", detail: "Verification error" });
      }
      return;
    }

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
 *   1. `Authorization: MPCP <base64-encoded-json>` header (~6 KB decoded limit)
 *   2. `request.body.sba` fallback (requires a body parser to be registered)
 *
 * On valid: sets `request.mpcp` with grant info and calls the route handler.
 * On invalid (strict mode, default): replies 402 and skips the handler.
 *
 * @example
 * ```ts
 * import { fastifyMpcp } from "@mpcp/merchant-sdk/fastify";
 *
 * // Fastify does not parse JSON bodies by default — register a body parser first
 * // (or use @fastify/formbody for form data).
 * await app.register(import("@fastify/formbody"));
 *
 * await app.register(fastifyMpcp, {
 *   revocationTtl: 60_000,
 *   getAmount: (req) => (req.body as { amount: string }).amount,
 *   getCurrency: () => "USD",
 * });
 *
 * app.post("/charge", async (req) => {
 *   // req.mpcp is always set by the preHandler hook before this runs.
 *   req.mpcp!.grant  // typed via module augmentation
 * });
 * ```
 */
export const fastifyMpcp = fp(fastifyMpcpPlugin, {
  fastify: ">=5.0.0",
  name: "fastify-mpcp",
});
