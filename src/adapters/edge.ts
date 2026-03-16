/**
 * Edge-compatible MPCP verifier.
 *
 * This module has NO `node:crypto` imports. It relies entirely on the
 * Web Crypto API (`globalThis.crypto.subtle`) and is safe to use in:
 *   - Vercel Edge Runtime
 *   - Cloudflare Workers / Pages Functions
 *   - Deno Deploy
 *   - Node.js 22+ (which ships a global Web Crypto implementation)
 *
 * Trade-offs vs `verifyMpcp`:
 *   - No built-in revocation caching (wrap with a KV-backed cache if needed)
 *   - No cumulative spend tracking (stateless; inject a KV-backed SpendStorage if needed)
 *   - Does not call mpcp-reference; performs verification independently using the
 *     protocol rules documented in the MPCP spec
 */

import type { BudgetScope, GrantInfo, MpcpContext, MpcpError, VerificationResult } from "../types.js";

export type { MpcpContext } from "../types.js";

/** Maximum base64 chars for the Authorization header SBA payload (~6 KB decoded). */
const MAX_SBA_HEADER_BASE64_CHARS = 8192;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface EdgeMpcpOptions {
  /** Requested payment in minor units (e.g. "1500" = $15.00 for USD). */
  amount: string;
  /** Expected ISO 4217 currency code. Must match the SBA's currency. */
  currency: string;
  /** If set, checked against SBA's destinationAllowlist. */
  merchantId?: string;
  /**
   * Agent public key PEM (SPKI format).
   * Falls back to `MPCP_SBA_SIGNING_PUBLIC_KEY_PEM` env var.
   */
  signingKeyPem?: string;
  /**
   * Expected issuer key ID.
   * Falls back to `MPCP_SBA_SIGNING_KEY_ID` env var.
   */
  signingKeyId?: string;
  /** Override clock for testing (ms since epoch). */
  nowMs?: number;
  /**
   * Payment rail to validate against SBA's allowedRails.
   * Omitting this skips rail enforcement.
   */
  paymentRail?: string;
  /** Revocation endpoint URL. GET {endpoint}?grantId={id} → { revoked: boolean }. */
  revocationEndpoint?: string;
  /** Skip revocation check entirely. Default: false. */
  skipRevocationCheck?: boolean;
}

// ---------------------------------------------------------------------------
// SBA shape
// ---------------------------------------------------------------------------

interface SbaAuth {
  version: string;
  budgetId: string;
  grantId: string;
  sessionId: string;
  actorId: string;
  policyHash: string;
  currency: string;
  minorUnit: number;
  budgetScope: string;
  maxAmountMinor: string;
  allowedRails: string[];
  allowedAssets: unknown[];
  destinationAllowlist: string[];
  expiresAt: string;
}

interface SbaEnvelope {
  authorization: SbaAuth;
  issuerKeyId: string;
  signature: string;
}

function isSbaEnvelope(value: unknown): value is SbaEnvelope {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.issuerKeyId !== "string" || typeof v.signature !== "string") return false;
  if (!v.authorization || typeof v.authorization !== "object") return false;
  const a = v.authorization as Record<string, unknown>;
  return (
    typeof a.version === "string" &&
    typeof a.budgetId === "string" &&
    typeof a.grantId === "string" &&
    typeof a.sessionId === "string" &&
    typeof a.actorId === "string" &&
    typeof a.policyHash === "string" &&
    typeof a.currency === "string" &&
    typeof a.maxAmountMinor === "string" &&
    typeof a.expiresAt === "string" &&
    Array.isArray(a.allowedRails) &&
    Array.isArray(a.destinationAllowlist)
  );
}

// ---------------------------------------------------------------------------
// Canonical JSON (inlined from mpcp-reference to avoid node:crypto dependency)
// ---------------------------------------------------------------------------

function canonicalJsonEdge(value: unknown): string {
  if (value === undefined) throw new Error("Cannot canonicalize undefined");
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${(value as unknown[]).map((v) => canonicalJsonEdge(v === undefined ? null : v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const parts = Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined && obj[k] !== null)
    .map((k) => `${JSON.stringify(k)}:${canonicalJsonEdge(obj[k]!)}`);
  return `{${parts.join(",")}}`;
}

// ---------------------------------------------------------------------------
// PEM → ArrayBuffer (for Web Crypto importKey)
// ---------------------------------------------------------------------------

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  // Slice to get a true ArrayBuffer (not SharedArrayBuffer) required by SubtleCrypto.
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// ---------------------------------------------------------------------------
// DER-encoded ECDSA signature → IEEE P1363 (r ∥ s, each coordSize bytes)
//
// Node.js `crypto.sign(null, preHash, ecKey)` produces DER-encoded ECDSA.
// Web Crypto `subtle.verify({ name:'ECDSA', hash:'SHA-256' }, ...)` requires
// IEEE P1363 format (raw r ∥ s, 32 bytes each for P-256).
// ---------------------------------------------------------------------------

function derToP1363(der: Uint8Array, coordSize = 32): Uint8Array | null {
  try {
    if (der[0] !== 0x30) return null; // Not a SEQUENCE

    // Skip SEQUENCE tag + length (handle long-form length)
    let offset = 2;
    if (der[1] & 0x80) offset += der[1] & 0x7f;

    // Parse r
    if (der[offset] !== 0x02) return null;
    offset++;
    const rLen = der[offset++];
    const rPad = der[offset] === 0x00 ? 1 : 0; // leading 0x00 = positive-integer marker
    const rPayload = der.slice(offset + rPad, offset + rLen);
    offset += rLen;

    // Parse s
    if (der[offset] !== 0x02) return null;
    offset++;
    const sLen = der[offset++];
    const sPad = der[offset] === 0x00 ? 1 : 0;
    const sPayload = der.slice(offset + sPad, offset + sLen);

    // Build P1363: right-align r and s in their respective halves
    const result = new Uint8Array(coordSize * 2);
    result.set(rPayload, coordSize - rPayload.length);
    result.set(sPayload, coordSize * 2 - sPayload.length);
    return result;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Signature verification via Web Crypto
// ---------------------------------------------------------------------------

async function verifyEdgeSignature(sba: SbaEnvelope, keyPem: string): Promise<boolean> {
  try {
    const publicKey = await globalThis.crypto.subtle.importKey(
      "spki",
      pemToDer(keyPem),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    // mpcp-reference signing chain:
    //   1. h1 = SHA256("MPCP:SBA:1.0:" + canonicalJson(authorization))
    //   2. sig = crypto.sign(null, h1, privateKey)
    // crypto.sign(null, data, ecKey) ALWAYS hashes data with SHA-256 internally,
    // so the actual ECDSA digest is SHA256(h1).
    // Web Crypto subtle.verify({ hash: "SHA-256" }, key, sig, data) computes SHA256(data)
    // before verifying. Passing h1 as data makes Web Crypto compute SHA256(h1) = the actual digest.
    const msgBytes = new TextEncoder().encode("MPCP:SBA:1.0:" + canonicalJsonEdge(sba.authorization));
    const h1 = await globalThis.crypto.subtle.digest("SHA-256", msgBytes); // ArrayBuffer
    const derSig = Uint8Array.from(atob(sba.signature), (c) => c.charCodeAt(0));
    const p1363 = derToP1363(derSig);
    if (!p1363) return false;
    // Slice to true ArrayBuffer (not SharedArrayBuffer) required by SubtleCrypto.
    const sigBuf = p1363.buffer.slice(p1363.byteOffset, p1363.byteOffset + p1363.byteLength) as ArrayBuffer;
    return await globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      sigBuf,
      h1,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Revocation check (fetch-based, fail-open)
// ---------------------------------------------------------------------------

async function checkRevocationEdge(endpoint: string, grantId: string): Promise<boolean> {
  try {
    const url = `${endpoint}?grantId=${encodeURIComponent(grantId)}`;
    const res = await fetch(url);
    if (!res.ok) return false;
    const data = (await res.json()) as { revoked?: boolean };
    return Boolean(data.revoked);
  } catch {
    return false; // fail-open: network errors do not block payment
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function invalid(code: MpcpError["code"], detail: string): VerificationResult {
  return { valid: false, error: { code, detail } };
}

function getEnvVar(name: string): string | undefined {
  try {
    return (typeof process !== "undefined" && process.env[name]) || undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify a SignedBudgetAuthorization (SBA) in an Edge-compatible runtime.
 *
 * Unlike `verifyMpcp`, this function has **no `node:crypto` imports** and relies
 * entirely on `globalThis.crypto.subtle` (Web Crypto API). It is safe to deploy
 * in Vercel Edge, Cloudflare Workers, Deno Deploy, and Node.js 22+.
 *
 * Extracts the SBA from:
 *   1. `Authorization: MPCP <base64-encoded-json>` header (~6 KB decoded limit)
 *   2. JSON request body `.sba` field
 *
 * Revocation caching is not built-in. For high-traffic routes, wrap the
 * revocation check with an edge KV store (e.g. Vercel KV, Cloudflare KV).
 *
 * @example
 * ```ts
 * // app/api/charge/route.ts  (Next.js App Router)
 * import { verifyMpcpEdge } from "@mpcp/merchant-sdk/edge";
 *
 * export async function POST(req: Request) {
 *   const result = await verifyMpcpEdge(req, {
 *     amount: "1000",
 *     currency: "USD",
 *     signingKeyPem: process.env.MPCP_SIGNING_PUBLIC_KEY_PEM,
 *     skipRevocationCheck: true,
 *   });
 *   if (!result.valid) return Response.json(result.error, { status: 402 });
 *   return Response.json({ ok: true });
 * }
 * ```
 */
export async function verifyMpcpEdge(req: Request, options: EdgeMpcpOptions): Promise<VerificationResult> {
  const keyPem = options.signingKeyPem ?? getEnvVar("MPCP_SBA_SIGNING_PUBLIC_KEY_PEM");
  const keyId = options.signingKeyId ?? getEnvVar("MPCP_SBA_SIGNING_KEY_ID");

  if (!keyPem) {
    return invalid("sba_invalid", "No signing key configured (signingKeyPem or MPCP_SBA_SIGNING_PUBLIC_KEY_PEM)");
  }

  // --- Extract SBA ---
  let sba: unknown = undefined;

  const authHeader = req.headers.get("authorization");
  if (authHeader && authHeader.startsWith("MPCP ")) {
    const encoded = authHeader.slice(5).trim();
    if (encoded.length <= MAX_SBA_HEADER_BASE64_CHARS) {
      try {
        sba = JSON.parse(atob(encoded));
      } catch {
        // fall through to body fallback
      }
    }
  }

  if (sba === undefined) {
    try {
      const body = (await req.clone().json()) as Record<string, unknown>;
      if (body && typeof body === "object") sba = body.sba;
    } catch {
      // no parseable body — sba stays undefined
    }
  }

  if (!isSbaEnvelope(sba)) {
    return invalid("sba_invalid", "Invalid or missing SignedBudgetAuthorization");
  }

  // --- Key ID check ---
  if (keyId && sba.issuerKeyId !== keyId) {
    return invalid("sba_invalid", "Signing key ID mismatch");
  }

  // --- Signature verification ---
  const signatureOk = await verifyEdgeSignature(sba, keyPem);
  if (!signatureOk) return invalid("sba_invalid", "Invalid SBA signature");

  // --- Expiry ---
  const nowMs = options.nowMs ?? Date.now();
  if (Date.parse(sba.authorization.expiresAt) <= nowMs) {
    return invalid("grant_expired", "SBA has expired");
  }

  // --- Currency ---
  if (options.currency !== sba.authorization.currency) {
    return invalid(
      "sba_invalid",
      `Currency mismatch: expected ${options.currency}, got ${sba.authorization.currency}`,
    );
  }

  // --- Amount ---
  try {
    if (BigInt(options.amount) > BigInt(sba.authorization.maxAmountMinor)) {
      return invalid(
        "amount_exceeded",
        `Amount ${options.amount} exceeds grant ceiling ${sba.authorization.maxAmountMinor}`,
      );
    }
  } catch {
    return invalid("sba_invalid", "Invalid amount or maxAmountMinor value");
  }

  // --- Rail check ---
  if (options.paymentRail && !sba.authorization.allowedRails.includes(options.paymentRail)) {
    return invalid("sba_invalid", `Payment rail '${options.paymentRail}' not in allowedRails`);
  }

  // --- Destination allowlist ---
  if (options.merchantId && sba.authorization.destinationAllowlist.length > 0) {
    if (!sba.authorization.destinationAllowlist.includes(options.merchantId)) {
      return invalid("destination_not_allowed", "Merchant not in destination allowlist");
    }
  }

  // --- Revocation (fail-open) ---
  if (!options.skipRevocationCheck && options.revocationEndpoint) {
    const revoked = await checkRevocationEdge(options.revocationEndpoint, sba.authorization.grantId);
    if (revoked) return invalid("grant_revoked", "Grant has been revoked");
  }

  // --- Success ---
  const auth = sba.authorization;
  const grant: GrantInfo = {
    grantId: auth.grantId,
    policyHash: auth.policyHash,
    sessionId: auth.sessionId,
    actorId: auth.actorId,
    budgetScope: auth.budgetScope as BudgetScope,
    maxAmountMinor: auth.maxAmountMinor,
    currency: auth.currency,
    allowedRails: auth.allowedRails as GrantInfo["allowedRails"],
    expiresAt: auth.expiresAt,
  };

  return { valid: true, grant, amount: options.amount, currency: auth.currency };
}
