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

import type { BudgetScope, GrantInfo, MpcpContext, MpcpError, Rail, TrustBundle, VerificationResult } from "../types.js";

export type { MpcpContext } from "../types.js";

/** Maximum base64 chars for the Authorization header SBA payload (~6 KB decoded). */
const MAX_SBA_HEADER_BASE64_CHARS = 8192;

/**
 * Maximum Content-Length (bytes) allowed for the body-fallback SBA extraction.
 * The Authorization-header path is bounded by MAX_SBA_HEADER_BASE64_CHARS; the body
 * fallback is bounded here via the Content-Length header. When Content-Length is absent
 * (chunked transfer), platform-level limits apply (Cloudflare Workers: 100 MB,
 * Vercel Edge: configurable).
 */
const MAX_BODY_CONTENT_LENGTH = 65_536; // 64 KB

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Options for {@link verifyMpcpEdge}.
 *
 * Mirrors the relevant subset of {@link MpcpOptions} for the edge runtime.
 * Revocation caching (`revocationChecker`) and spend tracking (`trackSpend`,
 * `spendStorage`) are intentionally absent — edge functions are stateless.
 *
 * @see {@link MpcpOptions} for the full Node.js option set
 * @see {@link withMpcp} (Next.js Pages Router), {@link mpcp} (Express), {@link fastifyMpcp} (Fastify)
 */
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
  paymentRail?: Rail;
  /** Revocation endpoint URL. GET {endpoint}?grantId={id} → { revoked: boolean }. */
  revocationEndpoint?: string;
  /** Skip revocation check entirely. Default: false. */
  skipRevocationCheck?: boolean;
  /**
   * Pre-loaded Trust Bundles for offline key resolution (PR9).
   *
   * When provided, the verifier resolves the SBA signing key from these bundles
   * (step 1 of the MPCP key resolution algorithm) before falling back to the
   * `signingKeyPem` / env-var path. Bundles are pure JSON — no Node.js imports.
   * Supports P-256 (EC) and Ed25519 (OKP) JWKs embedded in the bundle.
   */
  trustBundles?: TrustBundle[];
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
  /** Issuer domain (e.g. "pa.example.com"). Present when created with PR29+ mpcp-reference. */
  issuer?: string;
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
    typeof a.budgetScope === "string" &&
    typeof a.minorUnit === "number" &&
    Array.isArray(a.allowedRails) &&
    (a.allowedRails as unknown[]).every((r) => typeof r === "string") &&
    Array.isArray(a.allowedAssets) &&
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

    // Reject oversized coordinates: a crafted DER blob with a malformed length
    // field could produce rPayload/sPayload longer than coordSize, causing
    // result.set() to silently write past the intended boundary.
    if (rPayload.length > coordSize || sPayload.length > coordSize) return null;

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
// Trust Bundle key resolution (pure JS — no crypto, works in all runtimes)
// ---------------------------------------------------------------------------

/** JWK shape used for Trust Bundle key resolution and Web Crypto importKey. */
type BundleJwk = JsonWebKey & { kid?: string };

/**
 * Resolve the signing key for `issuer` / `keyId` from the given Trust Bundles.
 * Bundles are sorted by expiry (latest first); expired bundles are skipped.
 * Returns the first matching JWK, or null if none found.
 */
function resolveKeyFromBundles(
  issuer: string,
  keyId: string | undefined,
  bundles: TrustBundle[],
): BundleJwk | null {
  const now = Date.now();
  const sorted = [...bundles].sort(
    (a, b) => Date.parse(b.expiresAt) - Date.parse(a.expiresAt),
  );
  for (const bundle of sorted) {
    if (Date.parse(bundle.expiresAt) <= now) continue;
    if (!bundle.approvedIssuers.includes(issuer)) continue;
    const entry = bundle.issuers.find((e) => e.issuer === issuer);
    if (!entry) continue;
    const key = keyId
      ? entry.keys.find((k) => k.kid === keyId)
      : entry.keys[0];
    if (key) return key as unknown as BundleJwk;
  }
  return null;
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
    // mpcp-reference signing chain (empirically verified — see test/edge.test.ts):
    //   1. h1  = SHA256("MPCP:SBA:1.0:" + canonicalJson(authorization))  [hashAuthorization()]
    //   2. sig = crypto.sign(null, h1, privateKey)                        [sign with null algo]
    //
    // Despite receiving a pre-hashed 32-byte buffer, crypto.sign(null, data, ecKey) applies
    // SHA-256 internally (same as sign("SHA256", data, key)), so the actual ECDSA digest
    // is SHA256(h1).
    //
    // subtle.verify({ hash: "SHA-256" }, key, sig, data) also computes SHA256(data) before
    // verifying. Passing h1 as `data` makes Web Crypto produce SHA256(h1) = the actual digest.
    // Passing the raw canonical string would produce SHA256(rawString) = h1 ≠ SHA256(h1).
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

/**
 * Verify an SBA signature against a JWK from a Trust Bundle.
 *
 * Supports:
 *   - EC P-256  (kty:"EC",  crv:"P-256")  — DER→P1363 conversion required
 *   - OKP Ed25519 (kty:"OKP", crv:"Ed25519") — raw 64-byte signature, no conversion
 *
 * Both algorithm paths compute h1 = SHA-256("MPCP:SBA:1.0:" + canonicalJson(auth))
 * then verify using the same double-hash chain as verifyEdgeSignature (see its
 * comment for the rationale).
 */
async function verifyEdgeSignatureFromJwk(sba: SbaEnvelope, jwk: BundleJwk): Promise<boolean> {
  try {
    const msgBytes = new TextEncoder().encode("MPCP:SBA:1.0:" + canonicalJsonEdge(sba.authorization));
    const h1 = await globalThis.crypto.subtle.digest("SHA-256", msgBytes); // ArrayBuffer

    if (jwk.kty === "EC" && jwk.crv === "P-256") {
      const publicKey = await globalThis.crypto.subtle.importKey(
        "jwk",
        jwk as JsonWebKey,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      const derSig = Uint8Array.from(atob(sba.signature), (c) => c.charCodeAt(0));
      const p1363 = derToP1363(derSig);
      if (!p1363) return false;
      const sigBuf = p1363.buffer.slice(p1363.byteOffset, p1363.byteOffset + p1363.byteLength) as ArrayBuffer;
      return await globalThis.crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        publicKey,
        sigBuf,
        h1,
      );
    }

    if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
      // Ed25519: crypto.sign(null, h1, edKey) in Node.js signs h1 directly with Ed25519
      // (no additional SHA-256 hashing by Node.js for Ed25519; the algorithm uses its own
      // internal hash). subtle.verify({ name: "Ed25519" }, key, sig, h1) verifies h1 directly.
      // Signature is raw 64 bytes — no DER conversion required.
      const publicKey = await globalThis.crypto.subtle.importKey(
        "jwk",
        jwk as JsonWebKey,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      const rawSig = Uint8Array.from(atob(sba.signature), (c) => c.charCodeAt(0));
      const sigBuf = rawSig.buffer.slice(rawSig.byteOffset, rawSig.byteOffset + rawSig.byteLength) as ArrayBuffer;
      return await globalThis.crypto.subtle.verify({ name: "Ed25519" }, publicKey, sigBuf, h1);
    }

    return false; // unsupported key type
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
    // Fail-open: both network errors (caught below) and non-OK HTTP responses
    // (e.g. HTTP 500 from a temporarily unavailable revocation service) are treated
    // as "not revoked" to avoid blocking legitimate payments during outages.
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

/**
 * Safe env-var reader for edge runtimes where `process` may not exist
 * (e.g. Cloudflare Workers). Returns `undefined` for absent or empty values.
 */
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
  const hasBundles = (options.trustBundles?.length ?? 0) > 0;

  if (!keyPem && !hasBundles) {
    return invalid(
      "sba_invalid",
      "No signing key configured (signingKeyPem, MPCP_SBA_SIGNING_PUBLIC_KEY_PEM, or trustBundles)",
    );
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
      // Guard: skip body parsing when Content-Length indicates an oversized payload.
      // If Content-Length is absent (chunked transfer), proceed and rely on platform limits.
      const cl = req.headers.get("content-length");
      if (cl === null || parseInt(cl, 10) <= MAX_BODY_CONTENT_LENGTH) {
        // req.clone() is required: the Web Fetch body stream can only be consumed once.
        // If the caller has already read the body, the clone will also be empty and
        // the JSON parse will throw, leaving sba as undefined.
        const body = (await req.clone().json()) as Record<string, unknown>;
        if (body && typeof body === "object") sba = body.sba;
      }
    } catch {
      // no parseable body — sba stays undefined
    }
  }

  if (!isSbaEnvelope(sba)) {
    return invalid("sba_invalid", "Invalid or missing SignedBudgetAuthorization");
  }

  // --- Trust Bundle key resolution (step 1 — checked before PEM/env-var key) ---
  // Mirrors the 3-step key resolution order in mpcp-reference PR29.
  let usedBundle = false;
  if (hasBundles && sba.issuer) {
    const jwk = resolveKeyFromBundles(sba.issuer, sba.issuerKeyId, options.trustBundles!);
    if (jwk) {
      const signatureOk = await verifyEdgeSignatureFromJwk(sba, jwk);
      if (!signatureOk) return invalid("sba_invalid", "Invalid SBA signature");
      usedBundle = true;
    }
  }

  if (!usedBundle) {
    // --- PEM/env-var key path (step 2 fallback) ---
    if (!keyPem) {
      return invalid("sba_invalid", "No signing key configured (signingKeyPem or MPCP_SBA_SIGNING_PUBLIC_KEY_PEM)");
    }
    // --- Key ID check ---
    if (keyId && sba.issuerKeyId !== keyId) {
      return invalid("sba_invalid", "Signing key ID mismatch");
    }
    // --- Signature verification ---
    const signatureOk = await verifyEdgeSignature(sba, keyPem);
    if (!signatureOk) return invalid("sba_invalid", "Invalid SBA signature");
  }

  // --- Expiry ---
  const nowMs = options.nowMs ?? Date.now();
  const expMs = Date.parse(sba.authorization.expiresAt);
  // Date.parse returns NaN for invalid date strings; NaN <= nowMs is false,
  // which would silently bypass expiry. Treat NaN as already expired.
  if (isNaN(expMs) || expMs <= nowMs) {
    return invalid("grant_expired", "SBA has expired or has an invalid expiresAt");
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
