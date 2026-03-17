# mpcp-merchant-sdk — Development Roadmap

TypeScript SDK for merchants and service providers accepting MPCP-authorized payments.

**Depends on:** `mpcp-reference` (protocol core — no protocol logic is re-implemented here)
**Stack:** Node.js 22 + TypeScript (ESM), Vitest, peer dependencies for Express / Fastify / Next.js

---

## Guiding principles

**One verify call**
The entire verification pipeline — artifact chain validation, revocation check, spend enforcement — should collapse into a single `verifyMpcp(sba, options)` call. Framework adapters are thin wrappers around this.

**Transparent revocation caching**
Every call to the revocation endpoint adds latency. The SDK caches results with a configurable TTL so merchants can balance freshness against performance.

**Protocol boundary respected**
Verification rules are owned by `mpcp-reference`. This SDK adds operational concerns (caching, spend tracking, framework integration, events) — it never re-implements or bypasses the verifier.

---

## Phase 1 — Core

### PR1 — Project setup + core verifier wrapper

Stack: Node.js 22, TypeScript ESM, Vitest.

```
src/
  types.ts           — VerificationResult, MpcpOptions, MpcpError
  verify.ts          — verifyMpcp(sba, options) → VerificationResult
  index.ts           — barrel exports
```

`verifyMpcp` orchestrates the full verification pipeline:
1. `mpcp-reference`: `verifyPolicyGrant` — validates the PolicyGrant signature and fields
2. `mpcp-reference`: `verifySignedBudgetAuthorization` — validates the SBA against the grant
3. Revocation check (Phase 1: synchronous pass-through, no caching yet)
4. Amount bounds check — amount ≤ grant ceiling

```typescript
export interface VerificationResult {
  valid: boolean;
  grant?: GrantInfo;       // parsed grant info (same shape as wallet-sdk GrantInfo)
  amount?: string;
  currency?: string;
  error?: MpcpError;       // structured error when valid=false
}

export interface MpcpError {
  code: "grant_invalid" | "sba_invalid" | "grant_revoked" | "amount_exceeded" | "grant_expired";
  detail: string;
}
```

Acceptance criteria:
- Valid SBA (created by `mpcp-wallet-sdk` or `mpcp-reference`) returns `{ valid: true }`
- Each failure mode returns the correct `code`
- All protocol verification goes through `mpcp-reference` — no protocol logic re-implemented

---

### PR2 — Revocation checking with caching

Integrate `checkRevocation` from `mpcp-reference` into the verify pipeline with an in-memory TTL cache.

```
src/
  revocation.ts      — RevocationChecker (cache + HTTP check)
  cache.ts           — RevocationCache<T> (generic in-memory TTL cache)
```

```typescript
export interface MpcpOptions {
  revocationTtl?: number;       // ms; default 60_000; 0 = always check
  skipRevocationCheck?: boolean; // for testing / offline scenarios
}
```

Cache key: `grantId`. On cache miss, call the grant's `revocationEndpoint`. On cache hit within TTL, skip network call.

Acceptance criteria:
- Revoked grant returns `{ valid: false, error: { code: "grant_revoked" } }`
- Second verify call within TTL does not make a network request (mock + spy test)
- `skipRevocationCheck: true` skips both network and cache entirely
- `revocationTtl: 0` always makes a live check

---

### PR3 — Spend tracking and idempotency

Enforce cumulative spend against the policy ceiling. Support idempotency keys to prevent double-counting retried requests.

```
src/
  spend.ts           — SpendTracker
  storage.ts         — SpendStorage interface
  adapters/
    memory.ts        — MemorySpendStorage (default)
```

```typescript
export interface SpendStorage {
  record(entry: SpendEntry): Promise<void>;
  total(grantId: string, currency: string): Promise<string>;
  exists(idempotencyKey: string): Promise<boolean>;
}

export interface SpendEntry {
  grantId: string;
  idempotencyKey?: string;
  amount: string;
  currency: string;
  recordedAt: string;       // ISO 8601
}
```

`verifyMpcp` checks `storage.total(grantId, currency) + amount ≤ ceiling` before returning `valid: true`.

Acceptance criteria:
- `amount_exceeded` returned when cumulative spend would breach the ceiling
- Idempotency key: same key used twice counts only once toward the ceiling
- Spend storage is injected — `MemorySpendStorage` is the default
- `trackSpend: false` option disables tracking (for read-only verification)

---

## Phase 2 — Framework adapters

### PR4 — Express middleware

```
src/
  adapters/
    express.ts       — mpcp(options) → Express RequestHandler
```

```typescript
import { mpcp } from "@mpcp/merchant-sdk";

app.use(mpcp({ revocationTtl: 60_000, trackSpend: true }));

// req.mpcp is available on every subsequent route
app.post("/charge", (req, res) => {
  if (!req.mpcp.valid) return res.status(402).json(req.mpcp.error);
  // ...
});
```

The middleware extracts the `SignedBudgetAuthorization` from the request:
- `Authorization: MPCP <base64-encoded SBA>` header (primary)
- `req.body.sba` (secondary, for JSON POST bodies)

Returns `402 Payment Required` with `req.mpcp.error` body when `valid: false`.

Acceptance criteria:
- `req.mpcp` populated on every request
- 402 returned automatically on invalid SBA
- Works with Express 4 and Express 5

---

### PR5 — Fastify plugin

```
src/
  adapters/
    fastify.ts       — fastifyMpcp plugin
```

```typescript
import { fastifyMpcp } from "@mpcp/merchant-sdk/fastify";

await app.register(fastifyMpcp, { revocationTtl: 60_000 });

app.post("/charge", async (req) => {
  req.mpcp   // typed via module augmentation
});
```

TypeScript module augmentation adds `mpcp: MpcpRequest` to Fastify's `FastifyRequest` interface.

Acceptance criteria:
- Plugin registers cleanly with `fastify-plugin` (no encapsulation)
- `request.mpcp` fully typed
- Compatible with Fastify 4 and Fastify 5

---

### PR6 — Next.js / Edge adapter

```
src/
  adapters/
    nextjs.ts        — withMpcp(handler, options) higher-order function
    edge.ts          — Edge runtime variant (no Node.js-only imports)
```

```typescript
// Pages Router
export default withMpcp(async (req, res) => {
  if (!req.mpcp.valid) return res.status(402).json(req.mpcp.error);
  // ...
});

// App Router (Edge compatible)
export async function POST(req: Request) {
  const result = await verifyMpcpEdge(req, { revocationTtl: 60_000 });
  if (!result.valid) return Response.json(result.error, { status: 402 });
  // ...
}
```

The Edge variant avoids Node.js-specific modules (`node:crypto`, `better-sqlite3`). Uses Web Crypto API for any cryptographic operations.

Acceptance criteria:
- Pages Router HOC works with standard Next.js API routes
- App Router function runs in Vercel Edge runtime
- Bundle size of Edge variant < 40 KB gzipped

---

## Phase 3 — Production hardening

### PR7 — Event system and webhook dispatch

```
src/
  events.ts          — MpcpEventEmitter, MpcpEvent types
```

```typescript
export type MpcpEvent =
  | { type: "payment.authorized"; grant: GrantInfo; amount: string; currency: string }
  | { type: "payment.rejected"; error: MpcpError }
  | { type: "grant.revoked"; grantId: string };

export interface MpcpOptions {
  // ...existing...
  onEvent?: (event: MpcpEvent) => void | Promise<void>;
}
```

`onEvent` is called synchronously after each verification. Async handlers are fire-and-forget (errors logged, never bubble).

Use cases: webhook dispatch, audit log writes, alerting.

Acceptance criteria:
- `payment.authorized` fires on every successful verify
- `payment.rejected` fires on every failed verify
- `onEvent` errors do not affect verification result or response
- Async `onEvent` does not block the response

---

### PR8 — Conformance test suite

End-to-end tests against `mpcp-reference` golden vectors and the `mpcp-wallet-sdk` integration.

Test scenarios:
- Valid SBA (via `mpcp-reference`) → `verifyMpcp` returns `{ valid: true }`
- Tampered SBA signature → `{ valid: false, error: { code: "sba_invalid" } }`
- Revoked grant (mock endpoint) → `{ valid: false, error: { code: "grant_revoked" } }`
- Amount exceeds ceiling → `{ valid: false, error: { code: "amount_exceeded" } }`
- Cumulative spend enforcement: N payments within ceiling succeed, N+1 fails
- Idempotency: same key twice counts once
- `mpcp-wallet-sdk` + `mpcp-merchant-sdk` integration: full roundtrip

---

### PR9 — Trust Bundle support (offline verification) ✓

Enable merchants and embedded verifiers to verify artifact signatures without network access at verification time.

**Depends on:** `mpcp-reference` PR29 (Trust Bundle types + `resolveFromTrustBundle`)

#### Changes to `MpcpOptions` (`src/types.ts`)

```typescript
export interface MpcpOptions {
  // ...existing fields...
  trustBundles?: TrustBundle[];  // pre-loaded bundles; checked before HTTPS well-known
}
```

#### Implementation

- `verifyMpcp` passes `options.trustBundles` through to `verifySignedBudgetAuthorization` (from `mpcp-reference`), which performs step-1 Trust Bundle key lookup before falling back to the env-var key
- No new runtime dependencies — bundle types come from `mpcp-reference`
- `TrustBundle` re-exported from `src/index.ts` so consumers don't need to import from `mpcp-service/sdk` directly

#### Tests (`test/trust-bundle.test.ts`)

- `verifyMpcp` with `trustBundles` containing the correct signing key → `valid: true`, no env var set
- `verifyMpcp` with no `trustBundles` and no env var → `sba_invalid` (baseline: existing behaviour unchanged)
- Expired bundle in `trustBundles` → falls through to env var → `sba_invalid` (no env var set)
- Bundle with wrong key embedded → `sba_invalid`

#### Acceptance criteria

- Merchant can verify a valid SBA with only a pre-loaded Trust Bundle — no `signingKeyPem`, no env var, no network call
- Expired bundles are not used for key resolution

---

## Spend storage adapters (future)

The `SpendStorage` interface is intentionally simple. Adapter implementations for production databases are out of scope for this SDK but follow naturally:

| Adapter | Notes |
|---------|-------|
| `MemorySpendStorage` | Default; no persistence; suitable for stateless deployments with short-lived grants |
| Redis | TTL-based; suits high-throughput stateless services |
| PostgreSQL / SQLite | Durable; suitable for policy authority co-deployment |
| Custom | Any store implementing the `SpendStorage` interface |

---

## Deferred

- **Multi-SBA batching** — verify multiple SBAs in a single call (for bulk settlement)
- **Streaming payment verification** — verify spend incrementally as a stream of small payments
- **XRPL NFT revocation in middleware** — on-chain revocation check (currently only HTTP endpoint)
- **Rate limiting** — protect revocation endpoint calls from DDoS via merchant backends
- **x402 dual-proof adapter** — accept both an x402 payment proof and an MPCP SBA in the same request; verify the x402 payment on-chain and the SBA policy chain via `verifyMpcp`. Gives merchants cryptographic payment finality (x402) plus human delegation proof (MPCP) with a single middleware call. Depends on `mpcp-wallet-sdk` PR9 (`attachSba: true`) on the agent side.
