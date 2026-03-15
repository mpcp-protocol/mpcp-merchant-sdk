# mpcp-merchant-sdk

Merchant acceptance SDK for the [Machine Payment Control Protocol (MPCP)](https://mpcp-protocol.github.io/spec/).

Provides everything a **merchant or service provider backend** needs to accept MPCP-authorized payments: verify the full artifact chain, check revocation, track spend against the policy ceiling, and integrate with standard Node.js frameworks.

> **Status: planned.** See [ROADMAP.md](./ROADMAP.md) for the development plan.
> Reference implementation and protocol core: [`mpcp-reference`](https://github.com/mpcp-protocol/mpcp-reference).

---

## What this SDK is for

A wallet or AI agent presents a `SignedBudgetAuthorization` to the merchant. The merchant needs to:

1. Verify the SBA is signed by a key authorized by a valid `PolicyGrant`
2. Confirm the grant has not been revoked
3. Confirm the amount is within the authorized ceiling
4. Record the spend so the ceiling is enforced cumulatively

The merchant SDK handles all of this as a single middleware call:

```typescript
import { mpcp } from "@mpcp/merchant-sdk";

app.use(mpcp({ revocationTtl: 60_000 }));

app.post("/charge", (req, res) => {
  if (!req.mpcp.valid) {
    return res.status(402).json(req.mpcp.error);
  }

  const { grant, amount, currency } = req.mpcp;
  // grant.grantId    — the authorized grant
  // grant.allowedPurposes — what this payment is for
  // amount / currency — what was authorized
  // Proceed with settlement...
});
```

---

## Planned API

### Express middleware

```typescript
import { mpcp } from "@mpcp/merchant-sdk";

app.use(mpcp({
  revocationTtl: 60_000,     // ms; cache revocation results
  trackSpend: true,           // enforce cumulative ceiling (default: true)
  spendStorage,               // pluggable spend store (default: in-memory)
  onEvent,                    // optional event hook
}));
```

Attaches `req.mpcp` to every request:

```typescript
interface MpcpRequest {
  valid: boolean;
  grant?: GrantInfo;
  amount?: string;
  currency?: string;
  error?: { code: string; detail: string };
}
```

Returns `402 Payment Required` with a structured error body when verification fails.

---

### Fastify plugin

```typescript
import { fastifyMpcp } from "@mpcp/merchant-sdk/fastify";

await app.register(fastifyMpcp, { revocationTtl: 60_000 });

app.post("/charge", async (req) => {
  if (!req.mpcp.valid) throw app.httpErrors.paymentRequired(req.mpcp.error);
  // ...
});
```

---

### Standalone verify function

For non-middleware use (background jobs, serverless, custom routing):

```typescript
import { verifyMpcp } from "@mpcp/merchant-sdk";

const result = await verifyMpcp(sba, {
  revocationTtl: 60_000,
  spendStorage,
});
// result.valid, result.grant, result.amount, result.error
```

---

## Relationship to mpcp-reference

`mpcp-merchant-sdk` wraps `mpcp-reference` verification — it does not re-implement protocol logic. It adds:

- Framework middleware (Express, Fastify, Next.js)
- Revocation caching to avoid per-transaction latency
- Spend tracking against the grant ceiling with idempotency key support
- Structured `402` error responses
- Event hooks for downstream webhook / audit systems

---

## Development

See [ROADMAP.md](./ROADMAP.md) for the phased implementation plan.

```bash
npm install
npm run build   # tsc
npm test        # vitest
```
