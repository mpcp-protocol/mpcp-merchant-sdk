import { checkRevocation } from "mpcp-service/sdk";
import { RevocationCache } from "./cache.js";

interface RevocationResult {
  revoked: boolean;
  revokedAt?: string;
}

/**
 * Wraps mpcp-reference's checkRevocation with an in-memory TTL cache.
 * Fail-open: network/parse errors do not block payment.
 */
export class RevocationChecker {
  private readonly cache: RevocationCache<RevocationResult>;
  private readonly ttlMs: number;

  constructor(options?: { ttlMs?: number }) {
    this.ttlMs = options?.ttlMs ?? 60_000;
    this.cache = new RevocationCache<RevocationResult>();
  }

  async check(endpoint: string, grantId: string): Promise<RevocationResult> {
    if (this.ttlMs > 0) {
      const cached = this.cache.get(grantId);
      if (cached !== undefined) return cached;
    }

    const result = await checkRevocation(endpoint, grantId);
    const outcome: RevocationResult = {
      revoked: result.revoked,
      revokedAt: result.revokedAt,
    };

    if (this.ttlMs > 0) {
      this.cache.set(grantId, outcome, this.ttlMs);
    }

    return outcome;
  }

  clearCache(): void {
    this.cache.clear();
  }
}
