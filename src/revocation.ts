import { checkRevocation } from "mpcp-service/sdk";
import { RevocationCache } from "./cache.js";

interface RevocationResult {
  revoked: boolean;
  revokedAt?: string;
}

/**
 * Wraps mpcp-reference's checkRevocation with an in-memory TTL cache.
 * Fail-open: network/parse errors do not block payment.
 *
 * Cache key is `${endpoint}:${grantId}` to avoid cross-endpoint cache hits
 * when a single checker instance is shared across different revocation services.
 */
export class RevocationChecker {
  private readonly cache: RevocationCache<RevocationResult>;
  private readonly ttlMs: number;

  constructor(options?: { ttlMs?: number; maxCacheSize?: number }) {
    this.ttlMs = options?.ttlMs ?? 60_000;
    this.cache = new RevocationCache<RevocationResult>({ maxSize: options?.maxCacheSize });
  }

  async check(endpoint: string, grantId: string): Promise<RevocationResult> {
    const cacheKey = `${endpoint}:${grantId}`;

    if (this.ttlMs > 0) {
      const cached = this.cache.get(cacheKey);
      if (cached !== undefined) return cached;
    }

    const result = await checkRevocation(endpoint, grantId);

    if (result.error) {
      // Fail-open: log-worthy but non-fatal. Callers can observe via the returned value.
      // Wire a logger here if needed: logger.warn({ endpoint, grantId, error: result.error })
      return { revoked: false };
    }

    const outcome: RevocationResult = {
      revoked: result.revoked,
      revokedAt: result.revokedAt,
    };

    if (this.ttlMs > 0) {
      this.cache.set(cacheKey, outcome, this.ttlMs);
    }

    return outcome;
  }

  clearCache(): void {
    this.cache.clear();
  }
}
