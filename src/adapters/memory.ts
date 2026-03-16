import type { SpendEntry, SpendStorage } from "../storage.js";

/**
 * In-memory SpendStorage implementation for development and testing.
 * Not suitable for multi-process deployments — use a persistent store in production.
 *
 * Idempotency is enforced via a synchronous Set check-and-add, which is safe
 * in Node.js's single-threaded event loop. External async stores must implement
 * their own atomic idempotency (e.g., a Redis SET NX).
 */
export class MemorySpendStorage implements SpendStorage {
  private readonly entries: SpendEntry[] = [];
  private readonly idempotencyKeys = new Set<string>();

  async record(entry: SpendEntry): Promise<void> {
    if (!/^\d+$/.test(entry.amount)) {
      throw new Error(`SpendEntry.amount must be a non-negative integer string, got: "${entry.amount}"`);
    }
    if (entry.idempotencyKey) {
      if (this.idempotencyKeys.has(entry.idempotencyKey)) return;
      this.idempotencyKeys.add(entry.idempotencyKey);
    }
    this.entries.push(entry);
  }

  async total(grantId: string, currency: string): Promise<string> {
    let sum = BigInt(0);
    for (const e of this.entries) {
      if (e.grantId === grantId && e.currency === currency) {
        sum += BigInt(e.amount);
      }
    }
    return sum.toString();
  }

  async exists(idempotencyKey: string): Promise<boolean> {
    return this.idempotencyKeys.has(idempotencyKey);
  }
}
