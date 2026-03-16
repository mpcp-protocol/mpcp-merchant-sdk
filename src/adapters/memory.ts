import type { SpendEntry, SpendStorage } from "../storage.js";

/**
 * In-memory SpendStorage implementation for development and testing.
 * Not suitable for multi-process deployments — use a persistent store in production.
 */
export class MemorySpendStorage implements SpendStorage {
  private readonly entries: SpendEntry[] = [];

  async record(entry: SpendEntry): Promise<void> {
    if (entry.idempotencyKey && (await this.exists(entry.idempotencyKey))) {
      return;
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
    return this.entries.some((e) => e.idempotencyKey === idempotencyKey);
  }
}
