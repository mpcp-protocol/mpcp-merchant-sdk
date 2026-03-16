export interface SpendEntry {
  grantId: string;
  idempotencyKey?: string;
  amount: string;
  currency: string;
  recordedAt: string;
}

export interface SpendStorage {
  /** Record a spend entry. Implementations must respect idempotency. */
  record(entry: SpendEntry): Promise<void>;
  /** Return the BigInt-safe sum of all recorded amounts for the given grant+currency as a string. */
  total(grantId: string, currency: string): Promise<string>;
  /** Return true if a spend entry with this idempotency key has already been recorded. */
  exists(idempotencyKey: string): Promise<boolean>;
}
