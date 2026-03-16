import { describe, it, expect, vi } from "vitest";
import { RevocationCache } from "../src/cache.js";

describe("RevocationCache", () => {
  it("returns undefined for missing key", () => {
    const cache = new RevocationCache<string>();
    expect(cache.get("missing")).toBeUndefined();
  });

  it("returns value within TTL", () => {
    const cache = new RevocationCache<string>();
    cache.set("k", "v", 60_000);
    expect(cache.get("k")).toBe("v");
  });

  it("returns undefined after TTL expires", () => {
    const cache = new RevocationCache<string>();
    cache.set("k", "v", 1);
    vi.useFakeTimers();
    vi.advanceTimersByTime(10);
    expect(cache.get("k")).toBeUndefined();
    vi.useRealTimers();
  });

  it("clear() removes all entries", () => {
    const cache = new RevocationCache<number>();
    cache.set("a", 1, 60_000);
    cache.set("b", 2, 60_000);
    cache.clear();
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it("enforces maxSize via FIFO eviction", () => {
    const cache = new RevocationCache<number>({ maxSize: 3 });
    cache.set("a", 1, 60_000);
    cache.set("b", 2, 60_000);
    cache.set("c", 3, 60_000);
    expect(cache.size).toBe(3);

    // Adding a 4th entry evicts "a" (first inserted)
    cache.set("d", 4, 60_000);
    expect(cache.size).toBe(3);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBe(2);
    expect(cache.get("c")).toBe(3);
    expect(cache.get("d")).toBe(4);
  });

  it("overwriting an existing key does not grow beyond maxSize", () => {
    const cache = new RevocationCache<number>({ maxSize: 2 });
    cache.set("a", 1, 60_000);
    cache.set("b", 2, 60_000);
    cache.set("a", 99, 60_000); // overwrite — Map updates in-place, no new key
    expect(cache.size).toBe(2);
    expect(cache.get("a")).toBe(99);
  });

  it("size reflects live (non-expired) entries after lazy eviction", () => {
    const cache = new RevocationCache<string>();
    vi.useFakeTimers();
    cache.set("x", "val", 10);
    expect(cache.size).toBe(1);
    vi.advanceTimersByTime(20);
    cache.get("x"); // triggers lazy delete
    expect(cache.size).toBe(0);
    vi.useRealTimers();
  });
});
