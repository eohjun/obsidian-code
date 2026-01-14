/**
 * TTL Map - Map with automatic expiration
 *
 * A Map wrapper that automatically removes entries after a configurable TTL.
 * Useful for caching data that should expire after a certain time.
 */

interface TtlEntry<V> {
  value: V;
  expiresAt: number;
}

/**
 * A Map that automatically removes entries after a configurable time-to-live (TTL).
 */
export class TtlMap<K, V> {
  private map = new Map<K, TtlEntry<V>>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * Create a new TtlMap.
   *
   * @param ttlMs - Time-to-live in milliseconds for each entry (default: 5 minutes)
   * @param cleanupIntervalMs - Interval for cleanup checks (default: 1 minute)
   */
  constructor(
    private readonly ttlMs: number = 5 * 60 * 1000,
    private readonly cleanupIntervalMs: number = 60 * 1000
  ) {
    this.startCleanup();
  }

  /**
   * Set a value with automatic expiration.
   */
  set(key: K, value: V): this {
    this.map.set(key, {
      value,
      expiresAt: Date.now() + this.ttlMs,
    });
    return this;
  }

  /**
   * Get a value if it exists and hasn't expired.
   * Does not delete the entry (use getAndDelete for that behavior).
   */
  get(key: K): V | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }

    return entry.value;
  }

  /**
   * Get a value and remove it from the map.
   * Useful for one-time retrieval patterns.
   */
  getAndDelete(key: K): V | undefined {
    const value = this.get(key);
    if (value !== undefined) {
      this.map.delete(key);
    }
    return value;
  }

  /**
   * Check if a key exists and hasn't expired.
   */
  has(key: K): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Delete a specific key.
   */
  delete(key: K): boolean {
    return this.map.delete(key);
  }

  /**
   * Clear all entries.
   */
  clear(): void {
    this.map.clear();
  }

  /**
   * Get the number of entries (including potentially expired ones).
   */
  get size(): number {
    return this.map.size;
  }

  /**
   * Stop the cleanup interval and clear all entries.
   * Call this when the map is no longer needed to prevent memory leaks.
   */
  dispose(): void {
    this.stopCleanup();
    this.map.clear();
  }

  /**
   * Remove all expired entries.
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.map) {
      if (now > entry.expiresAt) {
        this.map.delete(key);
      }
    }
  }

  /**
   * Start the automatic cleanup interval.
   */
  private startCleanup(): void {
    if (this.cleanupInterval) return;
    this.cleanupInterval = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
  }

  /**
   * Stop the automatic cleanup interval.
   */
  private stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
