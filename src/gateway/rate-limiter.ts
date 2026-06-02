/**
 * Per-agent sliding-window request counter. The eBook is explicit that rate
 * limits are friction, not a hard barrier ("they buy time but do not stop a
 * determined agentic attacker") — so this lives alongside, not instead of,
 * deny-by-default authorization. It mainly contains resource-exhaustion / loop
 * amplification abuse.
 */
export class RateLimiter {
  private windows = new Map<string, number[]>();
  private windowMs: number;

  constructor(windowMs = 60_000) {
    this.windowMs = windowMs;
  }

  /** Returns true if allowed; records the hit when allowed. */
  check(key: string, limitPerWindow: number | undefined): { allowed: boolean; count: number } {
    if (!limitPerWindow || limitPerWindow <= 0) return { allowed: true, count: 0 };
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const hits = (this.windows.get(key) ?? []).filter((t) => t > cutoff);
    if (hits.length >= limitPerWindow) {
      this.windows.set(key, hits);
      return { allowed: false, count: hits.length };
    }
    hits.push(now);
    this.windows.set(key, hits);
    return { allowed: true, count: hits.length };
  }
}
