/**
 * Detects request bursts before they can exhaust relayer resources.
 *
 * The monitor keeps only timestamps from the configured rolling window, so a
 * client that has been quiet for a full window is no longer considered bursty.
 */
export interface RateLimitMonitorOptions {
  /** Maximum requests allowed for one client within the window. */
  threshold?: number;
  /** Length of the rolling window in milliseconds. */
  windowMs?: number;
}

export interface RateLimitFinding {
  rule: "RATE_LIMIT_BURST";
  severity: "HIGH";
  clientId: string;
  requestCount: number;
  threshold: number;
  windowMs: number;
  message: string;
}

export interface RateLimitResult {
  allowed: boolean;
  requestCount: number;
  finding?: RateLimitFinding;
}

export class RateLimitMonitor {
  private readonly threshold: number;
  private readonly windowMs: number;
  private readonly requests = new Map<string, number[]>();

  constructor(options: RateLimitMonitorOptions = {}) {
    this.threshold = options.threshold ?? 100;
    this.windowMs = options.windowMs ?? 60_000;

    if (!Number.isInteger(this.threshold) || this.threshold < 1) {
      throw new Error("Rate-limit threshold must be a positive integer");
    }
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new Error("Rate-limit window must be greater than zero");
    }
  }

  /** Records a request and flags the first request above the configured limit. */
  record(clientId: string, now: number = Date.now()): RateLimitResult {
    const windowStart = now - this.windowMs;
    const activeRequests = (this.requests.get(clientId) ?? []).filter(
      (timestamp) => timestamp > windowStart,
    );
    activeRequests.push(now);
    this.requests.set(clientId, activeRequests);

    if (activeRequests.length <= this.threshold) {
      return { allowed: true, requestCount: activeRequests.length };
    }

    return {
      allowed: false,
      requestCount: activeRequests.length,
      finding: {
        rule: "RATE_LIMIT_BURST",
        severity: "HIGH",
        clientId,
        requestCount: activeRequests.length,
        threshold: this.threshold,
        windowMs: this.windowMs,
        message: `Request burst detected for '${clientId}': ${activeRequests.length} requests within ${this.windowMs}ms (limit ${this.threshold}).`,
      },
    };
  }

  /** Returns the current rolling-window count without recording another request. */
  getRequestCount(clientId: string, now: number = Date.now()): number {
    const windowStart = now - this.windowMs;
    const activeRequests = (this.requests.get(clientId) ?? []).filter(
      (timestamp) => timestamp > windowStart,
    );
    this.requests.set(clientId, activeRequests);
    return activeRequests.length;
  }
}

export default RateLimitMonitor;
