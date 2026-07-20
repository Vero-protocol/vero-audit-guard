export type CircuitBreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  resetTimeoutMs?: number;
  now?: () => number;
}

export interface CircuitBreakerSnapshot {
  state: CircuitBreakerState;
  consecutiveFailures: number;
  openedAt: number | null;
  lastReason: string | null;
}

export class CircuitBreakerError extends Error {
  public readonly retryAfterMs: number;

  public constructor(message: string, retryAfterMs = 0) {
    super(message);
    this.name = "CircuitBreakerError";
    this.retryAfterMs = retryAfterMs;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ProtocolCircuitBreaker {
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly now: () => number;
  private state: CircuitBreakerState = "CLOSED";
  private consecutiveFailures = 0;
  private openedAt: number | null = null;
  private lastReason: string | null = null;
  private halfOpenProbeInFlight = false;
  private generation = 0;

  public constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? 3;
    this.resetTimeoutMs = options.resetTimeoutMs ?? 30_000;
    this.now = options.now ?? Date.now;

    if (!Number.isInteger(this.failureThreshold) || this.failureThreshold < 1) {
      throw new CircuitBreakerError("failureThreshold must be a positive integer");
    }
    if (!Number.isInteger(this.resetTimeoutMs) || this.resetTimeoutMs < 1) {
      throw new CircuitBreakerError("resetTimeoutMs must be a positive integer");
    }
  }

  public getSnapshot(): CircuitBreakerSnapshot {
    return {
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      openedAt: this.openedAt,
      lastReason: this.lastReason,
    };
  }

  public async execute<T>(operation: () => Promise<T> | T): Promise<T> {
    if (typeof operation !== "function") {
      throw new CircuitBreakerError("operation must be a function");
    }

    const generation = this.acquirePermission();
    try {
      const result = await operation();
      this.recordSuccess(generation);
      return result;
    } catch (error) {
      this.recordFailure(generation, error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  public trip(reason: string): void {
    const normalizedReason = this.requireReason(reason);
    this.state = "OPEN";
    this.openedAt = this.now();
    this.lastReason = normalizedReason;
    this.consecutiveFailures = this.failureThreshold;
    this.halfOpenProbeInFlight = false;
    this.generation += 1;
  }

  public reset(): void {
    this.state = "CLOSED";
    this.consecutiveFailures = 0;
    this.openedAt = null;
    this.lastReason = null;
    this.halfOpenProbeInFlight = false;
    this.generation += 1;
  }

  private acquirePermission(): number {
    if (this.state === "OPEN") {
      const elapsed = this.now() - (this.openedAt ?? this.now());
      if (elapsed < this.resetTimeoutMs) {
        throw new CircuitBreakerError(
          `protocol circuit is open${this.lastReason ? `: ${this.lastReason}` : ""}`,
          this.resetTimeoutMs - Math.max(0, elapsed)
        );
      }
      this.state = "HALF_OPEN";
      this.halfOpenProbeInFlight = false;
    }

    if (this.state === "HALF_OPEN") {
      if (this.halfOpenProbeInFlight) {
        throw new CircuitBreakerError("protocol circuit is testing recovery");
      }
      this.halfOpenProbeInFlight = true;
    }

    return this.generation;
  }

  private recordSuccess(generation: number): void {
    if (generation !== this.generation) return;
    this.state = "CLOSED";
    this.consecutiveFailures = 0;
    this.openedAt = null;
    this.lastReason = null;
    this.halfOpenProbeInFlight = false;
  }

  private recordFailure(generation: number, reason: string): void {
    if (generation !== this.generation) return;
    this.halfOpenProbeInFlight = false;
    this.consecutiveFailures += 1;
    this.lastReason = this.requireReason(reason);
    if (this.state === "HALF_OPEN" || this.consecutiveFailures >= this.failureThreshold) {
      this.state = "OPEN";
      this.openedAt = this.now();
    }
  }

  private requireReason(reason: string): string {
    if (typeof reason !== "string" || reason.trim().length === 0) {
      throw new CircuitBreakerError("circuit breaker reason must not be empty");
    }
    return reason.trim();
  }
}

export const globalProtocolCircuitBreaker = new ProtocolCircuitBreaker();

export default ProtocolCircuitBreaker;
