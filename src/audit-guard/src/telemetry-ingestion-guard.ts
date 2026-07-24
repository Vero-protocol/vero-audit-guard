/**
 * Telemetry Ingestion Guard — VAG-012
 *
 * Adds backpressure and rate limiting at the telemetry ingestion boundary so
 * that event bursts cannot exhaust memory or CPU and delay detection of real
 * anomalies.
 *
 * Design constraints
 * ------------------
 * • STRICTLY OBSERVATIONAL — this module has no authority to halt, pause, or
 *   block on-chain operations.  It only controls whether telemetry events are
 *   accepted into the local processing queue.
 * • Token-bucket rate limiter: fixed capacity of tokens that refill at a
 *   configurable rate (tokens per second).  Each ingested event costs 1 token.
 * • Bounded FIFO queue with drop-oldest policy: when the queue is full the
 *   oldest pending event is silently dropped (and logged) to make room for the
 *   incoming one, preventing unbounded memory growth.
 * • All rate-limit hits and dropped events surface as console alerts — never
 *   silent failures.
 * • No bare panics / throws that escape the public API — every error is
 *   captured and returned via IngestionResult.
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Outcome of a single ingest() call. */
export type IngestionOutcome =
  | "ACCEPTED"         // event passed rate-limit check and was enqueued
  | "RATE_LIMITED"     // token bucket exhausted — event was NOT enqueued
  | "QUEUE_FULL_DROP"  // queue was full; oldest event dropped to make room
  | "MALFORMED";       // event failed basic validation — not enqueued

export interface IngestionResult {
  outcome: IngestionOutcome;
  queueDepth: number;
  tokensRemaining: number;
  /** Only set when outcome is MALFORMED. */
  validationError?: string;
  /** Only set when outcome is QUEUE_FULL_DROP — describes the dropped item. */
  droppedEventId?: string;
}

/** Minimal shape an event must satisfy to be accepted. */
export interface TelemetryEvent {
  /** Unique identifier for the event. Validated to be a non-empty string. */
  id: string;
  /** ISO-8601 timestamp. Validated to be parseable by Date. */
  timestamp: string;
  /** Arbitrary payload — not further validated here. */
  payload: unknown;
}

export interface TelemetryIngestionGuardOptions {
  /**
   * Maximum number of tokens the bucket can hold.
   * Also the maximum burst size.
   * Default: 100
   */
  bucketCapacity?: number;
  /**
   * Number of tokens refilled per second.
   * Default: 50
   */
  refillRatePerSecond?: number;
  /**
   * Maximum number of events that can sit in the queue awaiting processing.
   * When the queue is full the oldest event is dropped to make room.
   * Default: 500
   */
  maxQueueDepth?: number;
  /**
   * Label used in log lines to identify the source of ingestion events.
   * Default: "telemetry"
   */
  sourceName?: string;
  /**
   * Override Date.now for deterministic testing.
   * @internal
   */
  _nowFn?: () => number;
}

// ---------------------------------------------------------------------------
// Internal token-bucket implementation
// ---------------------------------------------------------------------------

/**
 * Token-bucket rate limiter.
 *
 * Tokens are lazily refilled on every tryConsume() call — no background timer
 * is needed, which keeps the implementation simple and testable.
 *
 * This class is intentionally NOT exported — use TelemetryIngestionGuard.
 */
class TokenBucket {
  private tokens: number;
  private lastRefillTime: number;

  private readonly capacity: number;
  private readonly refillRatePerMs: number; // tokens per millisecond
  private readonly nowFn: () => number;

  constructor(
    capacity: number,
    refillRatePerSecond: number,
    nowFn: () => number = Date.now
  ) {
    if (capacity <= 0) throw new Error("TokenBucket: capacity must be > 0");
    if (refillRatePerSecond <= 0)
      throw new Error("TokenBucket: refillRatePerSecond must be > 0");

    this.capacity = capacity;
    this.tokens = capacity; // start full
    this.refillRatePerMs = refillRatePerSecond / 1000;
    this.nowFn = nowFn;
    this.lastRefillTime = nowFn();
  }

  /** Attempt to consume one token. Returns true if successful. */
  tryConsume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** Current token count (fractional, floored for display). */
  get available(): number {
    // Return the refilled count without mutating state, for read-only snapshots.
    const now = this.nowFn();
    const elapsed = Math.max(0, now - this.lastRefillTime);
    const refilled = elapsed * this.refillRatePerMs;
    return Math.min(this.capacity, this.tokens + refilled);
  }

  private refill(): void {
    const now = this.nowFn();
    const elapsed = Math.max(0, now - this.lastRefillTime);
    const tokensToAdd = elapsed * this.refillRatePerMs;
    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefillTime = now;
  }

  /** Reset to full capacity — for testing. */
  reset(): void {
    this.tokens = this.capacity;
    this.lastRefillTime = this.nowFn();
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateEvent(event: unknown): string | null {
  if (event === null || event === undefined) {
    return "event must not be null or undefined";
  }
  if (typeof event !== "object" || Array.isArray(event)) {
    return "event must be a plain object";
  }
  const e = event as Record<string, unknown>;

  if (typeof e["id"] !== "string" || e["id"].trim() === "") {
    return "event.id must be a non-empty string";
  }
  if (typeof e["timestamp"] !== "string" || isNaN(Date.parse(e["timestamp"] as string))) {
    return "event.timestamp must be a valid ISO-8601 date string";
  }
  if (!("payload" in e)) {
    return "event.payload is required";
  }
  return null; // valid
}

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

/**
 * TelemetryIngestionGuard wraps any telemetry ingestion pipeline with:
 *  1. Token-bucket rate limiting
 *  2. Bounded queue with drop-oldest backpressure
 *  3. Structured validation of incoming events
 *  4. Observable alerting for every rate-limit hit or drop
 *
 * Usage
 * -----
 * ```ts
 * const guard = new TelemetryIngestionGuard({ bucketCapacity: 200 });
 *
 * // At the ingestion boundary:
 * const result = guard.ingest(event);
 * if (result.outcome === "ACCEPTED") {
 *   const batch = guard.drain(50);
 *   processBatch(batch);
 * }
 * ```
 *
 * SAFETY NOTE: This module is observational only.  It has no mechanism to
 * interact with on-chain operations and does not import any chain SDK.
 */
export class TelemetryIngestionGuard {
  private readonly bucket: TokenBucket;
  private readonly queue: TelemetryEvent[];
  private readonly maxQueueDepth: number;
  private readonly sourceName: string;

  // Monotonic counters — exposed for metrics / testing
  private _totalAccepted = 0;
  private _totalRateLimited = 0;
  private _totalDropped = 0;
  private _totalMalformed = 0;

  constructor(options: TelemetryIngestionGuardOptions = {}) {
    const capacity = options.bucketCapacity ?? 100;
    const refillRate = options.refillRatePerSecond ?? 50;
    const nowFn = options._nowFn ?? (() => Date.now());

    this.bucket = new TokenBucket(capacity, refillRate, nowFn);
    this.maxQueueDepth = options.maxQueueDepth ?? 500;
    this.sourceName = options.sourceName ?? "telemetry";
    this.queue = [];
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Attempt to ingest a single telemetry event.
   *
   * Never throws — all errors are captured in the returned IngestionResult.
   */
  ingest(event: unknown): IngestionResult {
    // 1. Structural validation
    const validationError = validateEvent(event);
    if (validationError !== null) {
      this._totalMalformed += 1;
      const result: IngestionResult = {
        outcome: "MALFORMED",
        queueDepth: this.queue.length,
        tokensRemaining: Math.floor(this.bucket.available),
        validationError,
      };
      console.error(
        `[TelemetryIngestionGuard][${this.sourceName}] MALFORMED event rejected — ${validationError}`
      );
      return result;
    }

    const validated = event as TelemetryEvent;

    // 2. Rate limiting
    if (!this.bucket.tryConsume()) {
      this._totalRateLimited += 1;
      const result: IngestionResult = {
        outcome: "RATE_LIMITED",
        queueDepth: this.queue.length,
        tokensRemaining: 0,
      };
      console.warn(
        `[TelemetryIngestionGuard][${this.sourceName}] RATE_LIMITED — event id=${validated.id} dropped at ingestion boundary. ` +
          `queue=${this.queue.length}/${this.maxQueueDepth}`
      );
      return result;
    }

    // 3. Backpressure / bounded queue
    let droppedEventId: string | undefined;
    if (this.queue.length >= this.maxQueueDepth) {
      const dropped = this.queue.shift(); // drop-oldest
      droppedEventId = dropped?.id;
      this._totalDropped += 1;
      console.warn(
        `[TelemetryIngestionGuard][${this.sourceName}] QUEUE_FULL — dropped oldest event id=${droppedEventId} ` +
          `to make room. queue depth was ${this.maxQueueDepth}.`
      );
    }

    this.queue.push(validated);
    this._totalAccepted += 1;

    const outcome: IngestionOutcome =
      droppedEventId !== undefined ? "QUEUE_FULL_DROP" : "ACCEPTED";

    return {
      outcome,
      queueDepth: this.queue.length,
      tokensRemaining: Math.floor(this.bucket.available),
      droppedEventId,
    };
  }

  /**
   * Ingest a batch of raw events.  Each event is validated individually.
   * Returns one IngestionResult per input item in the same order.
   */
  ingestBatch(events: unknown[]): IngestionResult[] {
    if (!Array.isArray(events)) {
      // Treat malformed batch as a single malformed event for alerting
      console.error(
        `[TelemetryIngestionGuard][${this.sourceName}] MALFORMED batch — expected an array`
      );
      return [];
    }
    return events.map((e) => this.ingest(e));
  }

  /**
   * Remove and return up to `count` events from the front of the queue for
   * downstream processing.
   */
  drain(count: number = this.maxQueueDepth): TelemetryEvent[] {
    const actualCount = Math.min(count, this.queue.length);
    return this.queue.splice(0, actualCount);
  }

  // -------------------------------------------------------------------------
  // Observability
  // -------------------------------------------------------------------------

  /** Current queue depth. */
  get queueDepth(): number {
    return this.queue.length;
  }

  /** Current token count (approximate — may include unrefilled tokens). */
  get tokensAvailable(): number {
    return Math.floor(this.bucket.available);
  }

  /** Snapshot of lifetime counters — useful for dashboards / alerts. */
  getMetrics(): {
    totalAccepted: number;
    totalRateLimited: number;
    totalDropped: number;
    totalMalformed: number;
    queueDepth: number;
    tokensAvailable: number;
  } {
    return {
      totalAccepted: this._totalAccepted,
      totalRateLimited: this._totalRateLimited,
      totalDropped: this._totalDropped,
      totalMalformed: this._totalMalformed,
      queueDepth: this.queue.length,
      tokensAvailable: Math.floor(this.bucket.available),
    };
  }

  /**
   * Emit a structured status log line — call this periodically to surface
   * rate-limit pressure as an observable signal rather than a silent counter.
   */
  logStatus(): void {
    const m = this.getMetrics();
    if (m.totalRateLimited > 0 || m.totalDropped > 0) {
      console.warn(
        `[TelemetryIngestionGuard][${this.sourceName}] STATUS — ` +
          `accepted=${m.totalAccepted} rate_limited=${m.totalRateLimited} ` +
          `dropped=${m.totalDropped} malformed=${m.totalMalformed} ` +
          `queue=${m.queueDepth}/${this.maxQueueDepth} tokens=${m.tokensAvailable}`
      );
    } else {
      console.log(
        `[TelemetryIngestionGuard][${this.sourceName}] STATUS — ` +
          `accepted=${m.totalAccepted} queue=${m.queueDepth}/${this.maxQueueDepth} tokens=${m.tokensAvailable}`
      );
    }
  }

  /**
   * Reset all internal state — for testing only.
   * @internal
   */
  _reset(): void {
    this.queue.length = 0;
    this.bucket.reset();
    this._totalAccepted = 0;
    this._totalRateLimited = 0;
    this._totalDropped = 0;
    this._totalMalformed = 0;
  }
}

// ---------------------------------------------------------------------------
// Default singleton — suitable for the anomaly-detector polling loop
// ---------------------------------------------------------------------------

/**
 * Module-level singleton with environment-driven configuration.
 *
 * Configure via env vars:
 *   TELEMETRY_BUCKET_CAPACITY       — integer, default 100
 *   TELEMETRY_REFILL_RATE_PER_SEC   — integer, default 50
 *   TELEMETRY_MAX_QUEUE_DEPTH       — integer, default 500
 */
export const defaultIngestionGuard = new TelemetryIngestionGuard({
  bucketCapacity: Number(process.env["TELEMETRY_BUCKET_CAPACITY"] ?? 100),
  refillRatePerSecond: Number(process.env["TELEMETRY_REFILL_RATE_PER_SEC"] ?? 50),
  maxQueueDepth: Number(process.env["TELEMETRY_MAX_QUEUE_DEPTH"] ?? 500),
  sourceName: "default",
});

export default TelemetryIngestionGuard;
