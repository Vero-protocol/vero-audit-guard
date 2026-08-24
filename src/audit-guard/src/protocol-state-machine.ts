/**
 * Internal Protocol-Invariant State Machine
 *
 * Issue #172 / VAG-004: Canonical in-memory representation of scanner-engine
 * protocol state, providing a baseline against which invalid transitions from
 * scanner-engine can be detected and surfaced as telemetry alerts.
 *
 * Design constraints
 * ------------------
 * • STRICTLY OBSERVATIONAL — this module has NO on-chain halt authority.
 *   It only observes, validates, and reports. Any consumer that wishes to act
 *   on an invalid transition must do so independently.
 * • Error propagation follows the TypeScript equivalent of the 'thiserror'
 *   pattern: a discriminated union of typed custom Error subclasses surfaces
 *   all failure modes explicitly rather than as silent drops or bare panics.
 * • ZK-readiness: state transitions produce a deterministic, hash-verifiable
 *   snapshot that a future ZK-proving layer could consume.
 * • Memory-safe: no unbounded data structures; history is capped at a
 *   configurable limit.
 */

// ---------------------------------------------------------------------------
// Protocol states
// ---------------------------------------------------------------------------

/**
 * The set of valid states the scanner-engine protocol can be in.
 *
 *   IDLE ──► SCANNING ──► REPORTING ──► DONE
 *                │                        │
 *                └──────────────────►  FAILED
 *
 * IDLE     – No scan in progress. Waiting for a trigger.
 * SCANNING – A scan is actively running against a target.
 * REPORTING– Scan complete; writing/uploading the report.
 * DONE     – Terminal success: report delivered and archived.
 * FAILED   – Terminal failure: scan or reporting encountered an unrecoverable error.
 */
export type ProtocolState = "IDLE" | "SCANNING" | "REPORTING" | "DONE" | "FAILED";

// ---------------------------------------------------------------------------
// Protocol events (triggers)
// ---------------------------------------------------------------------------

/**
 * Events that drive state transitions.  Each event is a typed discriminated
 * union member so callers can never accidentally pass the wrong shape.
 */
export type ProtocolEvent =
  | { type: "SCAN_STARTED";   scanId: string; target: string;  timestamp: number }
  | { type: "SCAN_COMPLETED"; scanId: string; findingCount: number; timestamp: number }
  | { type: "SCAN_FAILED";    scanId: string; reason: string;  timestamp: number }
  | { type: "REPORT_STARTED"; scanId: string; timestamp: number }
  | { type: "REPORT_DELIVERED"; scanId: string; reportHash: string; timestamp: number }
  | { type: "REPORT_FAILED";  scanId: string; reason: string;  timestamp: number }
  | { type: "RESET";          requestedBy: string; timestamp: number };

// ---------------------------------------------------------------------------
// Typed error hierarchy  (mirrors Rust's `thiserror` crate)
// ---------------------------------------------------------------------------

/** Base for all state-machine errors. Never instantiated directly. */
export abstract class StateMachineError extends Error {
  abstract readonly code: string;

  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = this.constructor.name;
    // Maintain correct prototype chain across TS → JS transpilation
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * An event was received that is not valid from the current state.
 * This is the primary signal that the protocol invariant has been violated.
 */
export class InvalidTransitionError extends StateMachineError {
  readonly code = "INVALID_TRANSITION" as const;

  constructor(
    public readonly fromState: ProtocolState,
    public readonly event: ProtocolEvent["type"],
    public readonly reason?: string
  ) {
    super(
      `Invalid protocol transition: cannot apply event "${event}" from state "${fromState}"` +
        (reason ? ` — ${reason}` : "")
    );
  }
}

/** An event arrived with a scanId that does not match the active session. */
export class ScanIdMismatchError extends StateMachineError {
  readonly code = "SCAN_ID_MISMATCH" as const;

  constructor(
    public readonly expected: string,
    public readonly received: string
  ) {
    super(
      `Scan-ID mismatch: expected "${expected}", received "${received}" — possible replay or race condition`
    );
  }
}

/** An event's timestamp is outside the acceptable clock-skew window. */
export class TimestampViolationError extends StateMachineError {
  readonly code = "TIMESTAMP_VIOLATION" as const;

  constructor(
    public readonly eventTimestamp: number,
    public readonly machineTimestamp: number,
    public readonly windowMs: number
  ) {
    const delta = eventTimestamp - machineTimestamp;
    super(
      `Event timestamp out of allowed window (±${windowMs}ms): ` +
        `event=${new Date(eventTimestamp).toISOString()}, ` +
        `machine=${new Date(machineTimestamp).toISOString()}, ` +
        `delta=${delta}ms`
    );
  }
}

/** The state machine has been shut down and will not accept further events. */
export class StateMachineShutdownError extends StateMachineError {
  readonly code = "STATE_MACHINE_SHUTDOWN" as const;

  constructor() {
    super("Protocol state machine has been shut down — no further events accepted");
  }
}

/** Internal invariant check failed (should never happen in correct code). */
export class InvariantViolationError extends StateMachineError {
  readonly code = "INVARIANT_VIOLATION" as const;

  constructor(public readonly detail: string) {
    super(`Internal invariant violated: ${detail}`);
  }
}

/** Union of every possible state-machine error (for exhaustive handling). */
export type StateMachineErrorUnion =
  | InvalidTransitionError
  | ScanIdMismatchError
  | TimestampViolationError
  | StateMachineShutdownError
  | InvariantViolationError;

// ---------------------------------------------------------------------------
// Transition table
// ---------------------------------------------------------------------------

/**
 * Allowed (fromState, eventType) → toState mappings.
 * Any combination not listed here is an INVALID_TRANSITION.
 */
const TRANSITIONS: ReadonlyMap<
  ProtocolState,
  ReadonlyMap<ProtocolEvent["type"], ProtocolState>
> = new Map([
  [
    "IDLE",
    new Map<ProtocolEvent["type"], ProtocolState>([
      ["SCAN_STARTED", "SCANNING"],
    ]),
  ],
  [
    "SCANNING",
    new Map<ProtocolEvent["type"], ProtocolState>([
      ["SCAN_COMPLETED", "REPORTING"],
      ["SCAN_FAILED",    "FAILED"],
    ]),
  ],
  [
    "REPORTING",
    new Map<ProtocolEvent["type"], ProtocolState>([
      ["REPORT_STARTED",   "REPORTING"], // idempotent: already in REPORTING
      ["REPORT_DELIVERED", "DONE"],
      ["REPORT_FAILED",    "FAILED"],
    ]),
  ],
  // DONE and FAILED are terminal — only RESET is accepted (handled separately)
]);

// ---------------------------------------------------------------------------
// History snapshot
// ---------------------------------------------------------------------------

/** An immutable record of one transition for the audit trail. */
export interface TransitionRecord {
  readonly seq: number;
  readonly fromState: ProtocolState;
  readonly toState: ProtocolState;
  readonly event: ProtocolEvent;
  readonly timestamp: number;
  /** SHA-256 hex digest of the prior snapshot + this event (ZK-compatible chain). */
  readonly snapshotHash: string;
}

// ---------------------------------------------------------------------------
// Current machine state snapshot
// ---------------------------------------------------------------------------

export interface StateMachineSnapshot {
  readonly state: ProtocolState;
  readonly activeScanId: string | null;
  readonly lastEventTimestamp: number | null;
  readonly transitionCount: number;
  readonly snapshotHash: string;
}

// ---------------------------------------------------------------------------
// Observer / telemetry callback
// ---------------------------------------------------------------------------

export type TransitionObserver = (
  record: TransitionRecord,
  error: StateMachineErrorUnion | null
) => void;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface ProtocolStateMachineOptions {
  /**
   * Maximum number of transition records retained in memory.
   * Older entries are evicted (FIFO) once the limit is reached.
   * Default: 1_000
   */
  maxHistoryDepth?: number;
  /**
   * Maximum allowed clock-skew between an event's timestamp and the
   * machine's `Date.now()` in milliseconds.  0 = disabled.
   * Default: 300_000 (5 minutes)
   */
  maxClockSkewMs?: number;
  /**
   * Override `Date.now` for deterministic testing.
   * @internal
   */
  nowFn?: () => number;
  /**
   * Observers receive every transition (valid and invalid) with the error
   * instance (null on valid transitions).  Used for telemetry/alerting.
   */
  observers?: TransitionObserver[];
}

// ---------------------------------------------------------------------------
// Deterministic hash helper (no Node crypto required, pure JS for portability)
// ---------------------------------------------------------------------------

/**
 * FNV-1a 64-bit approximated using two 32-bit halves — deterministic,
 * fast, and suitable as a ZK-compatible snapshot chaining hash in test/dev.
 *
 * For production use this should be replaced by node:crypto SHA-256, but
 * we keep the dependency surface minimal to stay portable.
 */
function computeSnapshotHash(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0xc4ceb9fe;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c, 0x01000193) >>> 0;
  }
  return (
    h1.toString(16).padStart(8, "0") +
    h2.toString(16).padStart(8, "0")
  );
}

// ---------------------------------------------------------------------------
// Main state machine class
// ---------------------------------------------------------------------------

/**
 * `ProtocolStateMachine` maintains the canonical in-memory representation of
 * the scanner-engine protocol state.  It is observational-only: it records
 * and reports invalid transitions but does NOT halt or modify the scanner.
 *
 * @example
 * ```ts
 * const sm = new ProtocolStateMachine({ observers: [myTelemetryLogger] });
 * sm.apply({ type: "SCAN_STARTED", scanId: "s1", target: "/path", timestamp: Date.now() });
 * sm.apply({ type: "SCAN_COMPLETED", scanId: "s1", findingCount: 3, timestamp: Date.now() });
 * ```
 */
export class ProtocolStateMachine {
  private _state: ProtocolState = "IDLE";
  private _activeScanId: string | null = null;
  private _lastEventTimestamp: number | null = null;
  private _transitionCount = 0;
  private _snapshotHash = computeSnapshotHash("IDLE:0");
  private _history: TransitionRecord[] = [];
  private _shutdown = false;

  private readonly maxHistoryDepth: number;
  private readonly maxClockSkewMs: number;
  private readonly nowFn: () => number;
  private readonly observers: TransitionObserver[];

  constructor(options: ProtocolStateMachineOptions = {}) {
    this.maxHistoryDepth = options.maxHistoryDepth ?? 1_000;
    this.maxClockSkewMs  = options.maxClockSkewMs  ?? 300_000;
    this.nowFn           = options.nowFn           ?? (() => Date.now());
    this.observers       = options.observers       ?? [];
  }

  // -------------------------------------------------------------------------
  // Public read accessors
  // -------------------------------------------------------------------------

  /** The current protocol state. */
  get state(): ProtocolState {
    return this._state;
  }

  /** The scanId of the currently active scan, or null when IDLE/DONE/FAILED. */
  get activeScanId(): string | null {
    return this._activeScanId;
  }

  /** Total number of valid transitions applied so far. */
  get transitionCount(): number {
    return this._transitionCount;
  }

  /** Immutable copy of the transition history (newest last). */
  get history(): ReadonlyArray<TransitionRecord> {
    return [...this._history];
  }

  /** Point-in-time snapshot — safe to hand off to a ZK circuit. */
  snapshot(): StateMachineSnapshot {
    return {
      state:                this._state,
      activeScanId:         this._activeScanId,
      lastEventTimestamp:   this._lastEventTimestamp,
      transitionCount:      this._transitionCount,
      snapshotHash:         this._snapshotHash,
    };
  }

  // -------------------------------------------------------------------------
  // Core transition logic
  // -------------------------------------------------------------------------

  /**
   * Apply a protocol event to the machine.
   *
   * On a **valid** transition the internal state is updated, a
   * `TransitionRecord` is appended to history, and all observers are called
   * with `error = null`.
   *
   * On an **invalid** transition the internal state is NOT modified, but all
   * observers are still called with the typed error instance so that
   * telemetry/alerting layers surface the anomaly.  The error is then
   * rethrown so the caller can decide how to handle it.
   *
   * @throws {StateMachineShutdownError}   if the machine has been shut down
   * @throws {TimestampViolationError}     if the event timestamp is too skewed
   * @throws {ScanIdMismatchError}         if the scanId doesn't match active session
   * @throws {InvalidTransitionError}      if the event is not legal in current state
   */
  apply(event: ProtocolEvent): TransitionRecord {
    if (this._shutdown) {
      const err = new StateMachineShutdownError();
      this._notifyObservers(null, event, err);
      throw err;
    }

    // ------ 1. Clock-skew guard -----------------------------------------------
    if (this.maxClockSkewMs > 0 && "timestamp" in event) {
      const now = this.nowFn();
      const skew = Math.abs(event.timestamp - now);
      if (skew > this.maxClockSkewMs) {
        const err = new TimestampViolationError(event.timestamp, now, this.maxClockSkewMs);
        this._notifyObservers(null, event, err);
        throw err;
      }
    }

    // ------ 2. RESET is handled specially (allowed from any state) ------------
    if (event.type === "RESET") {
      return this._applyReset(event as Extract<ProtocolEvent, { type: "RESET" }>);
    }

    // ------ 3. ScanId coherence check -----------------------------------------
    if ("scanId" in event && event.type !== "SCAN_STARTED") {
      // For non-SCAN_STARTED events that carry a scanId, it must match the active session
      if (this._activeScanId !== null && (event as { scanId: string }).scanId !== this._activeScanId) {
        const err = new ScanIdMismatchError(
          this._activeScanId,
          (event as { scanId: string }).scanId
        );
        this._notifyObservers(null, event, err);
        throw err;
      }
    }

    // ------ 4. Transition table lookup ----------------------------------------
    const stateTransitions = TRANSITIONS.get(this._state);
    const toState = stateTransitions?.get(event.type);

    if (toState === undefined) {
      const err = new InvalidTransitionError(
        this._state,
        event.type,
        `no transition defined from "${this._state}" on "${event.type}"`
      );
      this._notifyObservers(null, event, err);
      throw err;
    }

    // ------ 5. Commit the transition ------------------------------------------
    return this._commit(toState, event);
  }

  /**
   * Apply an event without throwing on invalid transitions.
   *
   * Returns `{ record, error }` where `error` is null on success.
   * Observers are still called in all cases.
   *
   * This is the preferred API for fire-and-forget telemetry pipelines.
   */
  tryApply(event: ProtocolEvent): { record: TransitionRecord | null; error: StateMachineErrorUnion | null } {
    try {
      const record = this.apply(event);
      return { record, error: null };
    } catch (e) {
      if (
        e instanceof InvalidTransitionError ||
        e instanceof ScanIdMismatchError    ||
        e instanceof TimestampViolationError ||
        e instanceof StateMachineShutdownError ||
        e instanceof InvariantViolationError
      ) {
        return { record: null, error: e };
      }
      // Unexpected — re-throw to surface programming errors
      throw e;
    }
  }

  /**
   * Shut down the state machine.  After this call, `apply()` and `tryApply()`
   * will return / throw `StateMachineShutdownError`.
   */
  shutdown(): void {
    this._shutdown = true;
    console.log("[ProtocolStateMachine] Shut down. Final state:", this._state);
  }

  /** Whether the machine has been shut down. */
  get isShutdown(): boolean {
    return this._shutdown;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private _applyReset(event: Extract<ProtocolEvent, { type: "RESET" }>): TransitionRecord {
    const from = this._state;
    const record = this._commit("IDLE", event);
    this._activeScanId = null;
    console.log(
      `[ProtocolStateMachine] RESET by "${event.requestedBy}" from state "${from}"`
    );
    return record;
  }

  private _commit(toState: ProtocolState, event: ProtocolEvent): TransitionRecord {
    const from = this._state;
    const seq  = ++this._transitionCount;
    const ts   = "timestamp" in event ? (event as { timestamp: number }).timestamp : this.nowFn();

    const hashInput = `${this._snapshotHash}:${from}:${toState}:${event.type}:${seq}:${JSON.stringify(event)}`;
    const snapshotHash = computeSnapshotHash(hashInput);

    const record: TransitionRecord = {
      seq,
      fromState:     from,
      toState,
      event,
      timestamp:     ts,
      snapshotHash,
    };

    // Update machine state
    this._state = toState;
    this._snapshotHash = snapshotHash;
    this._lastEventTimestamp = ts;

    // Track active scan session
    if (event.type === "SCAN_STARTED") {
      this._activeScanId = (event as Extract<ProtocolEvent, { type: "SCAN_STARTED" }>).scanId;
    } else if (toState === "IDLE") {
      this._activeScanId = null;
    }

    // Append to history (evict oldest if cap exceeded)
    this._history.push(record);
    if (this._history.length > this.maxHistoryDepth) {
      this._history.shift();
    }

    this._notifyObservers(record, event, null);
    this._logTransition(record);

    return record;
  }

  private _notifyObservers(
    record: TransitionRecord | null,
    event: ProtocolEvent,
    error: StateMachineErrorUnion | null
  ): void {
    for (const obs of this.observers) {
      try {
        // If record is null (pre-commit error), synthesise a partial record so
        // observers always receive something meaningful
        const r: TransitionRecord = record ?? {
          seq:          this._transitionCount,
          fromState:    this._state,
          toState:      this._state, // no change
          event,
          timestamp:    "timestamp" in event ? (event as { timestamp: number }).timestamp : this.nowFn(),
          snapshotHash: this._snapshotHash,
        };
        obs(r, error);
      } catch (obsErr) {
        // Observer errors must never crash the state machine
        console.error("[ProtocolStateMachine] Observer threw an error:", obsErr);
      }
    }
  }

  private _logTransition(record: TransitionRecord): void {
    const prefix = "[ProtocolStateMachine]";
    const { seq, fromState, toState, event } = record;
    console.log(
      `${prefix} [seq=${seq}] ${fromState} → ${toState} (event="${event.type}"` +
        ("scanId" in event ? `, scanId="${(event as { scanId: string }).scanId}"` : "") +
        `)`
    );
  }
}

// ---------------------------------------------------------------------------
// Telemetry alert builder
// ---------------------------------------------------------------------------

/**
 * Builds a human-readable alert payload from a state-machine error.
 * Designed to plug into the existing `DashboardClient.sendAlert()` interface.
 */
export interface StateMachineAlertPayload {
  source: "protocol-state-machine";
  type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  detail: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export function buildStateMachineAlert(
  error: StateMachineErrorUnion,
  context?: Record<string, unknown>
): StateMachineAlertPayload {
  const severityMap: Record<string, StateMachineAlertPayload["severity"]> = {
    INVALID_TRANSITION:     "HIGH",
    SCAN_ID_MISMATCH:       "CRITICAL",
    TIMESTAMP_VIOLATION:    "HIGH",
    STATE_MACHINE_SHUTDOWN: "MEDIUM",
    INVARIANT_VIOLATION:    "CRITICAL",
  };

  const severity = severityMap[error.code] ?? "HIGH";

  return {
    source:    "protocol-state-machine",
    type:      error.code,
    severity,
    message:   `⚠️  Protocol state machine anomaly: [${error.code}] ${error.message}`,
    detail:    error.message,
    timestamp: new Date().toISOString(),
    metadata:  {
      errorName: error.name,
      ...context,
    },
  };
}

// ---------------------------------------------------------------------------
// Console-alert observer (drop-in for telemetry wiring)
// ---------------------------------------------------------------------------

/**
 * A ready-made `TransitionObserver` that logs invalid transitions as ALERT
 * lines to the console.  Wire it in via `options.observers`.
 *
 * Replace or augment with a `DashboardClient.sendAlert()` call in production.
 */
export function createConsoleAlertObserver(prefix = "[VAG-004]"): TransitionObserver {
  return (record, error) => {
    if (error === null) {
      // Valid transition — debug-level only
      return;
    }

    const alert = buildStateMachineAlert(error, {
      seq:       record.seq,
      fromState: record.fromState,
      toState:   record.toState,
      eventType: record.event.type,
    });

    console.error(
      `${prefix} ALERT [${alert.severity}] ${alert.type}: ${alert.message}`
    );
  };
}

export default ProtocolStateMachine;
