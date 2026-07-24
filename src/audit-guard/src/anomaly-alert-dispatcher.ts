/**
 * Anomaly Alert Dispatcher — Dashboard Channel
 *
 * Issue VAG-009: Non-blocking dispatch path from the anomaly-detector to the
 * Guardian Dashboard. This module bridges AnomalyAlert events (from the
 * anomaly-detector) to the DashboardClient without any on-chain halt authority
 * (observational-only invariant).
 *
 * Error propagation follows the TypeScript equivalent of the 'thiserror' pattern:
 * a discriminated union of typed custom Error subclasses surfaces all failure
 * modes explicitly rather than as silent drops or bare panics.
 */

import DashboardClient, { DashboardAlert } from "./dashboard-client";

// ---------------------------------------------------------------------------
// Typed error hierarchy (analogous to Rust's `thiserror` crate)
// ---------------------------------------------------------------------------

/** Base class for all dispatcher errors — never thrown directly. */
export abstract class DispatcherError extends Error {
  abstract readonly code: string;

  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = this.constructor.name;
    // Maintain proper prototype chain in transpiled JS
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** The upstream dashboard endpoint rejected or could not be reached. */
export class DashboardDeliveryError extends DispatcherError {
  readonly code = "DASHBOARD_DELIVERY_FAILED" as const;

  constructor(
    public readonly alertType: string,
    public readonly httpStatus?: number,
    cause?: unknown
  ) {
    const statusStr = httpStatus !== undefined ? ` (HTTP ${httpStatus})` : "";
    super(
      `Dashboard delivery failed for alert type "${alertType}"${statusStr}`,
      cause
    );
  }
}

/** The incoming alert payload failed schema/type validation. */
export class AlertValidationError extends DispatcherError {
  readonly code = "ALERT_VALIDATION_FAILED" as const;

  constructor(
    public readonly field: string,
    public readonly received: unknown
  ) {
    super(
      `Invalid alert payload: field "${field}" has unexpected value: ${JSON.stringify(received)}`
    );
  }
}

/** The dispatcher has been shut down and cannot accept new alerts. */
export class DispatcherShutdownError extends DispatcherError {
  readonly code = "DISPATCHER_SHUTDOWN" as const;

  constructor() {
    super("Dispatcher has been shut down — no further alerts will be accepted");
  }
}

/** Dispatch timed out waiting for the dashboard to acknowledge. */
export class DispatchTimeoutError extends DispatcherError {
  readonly code = "DISPATCH_TIMEOUT" as const;

  constructor(public readonly timeoutMs: number, alertType: string) {
    super(
      `Dispatch timed out after ${timeoutMs}ms for alert type "${alertType}"`
    );
  }
}

// Discriminated union for callers that want exhaustive error handling
export type DispatchError =
  | DashboardDeliveryError
  | AlertValidationError
  | DispatcherShutdownError
  | DispatchTimeoutError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Severity levels understood by the dispatcher. */
export type AlertSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Canonical alert shape consumed by the dispatcher. */
export interface AnomalyAlertInput {
  /** Originating monitor type — free-form string for forward compatibility. */
  type: string;
  severity: AlertSeverity;
  /** Human-readable summary shown in the dashboard feed. */
  message: string;
  /** Full contextual detail — address, delta, raw metric, etc. */
  detail: string;
  /** Arbitrary structured metadata (observational only; no on-chain effect). */
  metadata?: Record<string, unknown>;
  /** ISO 8601 timestamp; defaults to Date.now() if omitted. */
  timestamp?: string;
}

/** Result of a single dispatch attempt. */
export interface DispatchResult {
  /** true when the dashboard acknowledged the alert. */
  delivered: boolean;
  /** ISO 8601 dispatch timestamp. */
  dispatchedAt: string;
  /** Typed error description if delivery failed. */
  error?: DispatchError;
}

/** Dispatcher configuration. */
export interface AnomalyAlertDispatcherConfig {
  /** Dashboard endpoint URL. If absent, alerts are logged but not delivered. */
  dashboardUrl?: string;
  /** Bearer token for dashboard authentication. */
  dashboardToken?: string;
  /**
   * When true (default), a delivery failure surfaces as a telemetry log entry
   * rather than throwing, so the calling monitor loop is never interrupted.
   */
  nonBlocking?: boolean;
  /**
   * Optional override for the DashboardClient (enables injection in tests).
   */
  client?: DashboardClient;
}

// ---------------------------------------------------------------------------
// Internal telemetry logger
// ---------------------------------------------------------------------------

/** Minimal structured logger that annotates every entry with a module tag. */
interface TelemetryLogger {
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

function buildLogger(tag: string): TelemetryLogger {
  const fmt = (
    level: string,
    msg: string,
    meta?: Record<string, unknown>
  ): string => {
    const base = `[${tag}][${level.toUpperCase()}] ${msg}`;
    return meta && Object.keys(meta).length > 0
      ? `${base} ${JSON.stringify(meta)}`
      : base;
  };

  return {
    info: (msg, meta) => console.log(fmt("info", msg, meta)),
    warn: (msg, meta) => console.warn(fmt("warn", msg, meta)),
    error: (msg, meta) => console.error(fmt("error", msg, meta)),
  };
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const VALID_SEVERITIES: ReadonlySet<string> = new Set<AlertSeverity>([
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]);

/**
 * Validates an incoming alert payload.
 * @throws {AlertValidationError} on the first validation failure found.
 */
function validateAlert(input: AnomalyAlertInput): void {
  if (
    typeof input.type !== "string" ||
    input.type.trim().length === 0
  ) {
    throw new AlertValidationError("type", input.type);
  }

  if (!VALID_SEVERITIES.has(input.severity)) {
    throw new AlertValidationError("severity", input.severity);
  }

  if (
    typeof input.message !== "string" ||
    input.message.trim().length === 0
  ) {
    throw new AlertValidationError("message", input.message);
  }

  if (
    typeof input.detail !== "string" ||
    input.detail.trim().length === 0
  ) {
    throw new AlertValidationError("detail", input.detail);
  }

  if (
    input.timestamp !== undefined &&
    isNaN(Date.parse(input.timestamp))
  ) {
    throw new AlertValidationError("timestamp", input.timestamp);
  }

  if (
    input.metadata !== undefined &&
    (typeof input.metadata !== "object" ||
      Array.isArray(input.metadata) ||
      input.metadata === null)
  ) {
    throw new AlertValidationError("metadata", input.metadata);
  }
}

// ---------------------------------------------------------------------------
// AnomalyAlertDispatcher
// ---------------------------------------------------------------------------

/**
 * Non-blocking dispatcher that translates an AnomalyAlertInput into a
 * DashboardAlert and forwards it to the Guardian Dashboard.
 *
 * Observational-only invariant: this class never triggers on-chain actions.
 */
export class AnomalyAlertDispatcher {
  private readonly client: DashboardClient | null;
  private readonly nonBlocking: boolean;
  private readonly log: TelemetryLogger;
  private _shutdown = false;

  /** Running count of successfully delivered alerts — exposed for telemetry. */
  private _deliveredCount = 0;
  /** Running count of failed delivery attempts. */
  private _failedCount = 0;

  constructor(config: AnomalyAlertDispatcherConfig = {}) {
    const {
      dashboardUrl = process.env.DASHBOARD_URL ?? "",
      dashboardToken = process.env.DASHBOARD_TOKEN ?? "",
      nonBlocking = true,
      client,
    } = config;

    this.log = buildLogger("AnomalyAlertDispatcher");
    this.nonBlocking = nonBlocking;

    if (client) {
      this.client = client;
    } else if (dashboardUrl) {
      this.client = new DashboardClient(dashboardUrl, dashboardToken);
    } else {
      this.client = null;
      this.log.warn(
        "No DASHBOARD_URL configured — alerts will be logged locally only"
      );
    }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Dispatches an anomaly alert to the dashboard channel.
   *
   * - Validates the input payload (throws AlertValidationError on bad data).
   * - Maps the payload to a DashboardAlert and calls DashboardClient.sendAlert.
   * - In non-blocking mode (default) delivery failures are logged as telemetry
   *   warnings; in blocking mode they surface as DispatchError instances.
   *
   * @returns DispatchResult — callers can inspect `delivered` and `error`.
   * @throws DispatcherShutdownError  if the dispatcher has been shut down.
   * @throws AlertValidationError     if the input payload is invalid.
   * @throws DashboardDeliveryError   if nonBlocking=false and delivery fails.
   */
  async dispatch(input: AnomalyAlertInput): Promise<DispatchResult> {
    if (this._shutdown) {
      const err = new DispatcherShutdownError();
      this.log.error(err.message);
      throw err;
    }

    // Validate before any I/O (throws AlertValidationError on failure)
    try {
      validateAlert(input);
    } catch (err) {
      if (err instanceof AlertValidationError) {
        this.log.error("Alert validation failed", {
          field: err.field,
          received: err.received,
        });
        this._failedCount++;
        // Validation errors always propagate regardless of nonBlocking setting
        throw err;
      }
      throw err;
    }

    const timestamp = input.timestamp ?? new Date().toISOString();
    const dispatchedAt = new Date().toISOString();

    const dashboardAlert: DashboardAlert = {
      source: "anomaly-detector",
      type: input.type,
      severity: input.severity,
      message: input.message,
      detail: input.detail,
      timestamp,
      metadata: (input.metadata as Record<string, unknown>) ?? {},
    };

    // No client configured — log and return without delivery
    if (!this.client) {
      this.log.warn("No dashboard client available — alert not delivered", {
        type: input.type,
        severity: input.severity,
      });
      this._failedCount++;
      return { delivered: false, dispatchedAt };
    }

    this.log.info("Dispatching anomaly alert to dashboard", {
      type: input.type,
      severity: input.severity,
      timestamp,
    });

    let delivered = false;
    let dispatchError: DispatchError | undefined;

    try {
      delivered = await this.client.sendAlert(dashboardAlert);

      if (delivered) {
        this._deliveredCount++;
        this.log.info("Alert delivered successfully", { type: input.type });
      } else {
        this._failedCount++;
        dispatchError = new DashboardDeliveryError(input.type);

        const logMeta = {
          type: input.type,
          severity: input.severity,
          error: dispatchError.code,
        };

        if (this.nonBlocking) {
          // Non-blocking: surface as a telemetry warning, do not throw
          this.log.warn(
            "Dashboard delivery returned false — alert not confirmed",
            logMeta
          );
        } else {
          this.log.error("Dashboard delivery failed", logMeta);
          throw dispatchError;
        }
      }
    } catch (err) {
      if (err instanceof DispatcherError) {
        throw err; // Re-throw typed dispatcher errors
      }

      this._failedCount++;
      const wrappedErr = new DashboardDeliveryError(input.type, undefined, err);
      dispatchError = wrappedErr;

      const logMeta = {
        type: input.type,
        severity: input.severity,
        cause: err instanceof Error ? err.message : String(err),
        error: wrappedErr.code,
      };

      if (this.nonBlocking) {
        // Non-blocking: emit as error-level telemetry alert, do not throw
        this.log.error(
          "Unhandled error during dashboard dispatch — alert dropped",
          logMeta
        );
      } else {
        this.log.error("Dashboard dispatch threw an error", logMeta);
        throw wrappedErr;
      }
    }

    return { delivered, dispatchedAt, error: dispatchError };
  }

  /**
   * Dispatches multiple alerts in sequence; individual failures do not abort
   * the remaining items. Returns one DispatchResult per input alert.
   */
  async dispatchBatch(
    inputs: AnomalyAlertInput[]
  ): Promise<DispatchResult[]> {
    if (this._shutdown) {
      throw new DispatcherShutdownError();
    }

    if (!Array.isArray(inputs)) {
      const err = new AlertValidationError("inputs", inputs);
      this.log.error("dispatchBatch called with non-array argument");
      throw err;
    }

    this.log.info(`Dispatching batch of ${inputs.length} alert(s)`);

    const results: DispatchResult[] = [];

    for (const input of inputs) {
      try {
        const result = await this.dispatch(input);
        results.push(result);
      } catch (err) {
        // Capture per-item errors without aborting the batch
        const dispatchedAt = new Date().toISOString();
        if (err instanceof DispatcherError) {
          results.push({ delivered: false, dispatchedAt, error: err as DispatchError });
        } else {
          const wrapped = new DashboardDeliveryError(
            typeof input?.type === "string" ? input.type : "UNKNOWN",
            undefined,
            err
          );
          results.push({ delivered: false, dispatchedAt, error: wrapped });
        }
      }
    }

    const delivered = results.filter((r) => r.delivered).length;
    this.log.info(`Batch complete: ${delivered}/${results.length} delivered`);

    return results;
  }

  /**
   * Gracefully shuts down the dispatcher. After shutdown, `dispatch()` and
   * `dispatchBatch()` will throw DispatcherShutdownError.
   */
  shutdown(): void {
    this._shutdown = true;
    this.log.info("Dispatcher shut down", {
      totalDelivered: this._deliveredCount,
      totalFailed: this._failedCount,
    });
  }

  // -------------------------------------------------------------------------
  // Telemetry accessors
  // -------------------------------------------------------------------------

  /** Total number of successfully delivered alerts since construction. */
  get deliveredCount(): number {
    return this._deliveredCount;
  }

  /** Total number of failed dispatch attempts since construction. */
  get failedCount(): number {
    return this._failedCount;
  }

  /** Whether the dispatcher has been shut down. */
  get isShutdown(): boolean {
    return this._shutdown;
  }
}

export default AnomalyAlertDispatcher;
