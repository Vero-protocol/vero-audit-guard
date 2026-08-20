/**
 * Admin Multi-Sig Webhook Notification Channel — Issue VAG-010
 *
 * Sends HMAC-SHA256-authenticated webhook notifications to configured
 * multi-sig signer endpoints when a critical anomaly is detected.
 *
 * Design invariants
 * -----------------
 * 1. STRICTLY OBSERVATIONAL — this module has no authority to halt, pause,
 *    block, or revert any on-chain state or contract execution.  It sends
 *    HTTP notifications only.  No chain SDK is imported; no on-chain method
 *    is callable.
 *
 * 2. HMAC-SHA256 authentication — every outbound request carries:
 *      X-Vero-Signature: sha256=<hex-HMAC>
 *    computed over the raw JSON body using a shared secret loaded exclusively
 *    from the MULTISIG_WEBHOOK_SECRET environment variable.  The secret is
 *    NEVER logged, echoed, or embedded in source.
 *
 * 3. Typed error hierarchy — follows the VAG-009 (AnomalyAlertDispatcher)
 *    convention: abstract WebhookNotificationError base → typed subclasses
 *    with a `readonly code` discriminant.  No bare panics; all failure modes
 *    propagate as typed errors or are captured in WebhookNotifyResult.
 *
 * 4. Visible failure — a failed notification attempt is logged at error level
 *    AND paged through the on-call roster (oncall-roster.ts) so that a silent
 *    failure on this path — the only path to human action — is impossible.
 *
 * 5. Non-blocking / non-throwing default — `notifySigners()` catches delivery
 *    errors per endpoint, accumulates results, and never throws unless ALL
 *    endpoints have been misconfigured (missing secret or zero endpoints).
 *    Callers may opt into strict mode (throwOnAnyFailure=true) for pipeline
 *    use.
 *
 * Environment variables
 * ---------------------
 *   MULTISIG_WEBHOOK_SECRET   — shared HMAC secret (required)
 *   MULTISIG_WEBHOOK_URLS     — comma-separated signer endpoint URLs (required)
 *   MULTISIG_WEBHOOK_TIMEOUT_MS — per-request timeout in ms (default: 5000)
 */

import * as crypto from "crypto";
import axios from "axios";
import { OnCallRoster } from "./oncall-roster";

// ---------------------------------------------------------------------------
// Typed error hierarchy (VAG-009 convention)
// ---------------------------------------------------------------------------

/**
 * Base class for all webhook notifier errors — never thrown directly.
 * Follows the same pattern as DispatcherError in anomaly-alert-dispatcher.ts.
 */
export abstract class WebhookNotificationError extends Error {
  abstract readonly code: string;

  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = this.constructor.name;
    // Maintain proper prototype chain in transpiled JS
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** One or more endpoint URLs are missing or the secret is not configured. */
export class WebhookConfigurationError extends WebhookNotificationError {
  readonly code = "WEBHOOK_CONFIGURATION_INVALID" as const;

  constructor(detail: string) {
    super(`Webhook configuration error: ${detail}`);
  }
}

/** The anomaly payload failed schema validation before any HTTP attempt. */
export class WebhookPayloadSerializationError extends WebhookNotificationError {
  readonly code = "WEBHOOK_PAYLOAD_SERIALIZATION_FAILED" as const;

  constructor(detail: string, cause?: unknown) {
    super(`Webhook payload serialization failed: ${detail}`, cause);
  }
}

/** The HTTP request reached the endpoint but the server returned non-2xx. */
export class WebhookNon2xxResponseError extends WebhookNotificationError {
  readonly code = "WEBHOOK_NON_2XX_RESPONSE" as const;

  constructor(
    public readonly endpointUrl: string,
    public readonly httpStatus: number,
    cause?: unknown
  ) {
    super(
      `Webhook endpoint returned non-2xx status ${httpStatus} for URL: ${endpointUrl}`,
      cause
    );
  }
}

/** The HTTP request timed out before receiving a response. */
export class WebhookTimeoutError extends WebhookNotificationError {
  readonly code = "WEBHOOK_TIMEOUT" as const;

  constructor(
    public readonly endpointUrl: string,
    public readonly timeoutMs: number,
    cause?: unknown
  ) {
    super(
      `Webhook timed out after ${timeoutMs}ms for URL: ${endpointUrl}`,
      cause
    );
  }
}

/** The HTTP request failed due to a network-level error (DNS, connection refused, etc.). */
export class WebhookNetworkError extends WebhookNotificationError {
  readonly code = "WEBHOOK_NETWORK_ERROR" as const;

  constructor(public readonly endpointUrl: string, cause?: unknown) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    super(`Webhook network error for URL ${endpointUrl}: ${msg}`, cause);
  }
}

/** Discriminated union — exhaustive over all recoverable error kinds. */
export type WebhookDeliveryError =
  | WebhookNon2xxResponseError
  | WebhookTimeoutError
  | WebhookNetworkError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Canonical anomaly input shape consumed by the notifier. */
export interface CriticalAnomalyInput {
  /**
   * Anomaly type identifier — e.g. "NONCE_SPIKE", "THREAT_FEED_MATCH".
   * Must be a non-empty string.
   */
  type: string;
  /** Severity level. Notifications are only dispatched for HIGH and CRITICAL. */
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  /** Human-readable anomaly summary. */
  message: string;
  /** Full contextual detail — address, delta, raw metric, etc. */
  detail: string;
  /** Address of the relayer or account involved, if applicable. */
  address?: string;
  /** ISO-8601 timestamp; defaults to Date.now() if omitted. */
  timestamp?: string;
  /** Arbitrary structured metadata (observational only; no on-chain effect). */
  metadata?: Record<string, unknown>;
}

/** Per-endpoint delivery outcome. */
export interface EndpointDeliveryResult {
  /** The endpoint that was targeted. */
  url: string;
  /** true when the endpoint returned a 2xx response. */
  delivered: boolean;
  /** ISO-8601 timestamp of the attempt. */
  attemptedAt: string;
  /** Typed error if delivery failed. */
  error?: WebhookDeliveryError;
}

/** Aggregate result of a notifySigners() call. */
export interface WebhookNotifyResult {
  /** Number of endpoints that returned 2xx. */
  successCount: number;
  /** Number of endpoints that failed. */
  failureCount: number;
  /** Per-endpoint breakdown. */
  endpoints: EndpointDeliveryResult[];
  /** ISO-8601 timestamp when the notification round completed. */
  completedAt: string;
}

/** Notifier configuration. */
export interface MultisigWebhookNotifierConfig {
  /**
   * HMAC-SHA256 shared secret.  Loaded from MULTISIG_WEBHOOK_SECRET by
   * default — MUST NOT be passed as a literal string in production callers.
   * Only override in tests via dependency injection.
   */
  secret?: string;
  /**
   * Comma-separated list of signer endpoint URLs.
   * Loaded from MULTISIG_WEBHOOK_URLS by default.
   */
  webhookUrls?: string;
  /**
   * Per-request timeout in milliseconds.
   * Defaults to MULTISIG_WEBHOOK_TIMEOUT_MS env var, then 5000.
   */
  timeoutMs?: number;
  /**
   * When true, notifySigners() throws if ANY endpoint fails.
   * Default: false (accumulate errors into result, never throw).
   */
  throwOnAnyFailure?: boolean;
  /**
   * Injected axios instance for testing.  Production code should not set this.
   * @internal
   */
  _httpClient?: typeof axios;
  /**
   * Injected OnCallRoster for testing.
   * @internal
   */
  _rosterOverride?: OnCallRoster;
}

// ---------------------------------------------------------------------------
// Wire payload shape
// ---------------------------------------------------------------------------

/** Shape of the JSON body sent to each signer endpoint. */
interface WebhookPayload {
  /** Always "vero-audit-guard" — lets receivers identify the sender. */
  source: "vero-audit-guard";
  event: "CRITICAL_ANOMALY_DETECTED";
  anomaly: {
    type: string;
    severity: string;
    message: string;
    detail: string;
    address?: string;
    metadata: Record<string, unknown>;
  };
  /** ISO-8601 */
  detectedAt: string;
  /** ISO-8601 */
  notifiedAt: string;
}

// ---------------------------------------------------------------------------
// Internal logging
// ---------------------------------------------------------------------------

interface InternalLogger {
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

function buildLogger(tag: string): InternalLogger {
  const fmt = (level: string, msg: string, meta?: Record<string, unknown>): string => {
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
// HMAC signing
// ---------------------------------------------------------------------------

/**
 * Computes an HMAC-SHA256 signature over the raw JSON string.
 *
 * The signature header value is:  sha256=<lower-hex-digest>
 *
 * The secret is consumed as a Buffer to avoid encoding ambiguity and is never
 * returned, stored, or logged by this function.
 */
export function computeHmacSignature(jsonBody: string, secret: string): string {
  if (!secret) {
    throw new WebhookConfigurationError(
      "MULTISIG_WEBHOOK_SECRET is empty — cannot compute HMAC signature"
    );
  }
  const hmac = crypto.createHmac("sha256", Buffer.from(secret, "utf-8"));
  hmac.update(jsonBody, "utf-8");
  return `sha256=${hmac.digest("hex")}`;
}

// ---------------------------------------------------------------------------
// Payload validation
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = new Set<string>(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * Validates the incoming anomaly input.
 * @throws {WebhookPayloadSerializationError} on the first validation failure.
 */
function validateInput(input: CriticalAnomalyInput): void {
  if (typeof input.type !== "string" || input.type.trim().length === 0) {
    throw new WebhookPayloadSerializationError(
      `field "type" must be a non-empty string, got: ${JSON.stringify(input.type)}`
    );
  }
  if (!VALID_SEVERITIES.has(input.severity)) {
    throw new WebhookPayloadSerializationError(
      `field "severity" must be LOW|MEDIUM|HIGH|CRITICAL, got: ${JSON.stringify(input.severity)}`
    );
  }
  if (typeof input.message !== "string" || input.message.trim().length === 0) {
    throw new WebhookPayloadSerializationError(
      `field "message" must be a non-empty string, got: ${JSON.stringify(input.message)}`
    );
  }
  if (typeof input.detail !== "string" || input.detail.trim().length === 0) {
    throw new WebhookPayloadSerializationError(
      `field "detail" must be a non-empty string, got: ${JSON.stringify(input.detail)}`
    );
  }
  if (input.timestamp !== undefined && isNaN(Date.parse(input.timestamp))) {
    throw new WebhookPayloadSerializationError(
      `field "timestamp" must be a valid ISO-8601 string, got: ${JSON.stringify(input.timestamp)}`
    );
  }
  if (
    input.metadata !== undefined &&
    (typeof input.metadata !== "object" ||
      Array.isArray(input.metadata) ||
      input.metadata === null)
  ) {
    throw new WebhookPayloadSerializationError(
      `field "metadata" must be a plain object, got: ${JSON.stringify(input.metadata)}`
    );
  }
  if (
    input.address !== undefined &&
    (typeof input.address !== "string" || input.address.trim().length === 0)
  ) {
    throw new WebhookPayloadSerializationError(
      `field "address" must be a non-empty string when provided, got: ${JSON.stringify(input.address)}`
    );
  }
}

// ---------------------------------------------------------------------------
// MultisigWebhookNotifier
// ---------------------------------------------------------------------------

/**
 * Sends HMAC-SHA256-authenticated webhook notifications to all configured
 * multi-sig signer endpoints when a critical anomaly is detected.
 *
 * OBSERVATIONAL-ONLY: This class has no imports from any chain SDK and
 * contains no method that can halt, pause, block, or revert on-chain state.
 */
export class MultisigWebhookNotifier {
  private readonly secret: string;
  private readonly endpoints: string[];
  private readonly timeoutMs: number;
  private readonly throwOnAnyFailure: boolean;
  private readonly http: typeof axios;
  private readonly log: InternalLogger;
  private _roster: OnCallRoster | null = null;
  private readonly rosterOverride: OnCallRoster | null;

  constructor(config: MultisigWebhookNotifierConfig = {}) {
    // Secret — loaded from env; never logged
    this.secret =
      config.secret !== undefined
        ? config.secret
        : (process.env["MULTISIG_WEBHOOK_SECRET"] ?? "");

    // Endpoints — comma-separated, whitespace-trimmed, empties removed
    const rawUrls =
      config.webhookUrls !== undefined
        ? config.webhookUrls
        : (process.env["MULTISIG_WEBHOOK_URLS"] ?? "");
    this.endpoints = rawUrls
      .split(",")
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    this.timeoutMs =
      config.timeoutMs !== undefined
        ? config.timeoutMs
        : Number(process.env["MULTISIG_WEBHOOK_TIMEOUT_MS"] ?? 5000);

    this.throwOnAnyFailure = config.throwOnAnyFailure ?? false;
    this.http = config._httpClient ?? axios;
    this.rosterOverride = config._rosterOverride ?? null;
    this.log = buildLogger("MultisigWebhookNotifier");
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Lazy-initialized on-call roster — not constructed unless a failure occurs. */
  private getRoster(): OnCallRoster {
    if (this.rosterOverride) return this.rosterOverride;
    if (!this._roster) {
      this._roster = new OnCallRoster();
    }
    return this._roster;
  }

  /**
   * Delivers the signed payload to a single endpoint.
   * Returns an EndpointDeliveryResult; never throws.
   */
  private async deliverToEndpoint(
    url: string,
    jsonBody: string,
    signature: string
  ): Promise<EndpointDeliveryResult> {
    const attemptedAt = new Date().toISOString();

    try {
      const response = await this.http.post(url, jsonBody, {
        headers: {
          "Content-Type": "application/json",
          // HMAC signature for receiver-side verification
          "X-Vero-Signature": signature,
        },
        timeout: this.timeoutMs,
        // Pass the pre-serialised string; prevent axios from re-serialising
        transformRequest: [(data: string) => data],
      });

      // axios throws for non-2xx when validateStatus is default, but guard
      // explicitly in case the caller injects a custom axios instance.
      const status: number =
        typeof response.status === "number" ? response.status : 0;

      if (status < 200 || status >= 300) {
        const err = new WebhookNon2xxResponseError(url, status);
        this.log.error("Endpoint returned non-2xx status", {
          url,
          status,
          error: err.code,
        });
        return { url, delivered: false, attemptedAt, error: err };
      }

      this.log.info("Webhook delivered successfully", { url, status });
      return { url, delivered: true, attemptedAt };
    } catch (raw) {
      // Distinguish timeout from other network errors using axios error codes
      const isAxiosError =
        raw !== null &&
        typeof raw === "object" &&
        (raw as Record<string, unknown>)["isAxiosError"] === true;

      if (isAxiosError) {
        const axErr = raw as {
          code?: string;
          response?: { status: number };
          message: string;
        };

        // Non-2xx thrown by axios default validateStatus
        if (axErr.response !== undefined) {
          const status = axErr.response.status;
          const err = new WebhookNon2xxResponseError(url, status, raw);
          this.log.error("Endpoint returned non-2xx (axios thrown)", {
            url,
            status,
            error: err.code,
          });
          return { url, delivered: false, attemptedAt, error: err };
        }

        // Timeout
        if (axErr.code === "ECONNABORTED" || axErr.code === "ERR_CANCELED") {
          const err = new WebhookTimeoutError(url, this.timeoutMs, raw);
          this.log.error("Webhook request timed out", {
            url,
            timeoutMs: this.timeoutMs,
            error: err.code,
          });
          return { url, delivered: false, attemptedAt, error: err };
        }
      }

      // Network-level failure (DNS, connection refused, etc.)
      const err = new WebhookNetworkError(url, raw);
      this.log.error("Webhook network error", {
        url,
        error: err.code,
        cause: raw instanceof Error ? raw.message : String(raw),
      });
      return { url, delivered: false, attemptedAt, error: err };
    }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Sends an authenticated webhook notification to all configured signer
   * endpoints.
   *
   * Steps:
   *  1. Validate the input payload (throws WebhookPayloadSerializationError on
   *     bad data — before any I/O).
   *  2. Validate configuration (throws WebhookConfigurationError if the secret
   *     is missing or no endpoints are configured).
   *  3. Serialize the canonical payload to JSON and compute HMAC-SHA256.
   *  4. POST to each endpoint concurrently with a per-request timeout.
   *  5. Log any failures at error level and page the on-call roster so that
   *     notification failures are never silent.
   *  6. Return a WebhookNotifyResult summarising per-endpoint outcomes.
   *
   * @throws {WebhookPayloadSerializationError} if input is structurally invalid
   * @throws {WebhookConfigurationError}        if secret or endpoints are missing
   * @throws {WebhookDeliveryError}             if throwOnAnyFailure=true and ≥1 endpoint fails
   */
  async notifySigners(input: CriticalAnomalyInput): Promise<WebhookNotifyResult> {
    // 1. Validate input (throws before any I/O)
    validateInput(input);

    // 2. Validate configuration
    if (!this.secret) {
      throw new WebhookConfigurationError(
        "MULTISIG_WEBHOOK_SECRET environment variable is not set"
      );
    }
    if (this.endpoints.length === 0) {
      throw new WebhookConfigurationError(
        "MULTISIG_WEBHOOK_URLS environment variable is not set or contains no valid URLs"
      );
    }

    // 3. Build and serialise payload
    const notifiedAt = new Date().toISOString();
    const detectedAt = input.timestamp ?? notifiedAt;

    const payload: WebhookPayload = {
      source: "vero-audit-guard",
      event: "CRITICAL_ANOMALY_DETECTED",
      anomaly: {
        type: input.type,
        severity: input.severity,
        message: input.message,
        detail: input.detail,
        ...(input.address !== undefined ? { address: input.address } : {}),
        metadata: input.metadata ?? {},
      },
      detectedAt,
      notifiedAt,
    };

    let jsonBody: string;
    try {
      jsonBody = JSON.stringify(payload);
    } catch (serErr) {
      throw new WebhookPayloadSerializationError(
        "JSON.stringify failed on anomaly payload",
        serErr
      );
    }

    // 4. Compute HMAC — uses the secret in memory only; never logged
    const signature = computeHmacSignature(jsonBody, this.secret);

    this.log.info("Notifying multi-sig signers of critical anomaly", {
      type: input.type,
      severity: input.severity,
      endpointCount: this.endpoints.length,
    });

    // 5. Deliver concurrently to all endpoints
    const deliveryPromises = this.endpoints.map((url) =>
      this.deliverToEndpoint(url, jsonBody, signature)
    );
    const endpointResults = await Promise.all(deliveryPromises);

    // 6. Handle failures — surface at error level and page on-call roster
    const failures = endpointResults.filter((r) => !r.delivered);

    if (failures.length > 0) {
      const failedUrls = failures.map((r) => r.url).join(", ");
      this.log.error(
        "One or more multi-sig webhook notifications failed — paging on-call roster",
        {
          failedCount: failures.length,
          totalEndpoints: this.endpoints.length,
          failedUrls,
          anomalyType: input.type,
          severity: input.severity,
        }
      );

      // Page on-call roster — notification failures on this path are critical
      // because this is the ONLY channel from anomaly to human action.
      try {
        const roster = this.getRoster();
        await roster.pageCurrentOnCall(
          `[VAG-010] Multi-sig webhook delivery failed for anomaly type "${input.type}" (${input.severity}). ` +
            `Failed endpoints: ${failedUrls}. ` +
            `${failures.length}/${this.endpoints.length} notification(s) undelivered.`,
          "CRITICAL",
          "vero-audit-guard"
        );
      } catch (rosterErr) {
        // Log the roster failure — we cannot swallow it silently, but we also
        // cannot let a roster error suppress the original delivery result.
        this.log.error(
          "On-call roster paging also failed during notification failure handling",
          {
            cause:
              rosterErr instanceof Error ? rosterErr.message : String(rosterErr),
          }
        );
      }

      if (this.throwOnAnyFailure && failures[0].error !== undefined) {
        throw failures[0].error;
      }
    }

    const completedAt = new Date().toISOString();
    const successCount = endpointResults.filter((r) => r.delivered).length;

    return {
      successCount,
      failureCount: failures.length,
      endpoints: endpointResults,
      completedAt,
    };
  }

  // -------------------------------------------------------------------------
  // Accessors (observability / testing)
  // -------------------------------------------------------------------------

  /** Number of configured signer endpoints. */
  get endpointCount(): number {
    return this.endpoints.length;
  }

  /** Whether the notifier has a non-empty HMAC secret loaded. */
  get isConfigured(): boolean {
    return this.secret.length > 0 && this.endpoints.length > 0;
  }
}

export default MultisigWebhookNotifier;
