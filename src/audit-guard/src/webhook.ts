import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { WEBHOOK_URL, WEBHOOK_TOKEN } from "./config";

export interface AlertPayload {
  repository: string;
  alert: string;
  timestamp: string;
}

type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  }
) => Promise<unknown>;

// Log file for relay events
const LOG_FILE = path.join(__dirname, "..", "logs", "relay-events.log");

// Default timeout for webhook requests (5 seconds)
const DEFAULT_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Typed error hierarchy (VAG-009 / multisig-webhook-notifier convention)
// ---------------------------------------------------------------------------

/**
 * Base class for all webhook errors — never thrown directly.
 */
export abstract class WebhookError extends Error {
  abstract readonly code: string;

  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** The HTTP request reached the endpoint but the server returned non-2xx. */
export class WebhookNon2xxResponseError extends WebhookError {
  readonly code = "WEBHOOK_NON_2XX_RESPONSE" as const;

  constructor(
    public readonly httpStatus: number,
    cause?: unknown
  ) {
    super(`Webhook endpoint returned non-2xx status ${httpStatus}`, cause);
  }
}

/** The HTTP request timed out before receiving a response. */
export class WebhookTimeoutError extends WebhookError {
  readonly code = "WEBHOOK_TIMEOUT" as const;

  constructor(
    public readonly timeoutMs: number,
    cause?: unknown
  ) {
    super(`Webhook timed out after ${timeoutMs}ms`, cause);
  }
}

/** The HTTP request failed due to a network-level error. */
export class WebhookNetworkError extends WebhookError {
  readonly code = "WEBHOOK_NETWORK_ERROR" as const;

  constructor(cause?: unknown) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    super(`Webhook network error: ${msg}`, cause);
  }
}

/** Discriminated union of all recoverable webhook errors. */
export type WebhookDeliveryError =
  | WebhookNon2xxResponseError
  | WebhookTimeoutError
  | WebhookNetworkError;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Outcome of a sendAlert() call. */
export interface WebhookDeliveryResult {
  /** true when the endpoint returned a 2xx response. */
  delivered: boolean;
  /** HTTP status code (number) or error code string on failure. */
  status: number | string;
  /** Typed error if delivery failed. */
  error?: WebhookDeliveryError;
  /** ISO-8601 timestamp of the attempt. */
  attemptedAt: string;
}

export async function sendAlert(
  payload: AlertPayload,
  options: { timeoutMs?: number } = {}
): Promise<WebhookDeliveryResult> {
  const attemptedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  if (!WEBHOOK_URL) {
    // No webhook configured — record as not delivered
    const result: WebhookDeliveryResult = {
      delivered: false,
      status: "NO_WEBHOOK_CONFIGURED",
      attemptedAt,
    };
    return result;
  }

  // Ensure log directory exists
  await fs.promises.mkdir(path.dirname(LOG_FILE), { recursive: true });

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const payloadStr = JSON.stringify(payload);

  if (WEBHOOK_TOKEN) {
    headers["Authorization"] = `Bearer ${WEBHOOK_TOKEN}`;
    const hmac = crypto.createHmac("sha256", Buffer.from(WEBHOOK_TOKEN, "utf-8"));
    hmac.update(payloadStr, "utf-8");
    headers["X-Vero-Signature"] = `sha256=${hmac.digest("hex")}`;
  }

  const fetchImpl = (globalThis as unknown as { fetch?: FetchLike }).fetch;
  if (!fetchImpl) {
    const error = new Error("Global fetch is unavailable in this runtime");
    const result: WebhookDeliveryResult = {
      delivered: false,
      status: "FETCH_UNAVAILABLE",
      error: new WebhookNetworkError(error),
      attemptedAt,
    };
    // Log the attempt with failure
    const logEntry = {
      ...payload,
      _delivery: {
        delivered: false,
        status: "FETCH_UNAVAILABLE",
        attemptedAt,
      },
    };
    await fs.promises.appendFile(LOG_FILE, JSON.stringify(logEntry) + "\n");
    return result;
  }

  // Set up AbortController for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(WEBHOOK_URL, {
      method: "POST",
      headers,
      body: payloadStr,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Cast response to get status - fetch Response-like objects have status
    const resp = response as { status?: number; ok?: boolean };
    const status = typeof resp.status === "number" ? resp.status : 0;

    if (status < 200 || status >= 300) {
      // Non-2xx response
      const error = new WebhookNon2xxResponseError(status);
      const result: WebhookDeliveryResult = {
        delivered: false,
        status,
        error,
        attemptedAt,
      };
      // Log the attempt with failure
      const logEntry = {
        ...payload,
        _delivery: {
          delivered: false,
          status,
          attemptedAt,
        },
      };
      await fs.promises.appendFile(LOG_FILE, JSON.stringify(logEntry) + "\n");
      return result;
    }

    // Success
    const result: WebhookDeliveryResult = {
      delivered: true,
      status,
      attemptedAt,
    };
    // Log the successful attempt
    const logEntry = {
      ...payload,
      _delivery: {
        delivered: true,
        status,
        attemptedAt,
      },
    };
    await fs.promises.appendFile(LOG_FILE, JSON.stringify(logEntry) + "\n");
    return result;
  } catch (e) {
    clearTimeout(timeoutId);

    let error: WebhookDeliveryError;
    let status: string;

    // Check if this is an abort/timeout error
    const isAbort =
      (typeof e === "object" && e !== null && (e as Record<string, unknown>)["name"] === "AbortError") ||
      (e instanceof Error && (e.name === "AbortError" || e.constructor.name === "DOMException"));

    if (isAbort) {
      error = new WebhookTimeoutError(timeoutMs, e);
      status = "TIMEOUT";
    } else {
      // Network-level failure
      error = new WebhookNetworkError(e);
      status = "NETWORK_ERROR";
    }

    const result: WebhookDeliveryResult = {
      delivered: false,
      status,
      error,
      attemptedAt,
    };

    // Log the attempt with failure
    const logEntry = {
      ...payload,
      _delivery: {
        delivered: false,
        status,
        attemptedAt,
      },
    };
    await fs.promises.appendFile(LOG_FILE, JSON.stringify(logEntry) + "\n");

    console.error("Failed to deliver audit‑guard webhook:", e);
    return result;
  }
}
