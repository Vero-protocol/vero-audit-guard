/**
 * Atomic RPC Relayer Bridge
 *
 * Issue #154: Integrate atomic RPC relayer bridge
 *
 * Provides atomic, verified RPC request relaying between endpoints
 * with integrity checks, failover, and audit logging.
 */

import axios, { type AxiosRequestConfig } from "axios";

export type BridgeRequestMethod = "GET" | "POST" | "PUT" | "DELETE";

export type VerificationStatus = "verified" | "failed" | "unavailable" | "skipped";

export interface BridgeEndpoint {
  url: string;
  chainId?: string;
  priority: number;
}

export interface BridgeRequest {
  id: string;
  method: BridgeRequestMethod;
  endpoint: string;
  payload?: unknown;
  timestamp: number;
  /** Explicitly declares that repeating this request has idempotent semantics. */
  idempotent?: boolean;
  /**
   * Caller-supplied key forwarded to the upstream Idempotency-Key header.
   * The caller is responsible for using endpoints that enforce the key.
   */
  idempotencyKey?: string;
}

export interface BridgeResponse {
  requestId: string;
  success: boolean;
  data?: unknown;
  error?: string;
  endpointUsed: string;
  latencyMs: number;
  timestamp: number;
  verificationStatus: VerificationStatus;
}

export type VerificationProjection = (
  request: BridgeRequest,
  response: unknown
) => unknown;

export interface AtomicBridgeOptions {
  endpoints: BridgeEndpoint[];
  timeoutMs?: number;
  maxRetries?: number;
  requireAtomicVerification?: boolean;
  /** Selects the stable response fields that participate in verification. */
  verificationProjection?: VerificationProjection;
}

interface VerificationResult {
  status: "verified" | "failed" | "unavailable";
  message?: string;
}

function normalizeJson(value: unknown, seen: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Verification projection must contain finite JSON numbers");
    }
    return value;
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      throw new TypeError("Verification projection must not contain circular references");
    }
    seen.add(value);
    try {
      return value.map((entry) => normalizeJson(entry, seen));
    } finally {
      seen.delete(value);
    }
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Verification projection must contain only JSON objects");
    }
    if (seen.has(value)) {
      throw new TypeError("Verification projection must not contain circular references");
    }

    seen.add(value);
    try {
      // A null-prototype object keeps JSON keys such as "__proto__" as ordinary
      // data while the canonical representation is assembled.
      const normalized = Object.create(null) as Record<string, unknown>;
      for (const key of Object.keys(value).sort()) {
        normalized[key] = normalizeJson((value as Record<string, unknown>)[key], seen);
      }
      return normalized;
    } finally {
      seen.delete(value);
    }
  }

  throw new TypeError("Verification projection must be valid JSON data");
}

/**
 * Produces deterministic JSON for equality checks. Object keys are sorted
 * recursively while array order is preserved, matching JSON semantics.
 */
function canonicalizeJson(value: unknown): string {
  return JSON.stringify(normalizeJson(value, new Set<object>()));
}

export class AtomicRpcRelayerBridge {
  private readonly endpoints: BridgeEndpoint[];
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly requireAtomicVerification: boolean;
  private readonly verificationProjection: VerificationProjection;
  private readonly auditLog: BridgeResponse[] = [];

  constructor(options: AtomicBridgeOptions) {
    this.endpoints = [...options.endpoints].sort((a, b) => b.priority - a.priority);
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.maxRetries = options.maxRetries ?? 3;
    this.requireAtomicVerification = options.requireAtomicVerification ?? true;
    this.verificationProjection =
      options.verificationProjection ?? ((_request, response) => response);
  }

  /** Relays a request with replay-aware failover and response verification. */
  public async relay(request: BridgeRequest): Promise<BridgeResponse> {
    const startTime = Date.now();
    const invalidIdempotencyKey =
      request.idempotencyKey !== undefined && request.idempotencyKey.trim().length === 0;

    if (invalidIdempotencyKey) {
      return this.recordResponse({
        requestId: request.id,
        success: false,
        error: "Idempotency key must not be empty",
        endpointUsed: "none",
        latencyMs: Date.now() - startTime,
        timestamp: Date.now(),
        verificationStatus: "skipped"
      });
    }

    const replayable = this.isReplayable(request);
    const eligibleEndpoints = replayable ? this.endpoints : this.endpoints.slice(0, 1);
    const attemptsPerEndpoint = replayable ? this.maxRetries : 1;
    let lastError: string | undefined;
    let lastVerificationStatus: VerificationStatus = "skipped";

    for (const endpoint of eligibleEndpoints) {
      let attempts = 0;

      while (attempts < attemptsPerEndpoint) {
        let response: unknown;
        try {
          response = await this.executeRequest(request, endpoint);
        } catch (err) {
          lastError = this.errorMessage(err);
          attempts++;
          continue;
        }

        if (!this.requireAtomicVerification || !replayable) {
          return this.recordResponse({
            requestId: request.id,
            success: true,
            data: response,
            endpointUsed: endpoint.url,
            latencyMs: Date.now() - startTime,
            timestamp: Date.now(),
            verificationStatus: "skipped"
          });
        }

        const verification = await this.verifyAtomicity(request, response, endpoint);
        lastVerificationStatus = verification.status;

        if (verification.status === "verified") {
          return this.recordResponse({
            requestId: request.id,
            success: true,
            data: response,
            endpointUsed: endpoint.url,
            latencyMs: Date.now() - startTime,
            timestamp: Date.now(),
            verificationStatus: "verified"
          });
        }

        if (verification.status === "unavailable") {
          return this.recordResponse({
            requestId: request.id,
            success: false,
            error: verification.message ?? "Atomic verification unavailable",
            endpointUsed: endpoint.url,
            latencyMs: Date.now() - startTime,
            timestamp: Date.now(),
            verificationStatus: "unavailable"
          });
        }

        lastError = verification.message ?? "Atomic verification failed";
        attempts++;
      }
    }

    return this.recordResponse({
      requestId: request.id,
      success: false,
      error: lastError ?? "All endpoints failed",
      endpointUsed: "none",
      latencyMs: Date.now() - startTime,
      timestamp: Date.now(),
      verificationStatus: lastVerificationStatus
    });
  }

  private recordResponse(response: BridgeResponse): BridgeResponse {
    this.auditLog.push(response);
    return response;
  }

  private isReplayable(request: BridgeRequest): boolean {
    return (
      request.method === "GET" ||
      request.idempotent === true ||
      request.idempotencyKey !== undefined
    );
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  private buildRequestUrl(requestEndpoint: string, endpointUrl: string): string {
    let baseUrl: URL;
    let requestUrl: URL;

    try {
      baseUrl = new URL(endpointUrl);
      requestUrl = new URL(requestEndpoint, baseUrl);
    } catch {
      throw new Error("Invalid RPC endpoint URL");
    }

    if (requestUrl.origin !== baseUrl.origin) {
      throw new Error("Request endpoint must resolve to the configured RPC origin");
    }

    return requestUrl.toString();
  }

  private async executeRequest(
    request: BridgeRequest,
    endpoint: BridgeEndpoint
  ): Promise<unknown> {
    const axiosConfig: AxiosRequestConfig = {
      method: request.method.toLowerCase(),
      url: this.buildRequestUrl(request.endpoint, endpoint.url),
      data: request.payload,
      timeout: this.timeoutMs
    };

    if (request.idempotencyKey !== undefined) {
      axiosConfig.headers = { "Idempotency-Key": request.idempotencyKey };
    }

    const response = await axios(axiosConfig);
    return response.data;
  }

  private endpointIdentity(request: BridgeRequest, endpoint: BridgeEndpoint): string {
    try {
      const resolved = new URL(this.buildRequestUrl(request.endpoint, endpoint.url));
      // URL fragments are not part of an HTTP request target and therefore do
      // not make two upstream voters independent.
      resolved.hash = "";
      return resolved.toString();
    } catch {
      // Keep malformed configured endpoints as unavailable voters while still
      // collapsing exact duplicates. executeRequest reports their failure.
      return `invalid:${endpoint.url}`;
    }
  }

  private distinctSecondaryEndpoints(
    request: BridgeRequest,
    endpoint: BridgeEndpoint
  ): BridgeEndpoint[] {
    const seen = new Set<string>([this.endpointIdentity(request, endpoint)]);
    const secondaries: BridgeEndpoint[] = [];

    for (const candidate of this.endpoints) {
      const identity = this.endpointIdentity(request, candidate);
      if (seen.has(identity)) continue;
      seen.add(identity);
      secondaries.push(candidate);
    }

    return secondaries;
  }

  private async verifyAtomicity(
    request: BridgeRequest,
    response: unknown,
    endpoint: BridgeEndpoint
  ): Promise<VerificationResult> {
    const secondaryEndpoints = this.distinctSecondaryEndpoints(request, endpoint);
    if (secondaryEndpoints.length === 0) {
      return {
        status: "unavailable",
        message: "Atomic verification unavailable: no distinct secondary endpoint"
      };
    }

    let canonicalPrimary: string;
    try {
      canonicalPrimary = canonicalizeJson(this.verificationProjection(request, response));
    } catch (err) {
      return {
        status: "unavailable",
        message: `Atomic verification unavailable: ${this.errorMessage(err)}`
      };
    }

    const secondaryResults = await Promise.allSettled(
      secondaryEndpoints.map(async (secondaryEndpoint) => {
        const secondaryResponse = await this.executeRequest(request, secondaryEndpoint);
        return canonicalizeJson(this.verificationProjection(request, secondaryResponse));
      })
    );

    const voterCount = secondaryEndpoints.length + 1;
    const requiredVotes = Math.floor(voterCount / 2) + 1;
    let matchingVotes = 1;
    let unavailableVotes = 0;

    for (const result of secondaryResults) {
      if (result.status === "rejected") {
        unavailableVotes++;
      } else if (result.value === canonicalPrimary) {
        matchingVotes++;
      }
    }

    if (matchingVotes >= requiredVotes) {
      return { status: "verified" };
    }

    if (matchingVotes + unavailableVotes >= requiredVotes) {
      return {
        status: "unavailable",
        message: "Atomic verification unavailable: quorum could not be reached"
      };
    }

    return {
      status: "failed",
      message: "Atomic verification failed: quorum disagreed with the primary response"
    };
  }

  /** Retrieves the audit log for all relayed requests. */
  public getAuditLog(): BridgeResponse[] {
    return [...this.auditLog];
  }

  /** Clears the audit log. */
  public clearAuditLog(): void {
    this.auditLog.length = 0;
  }
}

export default AtomicRpcRelayerBridge;
