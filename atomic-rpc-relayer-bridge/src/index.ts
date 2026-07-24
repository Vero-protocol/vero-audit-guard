/**
 * Atomic RPC Relayer Bridge
 * 
 * Issue #154: Integrate atomic RPC relayer bridge
 * 
 * Provides atomic, verified RPC request relaying between endpoints
 * with integrity checks, failover, and audit logging.
 */

import axios from "axios";

export type BridgeRequestMethod = "GET" | "POST" | "PUT" | "DELETE";

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
}

export interface BridgeResponse {
  requestId: string;
  success: boolean;
  data?: unknown;
  error?: string;
  endpointUsed: string;
  latencyMs: number;
  timestamp: number;
}

export interface AtomicBridgeOptions {
  endpoints: BridgeEndpoint[];
  timeoutMs?: number;
  maxRetries?: number;
  requireAtomicVerification?: boolean;
}

export class AtomicRpcRelayerBridge {
  private readonly endpoints: BridgeEndpoint[];
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly requireAtomicVerification: boolean;
  private readonly auditLog: BridgeResponse[] = [];

  constructor(options: AtomicBridgeOptions) {
    this.endpoints = options.endpoints.sort((a, b) => b.priority - a.priority);
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.maxRetries = options.maxRetries ?? 3;
    this.requireAtomicVerification = options.requireAtomicVerification ?? true;
  }

  /**
   * Relays a request atomically with failover and verification
   */
  public async relay(request: BridgeRequest): Promise<BridgeResponse> {
    const startTime = Date.now();
    let lastError: string | undefined;
    let attempts = 0;

    for (const endpoint of this.endpoints) {
      while (attempts < this.maxRetries) {
        try {
          const response = await this.executeRequest(request, endpoint);
          if (this.requireAtomicVerification) {
            const verified = await this.verifyAtomicity(request, response, endpoint);
            if (!verified) {
              throw new Error("Atomic verification failed");
            }
          }
          const bridgeResponse: BridgeResponse = {
            requestId: request.id,
            success: true,
            data: response,
            endpointUsed: endpoint.url,
            latencyMs: Date.now() - startTime,
            timestamp: Date.now()
          };
          this.auditLog.push(bridgeResponse);
          return bridgeResponse;
        } catch (err) {
          lastError = (err as Error).message;
          attempts++;
        }
      }
      attempts = 0;
    }

    const errorResponse: BridgeResponse = {
      requestId: request.id,
      success: false,
      error: lastError ?? "All endpoints failed",
      endpointUsed: "none",
      latencyMs: Date.now() - startTime,
      timestamp: Date.now()
    };
    this.auditLog.push(errorResponse);
    return errorResponse;
  }

  private async executeRequest(
    request: BridgeRequest,
    endpoint: BridgeEndpoint
  ): Promise<unknown> {
    const axiosConfig = {
      method: request.method.toLowerCase(),
      url: `${endpoint.url}${request.endpoint}`,
      data: request.payload,
      timeout: this.timeoutMs
    };
    const response = await axios(axiosConfig);
    return response.data;
  }

  private async verifyAtomicity(
    request: BridgeRequest,
    response: unknown,
    endpoint: BridgeEndpoint
  ): Promise<boolean> {
    // Atomic verification logic (can be extended with ZK proofs, multi-endpoint consensus, etc.)
    // For now, we'll do a simple verification by checking a secondary endpoint if available
    const secondaryEndpoint = this.endpoints.find(e => e.url !== endpoint.url);
    if (!secondaryEndpoint) return true;

    try {
      const secondaryResponse = await this.executeRequest(request, secondaryEndpoint);
      return JSON.stringify(response) === JSON.stringify(secondaryResponse);
    } catch {
      return false;
    }
  }

  /**
   * Retrieves the audit log for all relayed requests
   */
  public getAuditLog(): BridgeResponse[] {
    return [...this.auditLog];
  }

  /**
   * Clears the audit log
   */
  public clearAuditLog(): void {
    this.auditLog.length = 0;
  }
}

export default AtomicRpcRelayerBridge;
