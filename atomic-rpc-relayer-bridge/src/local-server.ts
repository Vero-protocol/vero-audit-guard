/**
 * Local HTTP server for Docker Compose / multi-service development.
 *
 * Exposes relayer metrics that anomaly-detector can poll, plus a health
 * endpoint so compose can wait until the bridge is ready.
 */
import * as http from "http";
import type { IncomingMessage, ServerResponse } from "http";
import AtomicRpcRelayerBridge, { type BridgeEndpoint } from "./index";

export interface LocalServerOptions {
  port?: number;
  host?: string;
  relayerAddress?: string;
  initialNonce?: number;
  initialFailedTxCount?: number;
  endpoints?: BridgeEndpoint[];
}

export interface RelayerMetricsPayload {
  address: string;
  nonce: number;
  failedTxCount: number;
  timestamp: number;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return parsed;
}

function defaultEndpoints(): BridgeEndpoint[] {
  const raw = process.env.BRIDGE_ENDPOINTS ?? "http://127.0.0.1:8545";
  return raw
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean)
    .map((url, index) => ({ url, priority: 10 - index }));
}

export function createLocalBridgeHandler(options: LocalServerOptions = {}): {
  handleRequest: (req: IncomingMessage, res: ServerResponse) => void;
  getMetrics: () => RelayerMetricsPayload[];
  getBridge: () => AtomicRpcRelayerBridge;
} {
  const relayerAddress = options.relayerAddress ?? process.env.RELAYER_ADDRESS ?? "GLOCALDEVRELAYER";
  let nonce = options.initialNonce ?? parsePositiveInt(process.env.INITIAL_NONCE, 100);
  const failedTxCount =
    options.initialFailedTxCount ?? parsePositiveInt(process.env.INITIAL_FAILED_TX_COUNT, 0);

  const bridge = new AtomicRpcRelayerBridge({
    endpoints: options.endpoints ?? defaultEndpoints(),
    requireAtomicVerification: false,
  });

  const json = (res: ServerResponse, status: number, body: unknown): void => {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };

  const getMetrics = (): RelayerMetricsPayload[] => [
    {
      address: relayerAddress,
      nonce,
      failedTxCount,
      timestamp: Date.now(),
    },
  ];

  const handleRequest = (req: IncomingMessage, res: ServerResponse): void => {
    const url = req.url?.split("?")[0] ?? "/";
    const method = req.method ?? "GET";

    if (method === "GET" && (url === "/health" || url === "/healthz")) {
      json(res, 200, { status: "ok", service: "atomic-rpc-relayer-bridge" });
      return;
    }

    if (method === "GET" && url === "/metrics") {
      nonce += 1;
      json(res, 200, getMetrics());
      return;
    }

    if (method === "GET" && url === "/audit-log") {
      json(res, 200, bridge.getAuditLog());
      return;
    }

    json(res, 404, { error: "not found" });
  };

  return { handleRequest, getMetrics, getBridge: () => bridge };
}

export function startLocalServer(options: LocalServerOptions = {}): http.Server {
  const port = options.port ?? parsePositiveInt(process.env.PORT ?? process.env.BRIDGE_PORT, 8545);
  const host = options.host ?? process.env.HOST ?? "0.0.0.0";
  const { handleRequest } = createLocalBridgeHandler(options);

  const server = http.createServer(handleRequest);
  server.listen(port, host, () => {
    const addr = server.address();
    const bound =
      typeof addr === "object" && addr !== null ? `${addr.address}:${addr.port}` : `${host}:${port}`;
    console.log(`[atomic-rpc-relayer-bridge] local server listening on ${bound}`);
    console.log("[atomic-rpc-relayer-bridge] GET /health  GET /metrics  GET /audit-log");
  });
  return server;
}

if (require.main === module) {
  startLocalServer();
}
