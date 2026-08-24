# atomic-rpc-relayer-bridge

> **Atomic RPC request relaying with integrity verification for the Vero Protocol relayer pipeline.**

The `atomic-rpc-relayer-bridge` provides a fault-tolerant, verified RPC request relay that ensures responses are consistent across multiple endpoints. It acts as a safety layer between the relayer service and upstream RPC providers, preventing a single malicious or misconfigured endpoint from compromising relayer operations.

## Purpose & Design

### Why Atomic Verification Matters

The Vero Protocol's relayer pipeline depends on RPC calls for state queries, transaction broadcasts, and nonce tracking. A compromised or flaky RPC endpoint could:
- Return inconsistent state (e.g., conflicting account balances)
- Silently fail transactions while reporting success
- Drift nonce counters, causing transaction reordering

The `atomic-rpc-relayer-bridge` mitigates these risks by:

1. **Cross-endpoint verification** — Requests are verified against a secondary endpoint before returning to the caller
2. **Automatic failover** — If an endpoint fails, the bridge transparently retries on the next priority endpoint
3. **Request atomicity** — All relayed requests and responses are logged for audit trail compliance
4. **Configurable policies** — Atomic verification can be disabled for latency-sensitive flows (with explicit trust trade-offs)

### Atomicity Guarantees

- **Verified responses**: By default, responses are cross-checked against a secondary endpoint to ensure consistency
- **Fault tolerance**: Automatic retries across configured endpoints with exponential backoff
- **Audit logging**: All requests and responses are tracked for incident investigation
- **Configurable trust model**: Explicit environment flag to disable atomic verification when latency is critical

## Quick Start

### Local Development

#### Install Dependencies
```bash
npm install
```

#### Build
```bash
npm run build
```

The TypeScript is compiled to `dist/index.js` (CommonJS).

#### Run Tests
```bash
npm test
```

#### Development Mode
Run the bridge without compilation (requires `ts-node`):

```bash
# Option 1: Bridge library (interactive usage)
npm run dev

# Option 2: Local HTTP server (with metrics endpoint)
npm run dev:local
```

The local server binds to `0.0.0.0:8545` by default and exposes:
- `GET /health` — Health check
- `GET /metrics` — Relayer metrics (requires `Bearer` token if `AUTH_TOKEN` is set)
- `GET /audit-log` — Request/response audit trail (requires `Bearer` token if `AUTH_TOKEN` is set)

### Production Build & Execution

```bash
npm run build
npm start           # Run the bridge library
npm run start:local # Run the HTTP server
```

## Configuration

Configuration is managed via environment variables. See `.env.example` for a complete reference.

### Core Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BRIDGE_PORT` | int | `8545` | HTTP server bind port (local-server mode) |
| `PORT` | int | unset | Alternative to `BRIDGE_PORT`; takes precedence if set |
| `HOST` | string | `0.0.0.0` | HTTP server bind address |
| `BRIDGE_ENDPOINTS` | string | `http://127.0.0.1:8545` | Comma-separated RPC endpoint URLs (ordered by priority) |

### Verification & Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DISABLE_ATOMIC_VERIFICATION` | bool | `false` | **Use with caution.** Set to `true` to disable cross-endpoint verification. Trades security for lower latency. Emits a warning on startup if enabled. Only accepted values: `"true"` or `"false"`; invalid values abort initialization. |
| `AUTH_TOKEN` | string | unset | Bearer token required to access `/metrics` and `/audit-log` endpoints. If unset, these endpoints are publicly accessible. |

### Relayer Metrics Simulation (Development)

When running the local server, these environment variables seed the simulated relayer metrics:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `RELAYER_ADDRESS` | string | `GLOCALDEVRELAYER` | Simulated relayer Stellar account address |
| `INITIAL_NONCE` | int | `100` | Starting nonce value |
| `INITIAL_FAILED_TX_COUNT` | int | `0` | Starting failed transaction count |

## API Reference

### TypeScript Library

#### `AtomicRpcRelayerBridge` Class

```typescript
import AtomicRpcRelayerBridge from "vero-atomic-rpc-relayer-bridge";

const bridge = new AtomicRpcRelayerBridge({
  endpoints: [
    { url: "http://rpc1.example.com", priority: 10 },
    { url: "http://rpc2.example.com", priority: 9 },
  ],
  timeoutMs: 5000,
  maxRetries: 3,
  requireAtomicVerification: true,
});

// Relay a request
const response = await bridge.relay({
  id: "req-123",
  method: "POST",
  endpoint: "/",
  payload: { jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 },
  timestamp: Date.now(),
});

// Access audit trail
const auditLog = bridge.getAuditLog();
```

**Options:**
- `endpoints`: Array of RPC endpoints with priority weights
- `timeoutMs`: Request timeout in milliseconds (default: 5000)
- `maxRetries`: Maximum retry attempts per endpoint (default: 3)
- `requireAtomicVerification`: Enable cross-endpoint verification (default: true)

**Methods:**
- `relay(request)`: Atomically relay a request; returns `BridgeResponse`
- `getAuditLog()`: Return array of all relayed request/response pairs
- `clearAuditLog()`: Wipe the audit log

#### Response Schema

```typescript
interface BridgeResponse {
  requestId: string;        // Echo of the request ID
  success: boolean;         // Whether the relay succeeded
  data?: unknown;           // Response payload (if success)
  error?: string;           // Error message (if failed)
  endpointUsed: string;     // URL of the RPC endpoint that succeeded
  latencyMs: number;        // Round-trip time in milliseconds
  timestamp: number;        // Unix timestamp of the response
}
```

### HTTP Server (`local-server`)

When running the local HTTP server, the following endpoints are available:

#### `GET /health`

Health check. Returns immediately.

**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "atomic-rpc-relayer-bridge"
}
```

#### `GET /metrics`

Current relayer metrics (nonce, failed TX count, etc.). Requires bearer token if `AUTH_TOKEN` is set.

**Request:**
```
GET /metrics
Authorization: Bearer <AUTH_TOKEN>  (optional if AUTH_TOKEN is not set)
```

**Response (200 OK):**
```json
[
  {
    "address": "GLOCALDEVRELAYER",
    "nonce": 102,
    "failedTxCount": 0,
    "timestamp": 1692921600000
  }
]
```

**Response (401 Unauthorized):** If `AUTH_TOKEN` is set and the header is missing or invalid.

#### `GET /audit-log`

Full audit trail of all relayed requests and responses. Requires bearer token if `AUTH_TOKEN` is set.

**Request:**
```
GET /audit-log
Authorization: Bearer <AUTH_TOKEN>  (optional if AUTH_TOKEN is not set)
```

**Response (200 OK):**
```json
[
  {
    "requestId": "req-123",
    "success": true,
    "data": { "result": "0x1a2b3c" },
    "endpointUsed": "http://rpc1.example.com",
    "latencyMs": 145,
    "timestamp": 1692921600000
  },
  {
    "requestId": "req-124",
    "success": false,
    "error": "All endpoints failed",
    "endpointUsed": "none",
    "latencyMs": 15000,
    "timestamp": 1692921610000
  }
]
```

## Docker Integration

The bridge is containerized for use in the full vero-audit-guard pipeline. See the root [`docker-compose.yml`](../docker-compose.yml) for service configuration.

### Build Docker Image

```bash
docker build -t vero-atomic-rpc-relayer-bridge:latest .
```

### Run in Docker

```bash
docker run \
  -p 8545:8545 \
  -e BRIDGE_ENDPOINTS="http://rpc.example.com" \
  -e RELAYER_ADDRESS="GXYZ..." \
  vero-atomic-rpc-relayer-bridge:latest
```

See the `.env.example` and [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for Docker Compose orchestration details.

## Atomic Verification Trade-offs

### Security (Default)

By default, `requireAtomicVerification` is `true`. The bridge cross-checks responses against a secondary endpoint before returning to the caller.

**Guarantees:**
- Single RPC endpoint cannot falsify responses
- Requires ≥2 configured endpoints

**Trade-off:**
- Latency increases (extra round-trip to secondary endpoint)
- Availability depends on all endpoints being responsive

### Performance (Opt-in)

Set `DISABLE_ATOMIC_VERIFICATION=true` to skip cross-endpoint verification.

**Guarantees:**
- Lower latency (single round-trip)
- Higher availability (only requires one endpoint)

**Trade-off:**
- A compromised RPC endpoint can return arbitrary data
- Relayer must trust the configured endpoint implicitly
- **NOT recommended for production**

**Startup Behavior:**
If atomic verification is disabled, the bridge logs:
```
[atomic-rpc-relayer-bridge] WARNING: atomic verification is disabled; responses from a single RPC endpoint will be trusted without a secondary cross-check
```

## Testing

Run the test suite:

```bash
npm test
```

Tests cover:
- Request relaying and failover logic
- Atomic verification cross-checks
- Endpoint priority ordering
- Audit log tracking
- HTTP server endpoints and authentication

## Integration with Vero Audit Guard

The `atomic-rpc-relayer-bridge` is part of the larger vero-audit-guard monitoring stack:

- **Scanner Engine** — Static analysis of Soroban/Rust contracts
- **Anomaly Detector** — Polls the bridge `/metrics` endpoint to detect relayer anomalies
- **Audit Guard** — Policy as Code enforcement on GitHub PRs
- **Verifiable Audit Trail** — Anchors audit reports to the Stellar ledger

See the root [`README.md`](../README.md) for the full architecture and [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the Docker Compose workflow.

## Security Considerations

1. **Endpoint Vetting** — Configure only trusted RPC providers in `BRIDGE_ENDPOINTS`. A malicious endpoint can still perform timing attacks or leak metadata.
2. **Bearer Token** — If running the HTTP server in a shared environment, always set `AUTH_TOKEN` to restrict access to `/metrics` and `/audit-log`.
3. **Atomic Verification** — Keep `DISABLE_ATOMIC_VERIFICATION=false` unless you have explicitly validated the RPC endpoint and accept the trust assumptions.
4. **Audit Logging** — In production, consider exporting the audit log periodically for external analysis (e.g., SIEM integration).

## Troubleshooting

### Bridge Reports "All endpoints failed"

1. Verify endpoint URLs are correct and accessible:
   ```bash
   curl http://rpc-endpoint-url/health
   ```

2. Check firewall and network rules allow outbound connections to RPC endpoints.

3. Verify the request payload is valid JSON (if POST).

### Atomic Verification Fails

1. Confirm both endpoints are returning consistent data:
   ```bash
   curl -X POST http://rpc1 -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   curl -X POST http://rpc2 -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   ```

2. Check for timing issues: ensure secondary endpoint is responsive within the `timeoutMs` window.

3. If endpoints legitimately differ, consider disabling verification (with caution) or adding a third endpoint for consensus.

### High Latency with Atomic Verification Enabled

The bridge makes two RPC calls per request (primary + secondary verification). If this latency is unacceptable for your use case:

1. Use faster/closer RPC endpoints
2. Increase `timeoutMs` to allow slower endpoints more time
3. Consider disabling atomic verification **only after security review** (set `DISABLE_ATOMIC_VERIFICATION=true`)

## Contributing

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for guidelines on submitting issues, PRs, and local development workflows.

## License

MIT (see [`../LICENSE`](../LICENSE))
