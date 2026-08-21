/**
 * Vero Anomaly Detector
 * Monitors the vero-relayer-service for:
 *   - Nonce spike anomalies
 *   - Failed transaction bursts
 *   - Unauthorized address interactions
 *   - Threat feed matches
 *   - RPC node health
 *
 * VAG-012: Telemetry ingestion is protected by a token-bucket rate limiter and
 * a bounded drop-oldest queue so that burst traffic cannot exhaust memory or
 * delay anomaly processing.  This layer is STRICTLY OBSERVATIONAL — it has no
 * authority to halt, pause, or block on-chain operations.
 */
import * as fs from "fs";
import { performance } from "perf_hooks";
import { sendAlert } from "../../src/audit-guard/src/webhook";
import * as path from "path";
import {
  TelemetryIngestionGuard,
  TelemetryEvent,
} from "../../src/audit-guard/src/telemetry-ingestion-guard";

import { ThreatFeedFetcher } from "./audit-guard/threat-feed-fetcher";
import { RpcFailoverMonitor } from "./rpc-failover-monitor";

// ---------------------------------------------------------------------------
// VAG-012: module-level ingestion guard — env-configurable, observational only
// ---------------------------------------------------------------------------
const metricsIngestionGuard = new TelemetryIngestionGuard({
  bucketCapacity: Number(process.env["TELEMETRY_BUCKET_CAPACITY"] ?? 200),
  refillRatePerSecond: Number(process.env["TELEMETRY_REFILL_RATE_PER_SEC"] ?? 100),
  maxQueueDepth: Number(process.env["TELEMETRY_MAX_QUEUE_DEPTH"] ?? 1000),
  sourceName: "anomaly-detector",
});

interface NodeStatus {
  url: string;
  healthy: boolean;
  lastChecked: number;
  responseTime?: number;
}

class NodeHealthChecker {
  private nodes: NodeStatus[];
  private currentNodeIndex: number;
  private failoverCallbacks: Array<(oldUrl: string, newUrl: string) => void>;

  constructor(nodeUrls: string[]) {
    this.nodes = nodeUrls.map((url) => ({
      url,
      healthy: true,
      lastChecked: Date.now(),
    }));
    this.currentNodeIndex = 0;
    this.failoverCallbacks = [];
  }

  addFailoverCallback(callback: (oldUrl: string, newUrl: string) => void): void {
    this.failoverCallbacks.push(callback);
  }

  getCurrentNode(): string {
    return this.nodes[this.currentNodeIndex].url;
  }

  async checkHealth(): Promise<NodeStatus[]> {
    const axios = await import("axios");
    const results: NodeStatus[] = [];

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const startTime = performance.now();

      try {
        await axios.default.post(
          node.url,
          { jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 },
          { timeout: 3000 }
        );

        node.healthy = true;
        node.responseTime = performance.now() - startTime;
      } catch {
        node.healthy = false;
        node.responseTime = undefined;
      }

      node.lastChecked = Date.now();
      results.push({ ...node });
    }

    if (!this.nodes[this.currentNodeIndex].healthy) {
      const newIndex = this.nodes.findIndex(
        (n, idx) => idx !== this.currentNodeIndex && n.healthy
      );

      if (newIndex !== -1) {
        const oldUrl = this.nodes[this.currentNodeIndex].url;
        const newUrl = this.nodes[newIndex].url;
        this.currentNodeIndex = newIndex;
        this.failoverCallbacks.forEach((cb) => cb(oldUrl, newUrl));
      }
    }

    return results;
  }
}

export { metricsIngestionGuard };
export const threatFetcher = new ThreatFeedFetcher();

export interface RelayerMetrics {
  address: string;
  nonce: number;
  failedTxCount: number;
  timestamp: number;
}

export interface AnomalyAlert {
  type: "NONCE_SPIKE" | "FAILED_TX_BURST" | "UNAUTHORIZED_ADDRESS" | "THREAT_FEED_MATCH" | "NONCE_REUSE" | "RELAYER_LATENCY_HIGH";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  address?: string;
  detail: string;
  timestamp: number;
}

const AUTHORIZED_ADDRESSES = new Set<string>(
  (process.env.AUTHORIZED_ADDRESSES ?? "").split(",").filter(Boolean)
);

const NONCE_SPIKE_THRESHOLD = Number(process.env.NONCE_SPIKE_THRESHOLD ?? 50);
const FAILED_TX_THRESHOLD = Number(process.env.FAILED_TX_THRESHOLD ?? 10);
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS ?? 5000);

const RPC_NODE_URLS = (process.env.RPC_NODE_URLS ?? "").split(",").filter(Boolean);

const nodeHealthChecker = RPC_NODE_URLS.length > 0
  ? new NodeHealthChecker(RPC_NODE_URLS)
  : null;

const rpcFailoverMonitor = RPC_NODE_URLS.length > 0
  ? new RpcFailoverMonitor()
  : null;

const DB_PATH = path.join(__dirname, "nonce-db.json");
const previousNonces = new Map<string, number>(loadNonces());
const alerts: AnomalyAlert[] = [];

// Dashboard dispatch — lightweight inline bridge to avoid cross-package import issues.
// The full AnomalyAlertDispatcher lives in src/audit-guard/src/anomaly-alert-dispatcher.ts
// and is the canonical implementation for the audit-guard module.
async function dispatchToDashboard(alert: AnomalyAlert): Promise<void> {
  const dashUrl = process.env.GUARDIAN_DASH_URL;
  if (!dashUrl) return;
  const dashToken = process.env.GUARDIAN_DASH_TOKEN ?? "";
  try {
    const axios = await import("axios");
    await axios.default.post(
      dashUrl,
      {
        source: "anomaly-detector",
        type: alert.type,
        severity: alert.severity,
        message: `[${alert.type}] ${alert.address} — ${alert.detail}`,
        detail: alert.detail,
        timestamp: new Date(alert.timestamp).toISOString(),
        metadata: {
          address: alert.address ?? null,
          anomalyType: alert.type,
          originalTimestamp: alert.timestamp,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${dashToken}`,
          "Content-Type": "application/json",
        },
        timeout: 5000,
      }
    );
  } catch (err) {
    console.error(
      "[anomaly-detector] Dashboard dispatch failed:",
      (err as Error).message
    );
  }
}

function loadNoncesFrom(dbPath: string): Record<string, number> {
  try {
    const data = fs.readFileSync(dbPath, "utf-8");
    const obj = JSON.parse(data) as Record<string, number>;
    return obj && typeof obj === "object" ? obj : {};
  } catch {
    return {};
  }
}

function loadNonces(): [string, number][] {
  return Object.entries(loadNoncesFrom(DB_PATH));
}

function lockPathFor(dbPath: string): string {
  return `${dbPath}.lock`;
}

function acquireNonceDbLock(dbPath: string, timeoutMs = 5000): string {
  const lockDir = lockPathFor(dbPath);
  const start = Date.now();
  while (true) {
    try {
      fs.mkdirSync(lockDir);
      return lockDir;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw err;
      if (Date.now() - start > timeoutMs) {
        throw new Error(
          `Timed out after ${timeoutMs}ms waiting for nonce-db lock: ${lockDir}`
        );
      }
      const waitUntil = Date.now() + 10;
      while (Date.now() < waitUntil) {
        /* brief spin before retry */
      }
    }
  }
}

function releaseNonceDbLock(lockDir: string): void {
  try {
    fs.rmdirSync(lockDir);
  } catch {
    // Best-effort unlock; next writer may recover after timeout.
  }
}

function atomicWriteJson(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  const tmp = path.join(
    dir,
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`
  );
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf-8");
  try {
    fs.renameSync(tmp, filePath);
  } catch {
    // Windows cannot rename over an existing file; replace then rename.
    try {
      fs.unlinkSync(filePath);
    } catch {
      /* file may not exist */
    }
    fs.renameSync(tmp, filePath);
  }
}

/**
 * Lock-protected read-modify-write for nonce state (Issue #307).
 * Merges local updates with on-disk state (per-address max nonce) so
 * concurrent writers cannot clobber each other, then atomically replaces
 * the db file via temp + rename.
 */
export function persistNonceMap(
  dbPath: string,
  local: Record<string, number>
): Record<string, number> {
  const lockDir = acquireNonceDbLock(dbPath);
  try {
    const onDisk = loadNoncesFrom(dbPath);
    const merged: Record<string, number> = { ...onDisk };

    for (const [addr, nonce] of Object.entries(local)) {
      const existing = merged[addr];
      merged[addr] =
        existing === undefined ? nonce : Math.max(existing, nonce);
    }

    atomicWriteJson(dbPath, merged);
    return merged;
  } finally {
    releaseNonceDbLock(lockDir);
  }
}

function saveNonces(): void {
  const local: Record<string, number> = {};
  for (const [addr, nonce] of previousNonces.entries()) {
    local[addr] = nonce;
  }
  const merged = persistNonceMap(DB_PATH, local);
  previousNonces.clear();
  for (const [addr, nonce] of Object.entries(merged)) {
    previousNonces.set(addr, nonce);
  }
}

function analyze(metrics: RelayerMetrics[]): AnomalyAlert[] {
  const detected: AnomalyAlert[] = [];

  for (const m of metrics) {
    const prevNonce = previousNonces.get(m.address) ?? m.nonce;
    // Nonce reuse detection
    if (previousNonces.has(m.address) && m.nonce <= prevNonce) {
      detected.push({
        type: "NONCE_REUSE",
        severity: "HIGH",
        address: m.address,
        detail: `Nonce reuse detected (prev: ${prevNonce}, now: ${m.nonce})`,
        timestamp: m.timestamp,
      });
    }
    const nonceDelta = m.nonce - prevNonce;
    if (nonceDelta > NONCE_SPIKE_THRESHOLD) {
      detected.push({
        type: "NONCE_SPIKE",
        severity: nonceDelta > NONCE_SPIKE_THRESHOLD * 2 ? "CRITICAL" : "HIGH",
        address: m.address,
        detail: `Nonce jumped by ${nonceDelta} (prev: ${prevNonce}, now: ${m.nonce})`,
        timestamp: m.timestamp,
      });
    }
    previousNonces.set(m.address, m.nonce);

    // Failed transaction burst
    if (m.failedTxCount >= FAILED_TX_THRESHOLD) {
      detected.push({
        type: "FAILED_TX_BURST",
        severity: m.failedTxCount >= FAILED_TX_THRESHOLD * 3 ? "CRITICAL" : "HIGH",
        address: m.address,
        detail: `${m.failedTxCount} failed transactions detected`,
        timestamp: m.timestamp,
      });
    }

    // Unauthorized address
    if (AUTHORIZED_ADDRESSES.size > 0 && !AUTHORIZED_ADDRESSES.has(m.address)) {
      detected.push({
        type: "UNAUTHORIZED_ADDRESS",
        severity: "HIGH",
        address: m.address,
        detail: `Address not in authorized set`,
        timestamp: m.timestamp,
      });
    }

    // Threat feed match
    if (threatFetcher.isThreat(m.address)) {
      detected.push({
        type: "THREAT_FEED_MATCH",
        severity: "CRITICAL",
        address: m.address,
        detail: `Address matches active blocklist in threat feed (last updated: ${threatFetcher.getLastUpdated()?.toISOString() ?? "never"})`,
        timestamp: m.timestamp,
      });
    }
  }

    saveNonces();
    return detected;
}

async function fetchMetrics(): Promise<RelayerMetrics[]> {
  const url = process.env.RELAYER_METRICS_URL;
  if (!url) return [];

  const axios = await import("axios");
  const { data } = await axios.default.get<RelayerMetrics[]>(url, { timeout: 4000 });
  return data;
}

function emit(alert: AnomalyAlert): void {
  alerts.push(alert);
  const line = `[ALERT][${alert.severity}][${alert.type}] ${alert.address} — ${alert.detail}`;
  console.error(line);
  // Dispatch to Guardian Dashboard (non-blocking, observational-only)
  dispatchToDashboard(alert).catch((err) => {
    console.error("[anomaly-detector] Dashboard dispatch failed:", (err as Error).message);
  });
  // In production: forward to PagerDuty / Slack webhook via env var ALERT_WEBHOOK_URL
}

/** Reset internal state — for testing only. */
export function resetState(): void {
  previousNonces.clear();
  alerts.length = 0;
  metricsIngestionGuard._reset();
}

export async function runOnce(metrics: RelayerMetrics[]): Promise<AnomalyAlert[]> {
  // VAG-012: run each metrics item through the ingestion guard before
  // processing.  Rate-limited or malformed items are surfaced as alerts and
  // skipped — this is observational only and does NOT affect on-chain state.
  const accepted: RelayerMetrics[] = [];
  let rateLimitedCount = 0;
  let malformedCount = 0;

  for (const m of metrics) {
    const event: TelemetryEvent = {
      id: `${m.address}-${m.timestamp}`,
      timestamp: new Date(m.timestamp).toISOString(),
      payload: m,
    };
    const result = metricsIngestionGuard.ingest(event);
    if (result.outcome === "ACCEPTED" || result.outcome === "QUEUE_FULL_DROP") {
      accepted.push(m);
    } else if (result.outcome === "RATE_LIMITED") {
      rateLimitedCount += 1;
    } else if (result.outcome === "MALFORMED") {
      malformedCount += 1;
    }
  }

  if (rateLimitedCount > 0) {
    console.warn(
      `[anomaly-detector][VAG-012] ${rateLimitedCount} metric(s) RATE_LIMITED at ingestion boundary — ` +
        `tokens_remaining=${metricsIngestionGuard.tokensAvailable} queue=${metricsIngestionGuard.queueDepth}`
    );
  }
  if (malformedCount > 0) {
    console.error(
      `[anomaly-detector][VAG-012] ${malformedCount} malformed metric event(s) rejected at ingestion boundary`
    );
  }

  const found = analyze(accepted);
  found.forEach(emit);
  return found;
}

async function monitor(): Promise<void> {
  console.log("[anomaly-detector] Starting Vero Relayer monitor...");
  
  try {
    await threatFetcher.updateFeed();
  } catch (err) {
    console.error("[anomaly-detector] Initial threat feed update failed:", (err as Error).message);
  }

  if (nodeHealthChecker) {
    nodeHealthChecker.addFailoverCallback((oldUrl, newUrl) => {
      console.error(`[node-health] Failover triggered: ${oldUrl} → ${newUrl}`);
      void sendAlert({
        repository: "relayer",
        alert: `Node failover: ${oldUrl} → ${newUrl}`,
        timestamp: new Date().toISOString(),
      });
      if (rpcFailoverMonitor) {
        const event = rpcFailoverMonitor.recordFailover(oldUrl, newUrl);
        console.log(`[rpc-failover-monitor] Failover latency: ${event.latencyMs}ms`);
        if (event.slowFailover) {
          console.warn(`[rpc-failover-monitor] WARNING: Slow failover detected (${event.latencyMs}ms > threshold)`);
        }
      }
    });

    const initialStatus = await nodeHealthChecker.checkHealth();
    console.log("[node-health] Initial node status:", initialStatus);
  }

      setInterval(async () => {
        try {
          await threatFetcher.updateFeed();
        } catch (err) {
          console.error("[anomaly-detector] Threat feed update error:", (err as Error).message);
        }

        try {
          if (nodeHealthChecker) {
            const statuses = await nodeHealthChecker.checkHealth();
            console.log("[node-health] Node statuses:", statuses);
            if (rpcFailoverMonitor) {
              for (const status of statuses) {
                rpcFailoverMonitor.recordCheck(status.url, status.healthy);
              }
              const degraded = rpcFailoverMonitor.getDegradedEndpoints();
              if (degraded.length > 0) {
                console.warn("[rpc-failover-monitor] Degraded endpoints:", degraded);
              }
              rpcFailoverMonitor.buildReport();
            }
          }
        } catch (err) {
          console.error("[node-health] Check error:", (err as Error).message);
        }

        try {
          const start = performance.now();
          const metrics = await fetchMetrics();
          await runOnce(metrics);
          const duration = performance.now() - start;
          const thresholdMs = Number(process.env.RELAYER_LATENCY_THRESHOLD_MS ?? 2000);
          if (duration > thresholdMs) {
            void sendAlert({
              repository: "relayer",
              alert: `Relayer latency high: ${Math.round(duration)}ms`,
              timestamp: new Date().toISOString(),
            });
            // Also dispatch to dashboard channel
            dispatchToDashboard({
              type: "RELAYER_LATENCY_HIGH",
              severity: "HIGH",
              detail: `Relayer latency high: ${Math.round(duration)}ms (threshold: ${thresholdMs}ms)`,
              timestamp: Date.now(),
            }).catch((err) => {
              console.error("[anomaly-detector] Dashboard latency alert dispatch failed:", (err as Error).message);
            });
          }
          // VAG-012: surface rate-limit pressure as a log alert each poll cycle
          metricsIngestionGuard.logStatus();
        } catch (err) {
          console.error("[anomaly-detector] Fetch error:", (err as Error).message);
        }
      }, POLL_INTERVAL_MS);
}

if (require.main === module) {
  monitor();
}
