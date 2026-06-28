/**
 * Vero Anomaly Detector
 * Monitors the vero-relayer-service for:
 *   - Nonce spike anomalies
 *   - Failed transaction bursts
 *   - Unauthorized address interactions
 *   - Threat feed matches
 *   - RPC node health
 */
import * as fs from "fs";
import { performance } from "perf_hooks";
import { sendAlert } from "../../src/audit-guard/src/webhook";
import * as path from "path";

import { ThreatFeedFetcher } from "./audit-guard/threat-feed-fetcher";
import { RpcFailoverMonitor } from "./rpc-failover-monitor";

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

export const threatFetcher = new ThreatFeedFetcher();

export interface RelayerMetrics {
  address: string;
  nonce: number;
  failedTxCount: number;
  timestamp: number;
}

export interface AnomalyAlert {
  type: "NONCE_SPIKE" | "FAILED_TX_BURST" | "UNAUTHORIZED_ADDRESS" | "THREAT_FEED_MATCH" | "NONCE_REUSE";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  address: string;
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

function loadNonces(): [string, number][] {
  try {
    const data = fs.readFileSync(DB_PATH, "utf-8");
    const obj = JSON.parse(data) as Record<string, number>;
    return Object.entries(obj);
  } catch {
    return [];
  }
}

function saveNonces(): void {
  const obj: Record<string, number> = {};
  for (const [addr, nonce] of previousNonces.entries()) {
    obj[addr] = nonce;
  }
  fs.writeFileSync(DB_PATH, JSON.stringify(obj, null, 2));
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
  // In production: forward to PagerDuty / Slack webhook via env var ALERT_WEBHOOK_URL
}

/** Reset internal state — for testing only. */
export function resetState(): void {
  previousNonces.clear();
  alerts.length = 0;
}

export async function runOnce(metrics: RelayerMetrics[]): Promise<AnomalyAlert[]> {
  const found = analyze(metrics);
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
          }
        } catch (err) {
          console.error("[anomaly-detector] Fetch error:", (err as Error).message);
        }
      }, POLL_INTERVAL_MS);
}

if (require.main === module) {
  monitor();
}
