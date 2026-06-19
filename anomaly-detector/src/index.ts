/**
 * Vero Anomaly Detector
 * Monitors the vero-relayer-service for:
 *   - Nonce spike anomalies
 *   - Failed transaction bursts
 *   - Unauthorized address interactions
 *   - Threat feed matches
 */
import * as fs from "fs";
import * as path from "path";

import { ThreatFeedFetcher } from "./audit-guard/threat-feed-fetcher";

export const threatFetcher = new ThreatFeedFetcher();

export interface RelayerMetrics {
  address: string;
  nonce: number;
  failedTxCount: number;
  timestamp: number;
}

export interface AnomalyAlert {
  type: "NONCE_SPIKE" | "FAILED_TX_BURST" | "UNAUTHORIZED_ADDRESS" | "THREAT_FEED_MATCH";
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

  setInterval(async () => {
    try {
      await threatFetcher.updateFeed();
    } catch (err) {
      console.error("[anomaly-detector] Threat feed update error:", (err as Error).message);
    }

    try {
      const metrics = await fetchMetrics();
      await runOnce(metrics);
    } catch (err) {
      console.error("[anomaly-detector] Fetch error:", (err as Error).message);
    }
  }, POLL_INTERVAL_MS);
}

if (require.main === module) {
  monitor();
}
