/**
 * Nonce Anomaly Watcher
 *
 * Issue #148: Real-time Anomaly Detection for Relayer Nonces
 *
 * Compares engine-stored nonces against on-chain transaction data in real time.
 * Triggers low-latency alerts when nonce deviation exceeds threshold.
 */

import { sendAlert } from "../src/webhook";
import * as fs from "fs";
import * as path from "path";

export interface NonceState {
  accountId: string;
  engineNonce: number;
  chainNonce: number;
  lastSyncedLedger: number;
  driftCount: number;
  maxDrift: number;
  updatedAt: number;
}

export interface NonceAnomalyAlert {
  accountId: string;
  engineNonce: number;
  chainNonce: number;
  drift: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  timestamp: number;
  ledgerNumber: number;
}

const DRIFT_WARNING_THRESHOLD = 2;
const DRIFT_CRITICAL_THRESHOLD = 10;
const SYNC_INTERVAL_MS = 30_000; // 30 seconds
const MAX_DRIFT_HISTORY = 100;

export class NonceAnomalyWatcher {
  private states: Map<string, NonceState> = new Map();
  private alertHistory: NonceAnomalyAlert[] = [];
  private syncTimer: NodeJS.Timeout | null = null;
  private chainDataProvider: ChainDataProvider;

  constructor(chainDataProvider: ChainDataProvider) {
    this.chainDataProvider = chainDataProvider;
  }

  /** Start real-time monitoring loop */
  start(): void {
    console.log("[NonceWatcher] Starting real-time nonce monitoring...");
    this.syncTimer = setInterval(() => this.syncNonces(), SYNC_INTERVAL_MS);
    this.syncNonces(); // Initial sync
  }

  /** Stop monitoring */
  stop(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
    console.log("[NonceWatcher] Monitoring stopped.");
  }

  /** Register an engine-stored nonce for an account */
  registerEngineNonce(accountId: string, nonce: number): void {
    const existing = this.states.get(accountId);
    this.states.set(accountId, {
      accountId,
      engineNonce: nonce,
      chainNonce: existing?.chainNonce ?? nonce,
      lastSyncedLedger: existing?.lastSyncedLedger ?? 0,
      driftCount: existing?.driftCount ?? 0,
      maxDrift: existing?.maxDrift ?? 0,
      updatedAt: Date.now(),
    });
  }

  /** Synchronize nonces against on-chain data */
  async syncNonces(): Promise<void> {
    for (const [accountId, state] of this.states) {
      try {
        const chainState = await this.chainDataProvider.getChainNonce(accountId);
        const drift = Math.abs(state.engineNonce - chainState.nonce);

        if (drift > 0) {
          const severity = this.calculateSeverity(drift);
          const alert: NonceAnomalyAlert = {
            accountId,
            engineNonce: state.engineNonce,
            chainNonce: chainState.nonce,
            drift,
            severity,
            timestamp: Date.now(),
            ledgerNumber: chainState.ledgerNumber,
          };

          this.alertHistory.push(alert);
          if (this.alertHistory.length > MAX_DRIFT_HISTORY) {
            this.alertHistory.shift();
          }

          await this.triggerAlert(alert);

          // Update state
          state.chainNonce = chainState.nonce;
          state.lastSyncedLedger = chainState.ledgerNumber;
          state.driftCount++;
          state.maxDrift = Math.max(state.maxDrift, drift);
        }
      } catch (err) {
        console.error([NonceWatcher] Sync failed for :, err);
      }
    }
  }

  /** Calculate severity based on drift magnitude */
  private calculateSeverity(drift: number): NonceAnomalyAlert["severity"] {
    if (drift >= DRIFT_CRITICAL_THRESHOLD) return "CRITICAL";
    if (drift >= DRIFT_WARNING_THRESHOLD) return "HIGH";
    if (drift > 0) return "MEDIUM";
    return "LOW";
  }

  /** Trigger alert via webhook and log immutably */
  private async triggerAlert(alert: NonceAnomalyAlert): Promise<void> {
    console.error(
      [NonceWatcher] NONCE ANOMALY:  engine= chain= drift= severity=
    );

    // Send webhook alert
    try {
      await sendAlert({
        event: "nonce_anomaly",
        accountId: alert.accountId,
        drift: alert.drift,
        severity: alert.severity,
        engineNonce: alert.engineNonce,
        chainNonce: alert.chainNonce,
        ledgerNumber: alert.ledgerNumber,
        timestamp: new Date(alert.timestamp).toISOString(),
      });
    } catch (err) {
      console.error("[NonceWatcher] Alert dispatch failed:", err);
    }

    // Immutable audit log
    this.writeAuditLog(alert);
  }

  /** Write alert to immutable audit log */
  private writeAuditLog(alert: NonceAnomalyAlert): void {
    const logDir = path.join(process.cwd(), "reports");
    const logFile = path.join(logDir, "nonce-anomaly-log.jsonl");
    
    try {
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      const entry = JSON.stringify(alert) + "\n";
      fs.appendFileSync(logFile, entry, "utf-8");
    } catch (err) {
      console.error("[NonceWatcher] Audit log write failed:", err);
    }
  }

  /** Get recent alerts for an account */
  getAlerts(accountId: string, limit = 10): NonceAnomalyAlert[] {
    return this.alertHistory
      .filter((a) => a.accountId === accountId)
      .slice(-limit);
  }

  /** Get current state for an account */
  getState(accountId: string): NonceState | undefined {
    return this.states.get(accountId);
  }
}

/** Interface for chain data providers */
export interface ChainDataProvider {
  getChainNonce(accountId: string): Promise<{ nonce: number; ledgerNumber: number }>;
}
