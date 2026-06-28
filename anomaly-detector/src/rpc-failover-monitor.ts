import * as fs from "fs";
import * as path from "path";

const WINDOW_SIZE = Number(process.env.RPC_HEALTH_WINDOW ?? 100);
const LATENCY_THRESHOLD_MS = Number(process.env.RPC_FAILOVER_LATENCY_THRESHOLD_MS ?? 3000);
const SUCCESS_RATE_THRESHOLD = Number(process.env.RPC_SUCCESS_RATE_THRESHOLD ?? 0.8);

export interface FailoverEvent {
  fromUrl: string;
  toUrl: string;
  latencyMs: number;
  slowFailover: boolean;
  timestamp: number;
}

export interface EndpointStats {
  url: string;
  successRate: number;
  checksRecorded: number;
}

export interface FailoverReport {
  generatedAt: number;
  endpoints: EndpointStats[];
  events: FailoverEvent[];
  degradedEndpoints: string[];
}

export class RpcFailoverMonitor {
  private healthWindows: Map<string, boolean[]>;
  private firstFailureTimes: Map<string, number>;
  private failoverEvents: FailoverEvent[];
  private windowSize: number;

  constructor(windowSize: number = WINDOW_SIZE) {
    this.windowSize = windowSize;
    this.healthWindows = new Map();
    this.firstFailureTimes = new Map();
    this.failoverEvents = [];
  }

  recordCheck(url: string, healthy: boolean): void {
    if (!this.healthWindows.has(url)) {
      this.healthWindows.set(url, []);
    }
    const window = this.healthWindows.get(url)!;
    window.push(healthy);
    if (window.length > this.windowSize) {
      window.shift();
    }

    if (!healthy && !this.firstFailureTimes.has(url)) {
      this.firstFailureTimes.set(url, Date.now());
    } else if (healthy) {
      this.firstFailureTimes.delete(url);
    }
  }

  getSuccessRate(url: string): number {
    const window = this.healthWindows.get(url);
    if (!window || window.length === 0) return 1;
    const successes = window.filter(Boolean).length;
    return successes / window.length;
  }

  recordFailover(fromUrl: string, toUrl: string): FailoverEvent {
    const now = Date.now();
    const firstFailure = this.firstFailureTimes.get(fromUrl) ?? now;
    const latencyMs = now - firstFailure;
    const slowFailover = latencyMs > LATENCY_THRESHOLD_MS;

    const event: FailoverEvent = {
      fromUrl,
      toUrl,
      latencyMs,
      slowFailover,
      timestamp: now,
    };
    this.failoverEvents.push(event);
    return event;
  }

  getDegradedEndpoints(): string[] {
    const degraded: string[] = [];
    for (const url of this.healthWindows.keys()) {
      if (this.getSuccessRate(url) < SUCCESS_RATE_THRESHOLD) {
        degraded.push(url);
      }
    }
    return degraded;
  }

  buildReport(writeToFile: boolean = true): FailoverReport {
    const endpoints: EndpointStats[] = [];
    for (const [url, window] of this.healthWindows.entries()) {
      endpoints.push({
        url,
        successRate: this.getSuccessRate(url),
        checksRecorded: window.length,
      });
    }

    const degradedEndpoints = this.getDegradedEndpoints();

    const report: FailoverReport = {
      generatedAt: Date.now(),
      endpoints,
      events: [...this.failoverEvents],
      degradedEndpoints,
    };

    if (writeToFile) {
      const reportsDir = path.join(__dirname, "..", "..", "reports");
      try {
        if (!fs.existsSync(reportsDir)) {
          fs.mkdirSync(reportsDir, { recursive: true });
        }
        const filePath = path.join(reportsDir, "rpc-failover-report.json");
        fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
      } catch (err) {
        console.error("[rpc-failover-monitor] Failed to write report:", (err as Error).message);
      }
    }

    return report;
  }

  reset(): void {
    this.healthWindows.clear();
    this.firstFailureTimes.clear();
    this.failoverEvents = [];
  }
}
