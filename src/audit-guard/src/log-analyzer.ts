/**
 * Log Anomaly Detector
 * Analyzes relayer logs for error patterns and spikes
 */

export interface LogEntry {
  timestamp: string; // ISO 8601
  level: "info" | "warn" | "error" | "fatal";
  message: string;
  service?: string;
}

export interface LogAnomaly {
  type: "ERROR_PATTERN" | "ERROR_SPIKE";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  timestamp: string;
  count?: number;
}

export interface LogAnalyzerConfig {
  errorThreshold: number; // Number of errors to trigger a spike
  windowMs: number; // Time window for spike detection
}

const DEFAULT_CONFIG: LogAnalyzerConfig = {
  errorThreshold: 5,
  windowMs: 60000, // 1 minute
};

export class LogAnalyzer {
  private config: LogAnalyzerConfig;

  constructor(config: Partial<LogAnalyzerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Analyzes a batch of logs for anomalies
   */
  analyze(logs: LogEntry[]): LogAnomaly[] {
    const anomalies: LogAnomaly[] = [];
    if (logs.length === 0) return [];

    // Sort logs by timestamp just in case
    const sortedLogs = [...logs].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    // 1. Detect individual error patterns
    const errorLogs = sortedLogs.filter(
      (log) => log.level === "error" || log.level === "fatal"
    );

    for (const log of errorLogs) {
      if (log.level === "fatal") {
        anomalies.push({
          type: "ERROR_PATTERN",
          severity: "CRITICAL",
          message: `Fatal error detected: ${log.message}`,
          timestamp: log.timestamp,
        });
      } else {
        // High severity for specific keywords even if level is just 'error'
        const isCritical = /panic|crash|security|unauthorized|vulnerability/i.test(
          log.message
        );
        anomalies.push({
          type: "ERROR_PATTERN",
          severity: isCritical ? "CRITICAL" : "HIGH",
          message: `Error pattern detected: ${log.message}`,
          timestamp: log.timestamp,
        });
      }
    }

    // 2. Detect error spikes
    if (errorLogs.length >= this.config.errorThreshold) {
      for (let i = 0; i <= errorLogs.length - this.config.errorThreshold; i++) {
        const windowStart = new Date(errorLogs[i].timestamp).getTime();
        const windowEnd = windowStart + this.config.windowMs;

        let countInWindow = 0;
        for (let j = i; j < errorLogs.length; j++) {
          if (new Date(errorLogs[j].timestamp).getTime() <= windowEnd) {
            countInWindow++;
          } else {
            break;
          }
        }

        if (countInWindow >= this.config.errorThreshold) {
          anomalies.push({
            type: "ERROR_SPIKE",
            severity: countInWindow >= this.config.errorThreshold * 2 ? "CRITICAL" : "HIGH",
            message: `Detected spike of ${countInWindow} errors in ${this.config.windowMs / 1000}s`,
            timestamp: errorLogs[i].timestamp,
            count: countInWindow,
          });
          // Skip forward to avoid duplicate alerts for the same spike
          i += countInWindow - 1;
        }
      }
    }

    return anomalies;
  }
}

export default LogAnalyzer;
