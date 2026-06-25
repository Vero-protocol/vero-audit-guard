/**
 * Logic Error Detector
 *
 * Issue #16: feat: add logic error detection
 *
 * Scans a code snippet for common logic bugs by running each pattern in
 * the pattern library against the input. Findings are aggregated and
 * returned as a `LogicScanResult` with an overall status and a list of
 * `LogicFlawFinding`s — one per detected issue, with line numbers and
 * remediation guidance.
 *
 * The detector itself is a thin orchestrator; all of the actual
 * heuristics live in `logic-patterns.ts` so they can be unit-tested and
 * composed individually.
 */

import { LOGIC_PATTERNS, LogicPattern, DetectionContext } from "./logic-patterns";

export type LogicSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** A single logic-bug finding. */
export interface LogicFlawFinding {
  file?: string;
  /** 1-indexed line number within the scanned snippet. */
  line?: number;
  snippet: string;
  ruleId: string;
  severity: LogicSeverity;
  message: string;
  remediation: string;
}

/** Aggregated result of a scan. */
export interface LogicScanResult {
  /** SAFE = no findings; VULNERABLE = at least one finding. */
  status: "SAFE" | "VULNERABLE";
  findings: LogicFlawFinding[];
  count: number;
  summary: string;
  scanTimestamp: string;
  /** Optional snapshot of the patterns that ran (ids). Useful for triage. */
  patternIds: string[];
}

/** Options accepted by `LogicErrorDetector.scan`. */
export interface LogicScanOptions {
  file?: string;
  /** Restrict scanning to a subset of pattern ids. */
  patterns?: string[];
}

const SEVERITY_RANK: Record<LogicSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * The detector runs every pattern by default; callers may restrict
 * to a subset via `options.patterns`. The detector is intentionally
 * pure — no I/O, no side effects.
 */
export class LogicErrorDetector {
  private readonly patterns: LogicPattern[];

  constructor(patterns: LogicPattern[] = LOGIC_PATTERNS as LogicPattern[]) {
    this.patterns = patterns;
  }

  /**
   * Scan a snippet and produce an aggregated result.
   * Returns `status: "SAFE"` if no findings fire.
   */
  public scan(code: string, options: LogicScanOptions = {}): LogicScanResult {
    if (typeof code !== "string") {
      throw new Error("LogicErrorDetector.scan: code must be a string");
    }

    const active = options.patterns
      ? this.patterns.filter((p) => options.patterns!.includes(p.id))
      : this.patterns;

    const context: DetectionContext = {
      file: options.file,
      lines: code.split(/\r?\n/),
    };

    const findings: LogicFlawFinding[] = [];
    for (const pattern of active) {
      try {
        const result = pattern.detect(code, context) ?? [];
        for (const f of result) findings.push(f);
      } catch (err) {
        // A buggy pattern must not poison the whole scan — skip and log.
        // eslint-disable-next-line no-console
        console.warn(
          `[LogicErrorDetector] pattern ${pattern.id} threw: ${(err as Error).message}`
        );
      }
    }

    // Sort by severity (CRITICAL first) then by line number.
    findings.sort((a, b) => {
      const sa = SEVERITY_RANK[a.severity] ?? 0;
      const sb = SEVERITY_RANK[b.severity] ?? 0;
      if (sa !== sb) return sb - sa;
      const la = a.line ?? 0;
      const lb = b.line ?? 0;
      return la - lb;
    });

    const status: LogicScanResult["status"] =
      findings.length === 0 ? "SAFE" : "VULNERABLE";

    const summary =
      status === "SAFE"
        ? "✅ No logic flaws detected"
        : `❌ ${findings.length} logic-flaw finding(s) — review before merging`;

    return {
      status,
      findings,
      count: findings.length,
      summary,
      scanTimestamp: new Date().toISOString(),
      patternIds: active.map((p) => p.id),
    };
  }

  /** Render a markdown report for humans. */
  public generateReport(result: LogicScanResult): string {
    const emoji = result.status === "SAFE" ? "✅" : "❌";
    let report = `## ${emoji} Logic Error Scan\n\n`;
    if (result.findings.length > 0 && result.findings[0].file) {
      report += `**File:** \`${result.findings[0].file}\`\n\n`;
    }
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `${result.summary}\n\n`;
    report += `**Patterns evaluated:** ${result.patternIds.length}\n\n`;

    if (result.findings.length === 0) {
      return report;
    }

    report += `### ❌ Findings\n\n`;
    for (const f of result.findings) {
      const lineLabel = f.line ? `(line ${f.line})` : "";
      report += `- **${f.ruleId}** [${f.severity}] ${lineLabel}\n`;
      report += `  ${f.message}\n`;
      report += `  \`\`\`\n  ${f.snippet}\n  \`\`\`\n`;
      report += `  _Remediation:_ ${f.remediation}\n\n`;
    }
    return report;
  }

  /** Get the patterns this detector runs (read-only). */
  public get patternIds(): string[] {
    return this.patterns.map((p) => p.id);
  }
}

export default LogicErrorDetector;
