/**
 * CI/CD Security Gate
 *
 * Evaluates scanner-engine JSON reports and fails builds when findings
 * exceed the configured severity threshold (default: block severity > 3).
 */

export type ScannerSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO";

/** Numeric rank aligned with LogicErrorDetector — higher is more severe. */
export const SEVERITY_RANK: Record<ScannerSeverity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** Block findings with rank strictly greater than this value (default: 3 → CRITICAL). */
export const DEFAULT_SEVERITY_THRESHOLD = 3;

export interface ScannerFinding {
  file: string;
  line: number;
  rule: string;
  severity: string;
  snippet?: string;
}

export interface ScannerReport {
  target: string;
  total_files?: number;
  findings: ScannerFinding[];
  report_hash?: string;
}

export interface SecurityGateResult {
  passed: boolean;
  threshold: number;
  totalFindings: number;
  blockingFindings: ScannerFinding[];
  summary: string;
  error?: string;
}

export function severityRank(severity: string): number | null {
  const normalized = severity.toUpperCase() as ScannerSeverity;
  return SEVERITY_RANK[normalized] ?? null;
}

export function isBlockingSeverity(
  severity: string,
  threshold: number = DEFAULT_SEVERITY_THRESHOLD
): boolean {
  const rank = severityRank(severity);
  if (rank === null) {
    return true;
  }
  return rank > threshold;
}

export function evaluateSecurityGate(
  report: ScannerReport,
  threshold: number = DEFAULT_SEVERITY_THRESHOLD
): SecurityGateResult {
  const findings = report.findings ?? [];
  const blockingFindings = findings.filter((finding) =>
    isBlockingSeverity(finding.severity, threshold)
  );

  if (blockingFindings.length > 0) {
    return {
      passed: false,
      threshold,
      totalFindings: findings.length,
      blockingFindings,
      summary: `Build blocked — ${blockingFindings.length} finding(s) exceed severity threshold (${threshold}).`,
    };
  }

  return {
    passed: true,
    threshold,
    totalFindings: findings.length,
    blockingFindings: [],
    summary:
      findings.length === 0
        ? "Security gate passed — no findings."
        : `Security gate passed — ${findings.length} finding(s) within threshold.`,
  };
}

export function evaluateSecurityGateFromJson(
  json: string,
  threshold: number = DEFAULT_SEVERITY_THRESHOLD
): SecurityGateResult {
  let report: ScannerReport;
  try {
    report = JSON.parse(json) as ScannerReport;
  } catch {
    return {
      passed: false,
      threshold,
      totalFindings: 0,
      blockingFindings: [],
      summary: "Build blocked — scan report is not valid JSON.",
      error: "INVALID_JSON",
    };
  }

  if (!Array.isArray(report.findings)) {
    return {
      passed: false,
      threshold,
      totalFindings: 0,
      blockingFindings: [],
      summary: "Build blocked — scan report is missing a findings array.",
      error: "INVALID_REPORT",
    };
  }

  return evaluateSecurityGate(report, threshold);
}
