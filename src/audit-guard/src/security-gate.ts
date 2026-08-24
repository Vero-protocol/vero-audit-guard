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

/**
 * Mirrors the GovernanceFinding struct emitted by multisig_scanner.rs.
 * Governance findings carry the same severity levels as plain findings and
 * must be evaluated by the security gate identically.
 */
export interface GovernanceFinding {
  file: string;
  line: number;
  rule: string;
  severity: string;
  snippet?: string;
  description?: string;
}

export interface ScannerReport {
  target: string;
  total_files?: number;
  findings: ScannerFinding[];
  /** Governance/multisig findings emitted by scanner-engine's multisig_scanner module. */
  governance_findings?: GovernanceFinding[];
  report_hash?: string;
}

export interface SecurityGateResult {
  passed: boolean;
  threshold: number;
  totalFindings: number;
  blockingFindings: ScannerFinding[];
  blockingGovernanceFindings: GovernanceFinding[];
  summary: string;
  error?: string;
}

function hasAnalyzedTarget(target: unknown): target is string {
  if (typeof target !== "string") return false;

  const normalizedTarget = target.trim();
  return normalizedTarget !== "" && normalizedTarget !== "N/A";
}

function invalidTargetResult(
  threshold: number,
  findings: ScannerFinding[],
  governanceFindings: GovernanceFinding[]
): SecurityGateResult {
  const blockingFindings = findings.filter((finding) =>
    isBlockingSeverity(finding.severity, threshold)
  );
  const blockingGovernanceFindings = governanceFindings.filter((finding) =>
    isBlockingSeverity(finding.severity, threshold)
  );

  return {
    passed: false,
    threshold,
    totalFindings: findings.length + governanceFindings.length,
    blockingFindings,
    blockingGovernanceFindings,
    summary: "Build blocked — scan report target is missing or analysis was skipped.",
    error: "INVALID_REPORT",
  };
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
  const governanceFindings = report.governance_findings ?? [];

  // Keep direct programmatic callers fail-closed as well as JSON callers.
  if (!hasAnalyzedTarget(report.target)) {
    return invalidTargetResult(threshold, findings, governanceFindings);
  }

  const blockingFindings = findings.filter((finding) =>
    isBlockingSeverity(finding.severity, threshold)
  );

  // Governance findings carry the same severity model as plain findings and
  // must be evaluated identically — a CRITICAL governance rule (e.g.
  // UNSAFE_SINGLE_SIG_WITHDRAWAL) must block the build just as a CRITICAL
  // static-analysis finding does.
  const blockingGovernanceFindings = governanceFindings.filter((finding) =>
    isBlockingSeverity(finding.severity, threshold)
  );

  const totalBlocking = blockingFindings.length + blockingGovernanceFindings.length;

  if (totalBlocking > 0) {
    return {
      passed: false,
      threshold,
      totalFindings: findings.length + governanceFindings.length,
      blockingFindings,
      blockingGovernanceFindings,
      summary: `Build blocked — ${totalBlocking} finding(s) exceed severity threshold (${threshold}).`,
    };
  }

  const totalFindings = findings.length + governanceFindings.length;
  return {
    passed: true,
    threshold,
    totalFindings,
    blockingFindings: [],
    blockingGovernanceFindings: [],
    summary:
      totalFindings === 0
        ? "Security gate passed — no findings."
        : `Security gate passed — ${totalFindings} finding(s) within threshold.`,
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
      blockingGovernanceFindings: [],
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
      blockingGovernanceFindings: [],
      summary: "Build blocked — scan report is missing a findings array.",
      error: "INVALID_REPORT",
    };
  }

  if (!hasAnalyzedTarget(report.target)) {
    return invalidTargetResult(
      threshold,
      report.findings,
      Array.isArray(report.governance_findings) ? report.governance_findings : []
    );
  }

  return evaluateSecurityGate(report, threshold);
}
