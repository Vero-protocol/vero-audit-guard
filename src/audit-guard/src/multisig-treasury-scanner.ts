/**
 * Multisig Treasury Governance Scanner
 *
 * Audits Rust/Soroban contract source for multi-sig treasury governance
 * anti-patterns: weak thresholds, timelock bypasses, hardcoded signers,
 * missing signer validation, admin key overrides, and no-op auth checks.
 *
 * Design follows the same conventions as the other audit-guard modules:
 *  - A primary class with a `scan()` method returning a typed result
 *  - A `generateReport()` method rendering a human-readable markdown summary
 *  - Pure computation (no I/O, no global state) so it is trivially testable
 *  - Explicit input validation with structured error propagation
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type GovernanceSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface GovernanceFinding {
  file: string;
  line: number;
  rule: string;
  severity: GovernanceSeverity;
  snippet: string;
  description: string;
}

export interface MultisigTreasuryScanResult {
  status: "SAFE" | "VULNERABILITIES_FOUND";
  findings: GovernanceFinding[];
  totalFiles: number;
  filesScanned: string[];
  summary: string;
  scanTimestamp: string;
}

export interface MultisigScanOptions {
  minThreshold?: number;
  minTimelockSeconds?: number;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MIN_THRESHOLD = 2;
const DEFAULT_MIN_TIMELOCK_SECONDS = 0;

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<GovernanceSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

export class MultisigTreasuryScanner {
  private readonly minThreshold: number;
  private readonly minTimelockSeconds: number;

  constructor(options: MultisigScanOptions = {}) {
    this.minThreshold = options.minThreshold ?? DEFAULT_MIN_THRESHOLD;
    this.minTimelockSeconds = options.minTimelockSeconds ?? DEFAULT_MIN_TIMELOCK_SECONDS;
  }

  /**
   * Scan source content for multi-sig treasury governance anti-patterns.
   *
   * @throws Error if source or filename is empty/null/undefined
   */
  public scan(source: string, filename: string): MultisigTreasuryScanResult {
    this.validateInput(source, filename);

    const findings = this.detectFindings(source, filename);

    const status: MultisigTreasuryScanResult["status"] =
      findings.length > 0 ? "VULNERABILITIES_FOUND" : "SAFE";

    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = findings.filter((f) => f.severity === "HIGH").length;
    const summary =
      findings.length === 0
        ? "✅ No multi-sig treasury governance vulnerabilities detected"
        : `❌ ${findings.length} finding(s): ${criticalCount} CRITICAL, ${highCount} HIGH`;

    return {
      status,
      findings,
      totalFiles: 1,
      filesScanned: [filename],
      summary,
      scanTimestamp: new Date().toISOString(),
    };
  }

  /**
   * Render a human-readable markdown report from a scan result.
   */
  public generateReport(result: MultisigTreasuryScanResult): string {
    const emoji = result.status === "SAFE" ? "✅" : "❌";
    let report = `## ${emoji} Multi-Sig Treasury Governance Audit\n\n`;
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `**Files:** ${result.totalFiles}  |  **Findings:** ${result.findings.length}\n\n`;
    report += `${result.summary}\n\n`;

    if (result.findings.length > 0) {
      report += "---\n\n";
      report += "### 🚨 Findings\n\n";
      const sorted = [...result.findings].sort(
        (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
      );
      for (const f of sorted) {
        report += `- **${f.rule}** [${f.severity}] in \`${f.file}:${f.line}\`\n`;
        report += `  ${f.description}\n`;
        report += `  _Snippet:_ \`${f.snippet.replace(/`/g, "'")}\`\n\n`;
      }
    }

    return report;
  }

  // -------------------------------------------------------------------------
  // Private: input validation
  // -------------------------------------------------------------------------

  private validateInput(source: string, filename: string): void {
    if (source == null || typeof source !== "string" || source.trim() === "") {
      throw new Error("MultisigTreasuryScanner.scan: source must be a non-empty string");
    }
    if (filename == null || typeof filename !== "string" || filename.trim() === "") {
      throw new Error("MultisigTreasuryScanner.scan: filename must be a non-empty string");
    }
  }

  // -------------------------------------------------------------------------
  // Private: detection engine
  // -------------------------------------------------------------------------

  private detectFindings(source: string, filename: string): GovernanceFinding[] {
    const findings: GovernanceFinding[] = [];
    const lines = source.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!trimmed) continue;

      this.checkWithdrawalPattern(findings, filename, i + 1, trimmed);
      this.checkThresholdPattern(findings, filename, i + 1, trimmed);
      this.checkTimelockPattern(findings, filename, i + 1, trimmed);
      this.checkHardcodedSigner(findings, filename, i + 1, trimmed);
      this.checkSignerValidation(findings, filename, i + 1, trimmed);
      this.checkAdminOverride(findings, filename, i + 1, trimmed);
      this.checkUnprotectedThresholdChange(findings, filename, i + 1, trimmed);
      this.checkNoopAuthCheck(findings, filename, i + 1, trimmed);
    }

    return findings;
  }

  private checkWithdrawalPattern(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const withdrawRe = /\bwithdraw\b/;
    const transferRe = /\btransfer\b/;
    const sigRe = /\bsign\b|\bsigner\b|\bthreshold\b/;

    if (withdrawRe.test(content) && transferRe.test(content) && !sigRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "UNSAFE_SINGLE_SIG_WITHDRAWAL",
        severity: "CRITICAL",
        snippet: content,
        description: "Withdrawal function lacks explicit multi-sig authorization check",
      });
    }
  }

  private checkThresholdPattern(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const thresholdRe = /(?:threshold|m)\s*=\s*1\b|const\s+M\s*:\s*u32\s*=\s*1/;
    const nRe = /N\s*=\s*1\b/;

    if (thresholdRe.test(content) || nRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "WEAK_THRESHOLD",
        severity: "HIGH",
        snippet: content,
        description: "Multi-sig threshold is set to 1, effectively disabling multi-sig protection",
      });
    }
  }

  private checkTimelockPattern(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const timelockRe = /timelock\s*=\s*0\b|delay\s*=\s*0\b|ZERO_DURATION|Duration::ZERO/;
    if (timelockRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "TIMELOCK_BYPASS",
        severity: "HIGH",
        snippet: content,
        description: "Timelock or delay is zero, allowing immediate execution without waiting period",
      });
    }
  }

  private checkHardcodedSigner(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const hardcodedRe =
      /\bpub\s+key\s*:\s*PublicKey\b|hardcoded|const\s+ADMIN\s*:|const\s+OWNER\s*:/;
    if (hardcodedRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "HARDCODED_SIGNER",
        severity: "MEDIUM",
        snippet: content,
        description:
          "Signer or admin key appears hardcoded instead of using configurable multi-sig set",
      });
    }
  }

  private checkSignerValidation(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const bypassRe =
      /signers\.len\s*\(\)\s*>=?\s*1\b|signers\.count\s*\(\)\s*>=?\s*1\b|require!\s*\(\s*signers\s*\.\s*len\s*\(\)\s*>=\s*1/;
    if (bypassRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "MISSING_SIGNER_VALIDATION",
        severity: "HIGH",
        snippet: content,
        description:
          "Signer count is validated against a hardcoded minimum of 1 instead of the configured threshold",
      });
    }
  }

  private checkAdminOverride(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const adminRe = /\badmin\.(?:withdraw|transfer)\b|\bauthority\.transfer\b/;
    if (adminRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "ADMIN_KEY_OVERRIDE",
        severity: "CRITICAL",
        snippet: content,
        description:
          "Admin or authority key can bypass multi-sig requirements for transfers",
      });
    }
  }

  private checkUnprotectedThresholdChange(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const setThresholdRe = /(?:set|update|change)_threshold\s*\(/;
    if (setThresholdRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "UNPROTECTED_THRESHOLD_CHANGE",
        severity: "HIGH",
        snippet: content,
        description:
          "Threshold change function lacks multi-sig confirmation requirement",
      });
    }
  }

  private checkNoopAuthCheck(
    findings: GovernanceFinding[],
    file: string,
    line: number,
    content: string
  ): void {
    const noopRe = /require!\s*\(\s*true\s*\)|assert!\s*\(\s*true\s*\)|if\s+true\s*\{/;
    if (noopRe.test(content)) {
      findings.push({
        file,
        line,
        rule: "NOOP_AUTH_CHECK",
        severity: "HIGH",
        snippet: content,
        description: "Authorization check is a no-op (always true), bypassing security logic",
      });
    }
  }
}

export default MultisigTreasuryScanner;
