/**
 * OPA Policy Engine
 * Evaluates Rego policies against PR data
 */

import { execSync } from "child_process";
import { Keypair } from "@stellar/stellar-sdk";
import * as fs from "fs";
import * as path from "path";
import OverflowChecker, { OverflowFinding } from "./overflow-checker";
import { SECURITY_TIPS, SecurityTip } from "./security-tips";
import { getNextReportVersion } from "./report-version";
import { DashboardClient } from "./dashboard-client";
import { sendAlert } from "./webhook";


export interface PRData {
  pull_request: {
    title: string;
    body: string;
    labels: string[];
    base_branch: string;
    head_branch: string;
    number: number;
    author: string;
  };
  files_modified: string[];
  file_contents?: Record<string, string>;
  additions: number;
  deletions: number;
  dependencies_added?: Array<{
    name: string;
    version: string;
    is_dev_dependency?: boolean;
  }>;
  dependencies_updated?: Array<{
    name: string;
    current_version: string;
    latest_version: string;
  }>;
  relayer?: string;
  signature?: string;
  timestamp?: number;
  maintenance_mode?: boolean;
  maintenance_message?: string;
}

export interface PolicyViolation {
  rule: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  detail: string;
}

export interface EvaluationResult {
  status: "COMPLIANT" | "NON_COMPLIANT" | "WARNING";
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  summary: string;
  violations_count: number;
  warnings_count: number;
  high_severity_violations: PolicyViolation[];
  overflow_findings?: OverflowFinding[];
  maintenance_alert?: string;
  anchored_tx?: string;
  security_tip?: SecurityTip;
}

/**
 * Evaluates PR data against OPA policies
 */
export class PolicyEngine {
  private policiesDir: string;
  private opaAvailable: boolean = false;
  private overflowChecker: OverflowChecker;

  constructor(policiesDir?: string) {
    this.overflowChecker = new OverflowChecker();
    this.policiesDir =
      policiesDir ||
      path.join(__dirname, "..", "policies");
    this.checkOpaAvailability();
  }

  /**
   * Check if OPA CLI is available
   */
  private checkOpaAvailability(): void {
    try {
      execSync("opa version", { stdio: "ignore" });
      this.opaAvailable = true;
      console.log("[PolicyEngine] OPA CLI available");
    } catch (e) {
      console.warn(
        "[PolicyEngine] OPA CLI not found. Policy evaluation requires 'opa' command."
      );
      this.opaAvailable = false;
    }
  }

  /**
   * Select a relevant security tip based on PR data
   */
  private getSecurityTip(prData: PRData): SecurityTip {
    const bodyLower = prData.pull_request.body.toLowerCase();
    const titleLower = prData.pull_request.title.toLowerCase();
    const allText = `${titleLower} ${bodyLower}`;

    // Map keywords to tip IDs
    const keywordMap: Record<string, string[]> = {
      SEC_TIP_SECRET_MGMT: ["secret", "key", "token", "password", "aws_access", "credential"],
      SEC_TIP_DEP_SECURITY: ["dependency", "package", "npm", "yarn", "lockfile", "version"],
      SEC_TIP_INPUT_VAL: ["input", "sanitize", "validate", "xss", "injection", "query"],
      SEC_TIP_AUTH_N_AUTHZ: ["auth", "login", "oauth", "jwt", "session"],
      SEC_TIP_LEAST_PRIV: ["permission", "access", "role", "grant", "policy", "admin"],
      SEC_TIP_SEC_COMM: ["https", "ssl", "tls", "encrypt", "certificate", "protocol"],
      SEC_TIP_ERR_HANDLING: ["error", "exception", "catch", "stacktrace", "debug"],
      SEC_TIP_DATA_MIN: ["sensitive", "data", "privacy", "pii", "collection"]
    };

    // Find first matching tip
    for (const [tipId, keywords] of Object.entries(keywordMap)) {
      if (keywords.some(kw => allText.includes(kw))) {
        const tip = SECURITY_TIPS.find(t => t.id === tipId);
        if (tip) return tip;
      }
    }

    // Default: Random tip or rotate based on PR number
    const index = prData.pull_request.number % SECURITY_TIPS.length;
    return SECURITY_TIPS[index];
  }

  /**
   * Evaluate PR data against policies
   */
  async evaluate(prData: PRData): Promise<EvaluationResult> {
    // Run overflow checker on modified files
    const overflowFindings = await this.overflowChecker.checkFiles(
      prData.files_modified
    );

    // Enrich PR data with overflow findings for OPA
    const enrichedPrData = {
      ...prData,
      overflow_findings: overflowFindings,
    };

    if (!this.opaAvailable) {
      const result = await this.evaluateWithoutOPA(enrichedPrData);
      result.overflow_findings = overflowFindings;
      return result;
    }

    try {
      const result = await this.evaluateWithOPA(enrichedPrData);
      result.overflow_findings = overflowFindings;
      return result;
    } catch (error) {
      console.error("[PolicyEngine] OPA evaluation failed:", error);
      const result = await this.evaluateWithoutOPA(enrichedPrData);
      result.overflow_findings = overflowFindings;
      return result;
    }
  }

  /**
   * Evaluate using OPA CLI
   */
  private async evaluateWithOPA(prData: PRData): Promise<EvaluationResult> {
    const tempInput = path.join("/tmp", `opa-input-${Date.now()}.json`);
    fs.writeFileSync(tempInput, JSON.stringify(prData, null, 2));

    try {
      // Use more robust OPA query that doesn't fail if a package is missing
      const query = `
        deny := data.pr.compliance.deny | data.pr.dependencies.deny | data.pr.crypto.deny;
        warning := data.pr.compliance.warning | data.pr.dependencies.warning;
        summary := data.pr.compliance.compliance_summary;
        result := {"deny": deny, "warning": warning, "summary": summary}
      `;

      const command = `opa eval -d ${this.policiesDir} -i ${tempInput} '${query}'`;

      const output = execSync(command).toString();
      const result = JSON.parse(output);

      return this.parseOPAResult(result);
    } finally {
      fs.unlinkSync(tempInput);
    }
  }

  /**
   * Evaluate without OPA CLI (fallback implementation)
   */
  private async evaluateWithoutOPA(prData: PRData): Promise<EvaluationResult> {
    const violations: PolicyViolation[] = [...this.verifyRelayerSignature(prData)];
    const warnings: PolicyViolation[] = [];

    // PR Title checks
    if (prData.pull_request.title === "") {
      violations.push({
        rule: "PR_TITLE_EMPTY",
        severity: "MEDIUM",
        message: "❌ PR title cannot be empty",
        detail: "Provide a clear, descriptive title for the PR",
      });
    }

    if (prData.pull_request.title.length < 10) {
      violations.push({
        rule: "PR_TITLE_TOO_SHORT",
        severity: "MEDIUM",
        message: "❌ PR title is too short",
        detail: `Title '${prData.pull_request.title}' is less than 10 characters`,
      });
    }

    // PR Description checks
    if (prData.pull_request.body === "") {
      violations.push({
        rule: "PR_DESCRIPTION_MISSING",
        severity: "HIGH",
        message: "❌ PR description is required",
        detail:
          "Provide a detailed description of changes, security implications, and testing",
      });
    } else {
      const bodyLower = prData.pull_request.body.toLowerCase();
      if (!bodyLower.includes("test")) {
        warnings.push({
          rule: "PR_TESTING_UNDOCUMENTED",
          severity: "MEDIUM",
          message: "⚠️  PR testing not documented",
          detail: "Describe how you tested these changes",
        });
      }

      // Breaking changes check
      if (
        bodyLower.includes("breaking") &&
        !prData.pull_request.labels.includes("breaking-change")
      ) {
        violations.push({
          rule: "BREAKING_CHANGE_NOT_LABELED",
          severity: "HIGH",
          message: "❌ Breaking changes must be labeled",
          detail: "Add 'breaking-change' label if this PR contains breaking changes",
        });
      }

      // Security-sensitive changes check
      const securityKeywords = [
        "auth",
        "crypto",
        "signature",
        "key",
        "secret",
        "token",
        "vulnerability",
      ];
      const hasSensitiveContent = securityKeywords.some((kw) =>
        bodyLower.includes(kw)
      );
      if (
        hasSensitiveContent &&
        !prData.pull_request.labels.includes("security") &&
        !prData.pull_request.labels.includes("audit")
      ) {
        warnings.push({
          rule: "SECURITY_CHANGE_NEEDS_LABEL",
          severity: "HIGH",
          message: "⚠️  Security-sensitive changes detected",
          detail:
            "Add 'security' or 'audit' label for changes involving auth, crypto, keys",
        });
      }

      // Changelog check
      if (
        !prData.pull_request.labels.includes("trivial") &&
        !prData.pull_request.labels.includes("docs") &&
        !bodyLower.includes("changelog")
      ) {
        warnings.push({
          rule: "CHANGELOG_NOT_UPDATED",
          severity: "MEDIUM",
          message: "⚠️  Changelog should be updated",
          detail:
            "For non-trivial changes, update CHANGELOG.md or mention changelog in PR",
        });
      }
    }

    // Crypto security checks
    const bannedAlgorithms = [
      {
        name: "MD5",
        pattern: /md5['"(]|md5$/i,
        message: "MD5 is cryptographically broken and should not be used for security purposes.",
      },
      {
        name: "SHA1",
        pattern: /sha1['"(]|sha1$/i,
        message: "SHA-1 is no longer considered secure against well-funded opponents.",
      },
      {
        name: "RC4",
        pattern: /rc4['"(]|rc4$/i,
        message: "RC4 is insecure and has many known vulnerabilities.",
      },
      {
        name: "DES",
        pattern: /des['"(]|des$/i,
        message: "DES has a small key size and can be brute-forced easily.",
      },
    ];

    if (prData.file_contents) {
      for (const [filename, content] of Object.entries(prData.file_contents)) {
        for (const algo of bannedAlgorithms) {
          if (algo.pattern.test(content)) {
            violations.push({
              rule: "INSECURE_CRYPTO_ALGORITHM",
              severity: "CRITICAL",
              message: `❌ Insecure crypto algorithm '${algo.name}' detected in ${filename}`,
              detail: `${algo.message} Use modern alternatives like SHA-256, SHA-3, or AES.`,
            });
          }
        }
      }
    }

    // Large change checks
    if (prData.files_modified.length > 20) {
      warnings.push({
        rule: "TOO_MANY_FILES_MODIFIED",
        severity: "MEDIUM",
        message: `⚠️  Many files modified (${prData.files_modified.length})`,
        detail: "Consider breaking this into smaller, focused PRs",
      });
    }

    const totalChanges = prData.additions + prData.deletions;
    if (totalChanges > 1000) {
      warnings.push({
        rule: "LARGE_DIFF_REQUIRES_JUSTIFICATION",
        severity: "MEDIUM",
        message: `⚠️  Large changeset (${totalChanges} lines)`,
        detail:
          "Break large changes into smaller PRs for easier review",
      });
    }

    // Overflow findings (for fallback evaluation)
    const overflowFindings = (prData as any).overflow_findings || [];
    for (const finding of overflowFindings) {
      violations.push({
        rule: finding.rule,
        severity: finding.severity,
        message: finding.message,
        detail: `${finding.detail} (at ${finding.file}:${finding.line})`,
      });
    }

    // Long title warning
    if (prData.pull_request.title.length > 100) {
      warnings.push({
        rule: "PR_TITLE_TOO_LONG",
        severity: "LOW",
        message: "ℹ️  PR title is long",
        detail: `Consider shortening title from ${prData.pull_request.title.length} characters`,
      });
    }

    const status =
      violations.length > 0
        ? "NON_COMPLIANT"
        : warnings.length > 0
          ? "WARNING"
          : "COMPLIANT";

    const high_severity_violations = violations.filter(
      (v) =>
        v.severity === "CRITICAL" ||
        v.severity === "HIGH"
    );

    const summary =
      violations.length === 0 && warnings.length === 0
        ? "✅ All compliance checks passed!"
        : `${violations.length > 0 ? `❌ ${violations.length} violation(s)` : ""} ${warnings.length > 0 ? `⚠️  ${warnings.length} warning(s)` : ""}`;

    return {
      status,
      violations,
      warnings,
      summary: summary.trim(),
      violations_count: violations.length,
      warnings_count: warnings.length,
      high_severity_violations,
    };
  }

  /**
   * Parse OPA eval output
   */
  private parseOPAResult(opaOutput: any): EvaluationResult {
    const bindings = opaOutput.result?.[0]?.bindings?.result || {};
    const violations: PolicyViolation[] = bindings.deny || [];
    const warnings: PolicyViolation[] = bindings.warning || [];
    const summary = bindings.summary?.[0] || {};

    const high_severity_violations = violations.filter(
      (v) =>
        v.severity === "CRITICAL" ||
        v.severity === "HIGH"
    );

    return {
      status: summary.status || "COMPLIANT",
      violations,
      warnings,
      summary: summary.message || "✅ All compliance checks passed!",
      violations_count: violations.length,
      warnings_count: warnings.length,
      high_severity_violations,
    };
  }

  /**
   * Reports evaluation result to the Guardian Dashboard
   */
  async reportToDashboard(
    result: EvaluationResult,
    prData: PRData
  ): Promise<void> {
    const dashUrl = process.env.GUARDIAN_DASH_URL;
    const dashToken = process.env.GUARDIAN_DASH_TOKEN || "";

    if (!dashUrl) {
      return;
    }

    const client = new DashboardClient(dashUrl, dashToken);
    const alerts: Promise<boolean>[] = [];

    // Report violations
    for (const v of result.violations) {
      alerts.push(
        client.sendAlert({
          source: "audit-guard",
          type: v.rule,
          severity: v.severity,
          message: v.message,
          detail: v.detail,
          timestamp: new Date().toISOString(),
          metadata: {
            pr_number: prData.pull_request.number,
            pr_author: prData.pull_request.author,
            pr_title: prData.pull_request.title,
            status: result.status,
          },
        })
      );
    }

    // Report warnings if they are high severity
    for (const w of result.warnings) {
      if (w.severity === "HIGH" || w.severity === "CRITICAL") {
        alerts.push(
          client.sendAlert({
            source: "audit-guard",
            type: w.rule,
            severity: w.severity,
            message: w.message,
            detail: w.detail,
            timestamp: new Date().toISOString(),
            metadata: {
              pr_number: prData.pull_request.number,
              pr_author: prData.pull_request.author,
              pr_title: prData.pull_request.title,
              status: result.status,
            },
          })
        );
      }
    }

    await Promise.all(alerts);
  }

  /**
   * Generate markdown report
   */
  generateReport(result: EvaluationResult): string {
    let report = "";

    // Maintenance Mode Notice
    if (process.env.MAINTENANCE_MODE === "true") {
      const msg =
        process.env.MAINTENANCE_MESSAGE ||
        "System undergoing maintenance. Compliance checks may be delayed.";
      report += `> 🛠️ **MAINTENANCE NOTICE:** ${msg}\n\n`;
    }

    // Header
    const emoji =
      result.status === "COMPLIANT"
        ? "✅"
        : result.status === "WARNING"
          ? "⚠️"
          : "❌";
    report += `## ${emoji} Policy Compliance Check\n\n`;
    report += `### Report Version: ${getNextReportVersion()}\n\n`;
    report += `**Status:** ${result.status}\n\n`;

    // Maintenance Alert
    if (result.maintenance_alert) {
      report += `> [!IMPORTANT]\n`;
      report += `> ### 🚧 MAINTENANCE NOTICE\n`;
      report += `> ${result.maintenance_alert}\n\n`;
      // Send alert via webhook
      void sendAlert({
        repository: "unknown",
        alert: result.maintenance_alert,
        timestamp: new Date().toISOString(),
      });
    }

    // Summary
    report += `${result.summary}\n\n`;

    // Violations
    if (result.violations.length > 0) {
      report += "### ❌ Violations\n\n";
      for (const violation of result.violations) {
        report += `- **${violation.rule}** [${violation.severity}]\n`;
        report += `  ${violation.message}\n`;
        report += `  _${violation.detail}_\n\n`;
      }
    }

    // Warnings
    if (result.warnings.length > 0) {
      report += "### ⚠️  Warnings\n\n";
      for (const warning of result.warnings) {
        report += `- **${warning.rule}** [${warning.severity}]\n`;
        report += `  ${warning.message}\n`;
        report += `  _${warning.detail}_\n\n`;
      }
    }

    // Anchoring info
    if (result.anchored_tx) {
      report += "### 🔗 Immutable Audit Trail\n\n";
      report += `This audit report has been anchored to the Stellar ledger for immutability.\n`;
      report += `**Transaction Hash:** \`${result.anchored_tx}\`\n\n`;
    }

    // Compliance tip
    if (result.violations.length === 0) {
      report += "---\n";
      report +=
        "_All mandatory compliance checks passed. Review warnings to ensure best practices._\n";
    }

    // Security Training Tip
    if (result.security_tip) {
      report += "\n---\n";
      report += `### 🎓 Security Training\n\n`;
      report += `**${result.security_tip.title}**\n\n`;
      report += `${result.security_tip.content}\n`;
    }

    return report;
  }

  /**
   * Verify the relayer signature and timestamp
   */
  private verifyRelayerSignature(prData: PRData): PolicyViolation[] {
    const violations: PolicyViolation[] = [];

    // 1. Check if signature fields are present
    if (!prData.relayer || !prData.signature || !prData.timestamp) {
      violations.push({
        rule: "RELAYER_SIGNATURE_MISSING",
        severity: "CRITICAL",
        message: "❌ Relayer signature missing",
        detail: "PR data must be signed by an authorized relayer",
      });
      return violations;
    }

    // 2. Check if relayer is authorized
    const authorizedRelayers = (process.env.AUTHORIZED_ADDRESSES || "").split(",").filter(Boolean);
    if (authorizedRelayers.length === 0) {
      violations.push({
        rule: "RELAYER_UNAUTHORIZED",
        severity: "CRITICAL",
        message: "❌ Relayer not authorized",
        detail: "No authorized relayers configured in AUTHORIZED_ADDRESSES environment variable",
      });
    } else if (!authorizedRelayers.includes(prData.relayer)) {
      violations.push({
        rule: "RELAYER_UNAUTHORIZED",
        severity: "CRITICAL",
        message: "❌ Relayer not authorized",
        detail: `The relayer address '${prData.relayer}' is not in the authorized set`,
      });
    }

    // 3. Check timestamp (5-minute window)
    const FIVE_MINUTES_MS = 5 * 60 * 1000;
    const now = Date.now();
    if (Math.abs(now - prData.timestamp) > FIVE_MINUTES_MS) {
      violations.push({
        rule: "RELAYER_SIGNATURE_EXPIRED",
        severity: "CRITICAL",
        message: "❌ Relayer signature expired",
        detail: `Signature timestamp (${new Date(prData.timestamp).toISOString()}) is outside the 5-minute window`,
      });
    }

    // 4. Verify cryptographic signature
    try {
      const payload = this.getSignaturePayload(prData);
      const keypair = Keypair.fromPublicKey(prData.relayer);
      const isValid = keypair.verify(Buffer.from(payload), Buffer.from(prData.signature, "hex"));

      if (!isValid) {
        violations.push({
          rule: "RELAYER_SIGNATURE_INVALID",
          severity: "CRITICAL",
          message: "❌ Invalid relayer signature",
          detail: "The cryptographic signature does not match the PR data payload",
        });
      }
    } catch (e) {
      violations.push({
        rule: "RELAYER_SIGNATURE_INVALID",
        severity: "CRITICAL",
        message: "❌ Invalid relayer signature",
        detail: `Signature verification failed: ${(e as Error).message}`,
      });
    }

    return violations;
  }

  /**
   * Get the payload used for signature verification
   */
  private getSignaturePayload(prData: PRData): string {
    // Create a stable copy of prData without signature fields
    const payloadData = {
      pull_request: prData.pull_request,
      files_modified: prData.files_modified,
      additions: prData.additions,
      deletions: prData.deletions,
      dependencies_added: prData.dependencies_added,
      dependencies_updated: prData.dependencies_updated,
      relayer: prData.relayer,
      timestamp: prData.timestamp,
    };

    // Use deterministic stringification
    // Note: For production use, a library like 'fast-json-stable-stringify' is recommended.
    return JSON.stringify(payloadData);
  }
}

export default PolicyEngine;
