/**
 * OPA Policy Engine
 * Evaluates Rego policies against PR data
 */

import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { SecurityTip, SECURITY_TIPS } from "./security-tips";
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
  security_tip?: SecurityTip;
  maintenance_alert?: string;
}

/**
 * Evaluates PR data against OPA policies
 */
export class PolicyEngine {
  private policiesDir: string;
  private opaAvailable: boolean = false;

  constructor(policiesDir?: string) {
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
    let result: EvaluationResult;

    if (!this.opaAvailable) {
      result = await this.evaluateWithoutOPA(prData);
    } else {
      try {
        result = await this.evaluateWithOPA(prData);
      } catch (error) {
        console.error("[PolicyEngine] OPA evaluation failed:", error);
        result = await this.evaluateWithoutOPA(prData);
      }
    }

    // Add security tip to result
    result.security_tip = this.getSecurityTip(prData);
    return result;
  }

  /**
   * Evaluate using OPA CLI
   */
  private async evaluateWithOPA(prData: PRData): Promise<EvaluationResult> {
    const tempInput = path.join("/tmp", `opa-input-${Date.now()}.json`);
    fs.writeFileSync(tempInput, JSON.stringify(prData, null, 2));

    try {
      const command = `opa eval -d ${this.policiesDir} -i ${tempInput} \
        -b 'data.pr.compliance.deny' \
        -b 'data.pr.compliance.warning' \
        -b 'data.pr.compliance.compliance_summary'`;

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
    const violations: PolicyViolation[] = [];
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
    const violations: PolicyViolation[] = opaOutput.result?.[0]?.bindings
      ?.deny || [];
    const warnings: PolicyViolation[] = opaOutput.result?.[0]?.bindings
      ?.warning || [];
    const summary = opaOutput.result?.[0]?.bindings?.compliance_summary?.[0] || {};

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
   * Generate markdown report
   */
  generateReport(result: EvaluationResult): string {
    let report = "";

    // Header
    const emoji =
      result.status === "COMPLIANT"
        ? "✅"
        : result.status === "WARNING"
          ? "⚠️"
          : "❌";
    report += `## ${emoji} Policy Compliance Check\n\n`;
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

    // Security Training tip
    if (result.security_tip) {
      report += "---\n";
      report += `### 🎓 Security Training: ${result.security_tip.title}\n\n`;
      report += `${result.security_tip.content}\n\n`;
    }

    // Compliance tip
    if (result.violations.length === 0) {
      report += "---\n";
      report +=
        "_All mandatory compliance checks passed. Review warnings to ensure best practices._\n";
    }

    return report;
  }
}

export default PolicyEngine;
