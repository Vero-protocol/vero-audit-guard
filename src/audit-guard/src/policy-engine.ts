/**
 * OPA Policy Engine
 * Evaluates Rego policies against PR data
 */

import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import DashboardClient from "./dashboard-client";

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
   * Evaluate PR data against policies
   */
  async evaluate(prData: PRData): Promise<EvaluationResult> {
    if (!this.opaAvailable) {
      return this.evaluateWithoutOPA(prData);
    }

    try {
      return await this.evaluateWithOPA(prData);
    } catch (error) {
      console.error("[PolicyEngine] OPA evaluation failed:", error);
      return this.evaluateWithoutOPA(prData);
    }
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
    report += `**Status:** ${result.status}\n\n`;

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
