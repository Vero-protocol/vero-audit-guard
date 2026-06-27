/**
 * Diff Engine for State Drift Detection
 * Compares current vs previous state to identify drift
 */

import * as fs from "fs";
import * as path from "path";

export interface DiffFinding {
  file: string;
  line?: number;
  rule?: string;
  severity?: string;
  snippet?: string;
}

export interface DiffReport {
  added: DiffFinding[];
  removed: DiffFinding[];
  modified: DiffFinding[];
  unchanged: DiffFinding[];
  drift_detected: boolean;
  drift_summary: string;
  current_hash?: string;
  previous_hash?: string;
}

export interface ScanReport {
  target?: string;
  total_files?: number;
  findings: DiffFinding[];
  report_hash?: string;
  [key: string]: any;
}

export class DiffEngine {
  private reportsDir: string;

  constructor(reportsDir?: string) {
    this.reportsDir = reportsDir || path.join(__dirname, "..", "reports");
  }

  /**
   * Compare current and previous scan reports
   */
  compare(current: ScanReport, previous: ScanReport | null): DiffReport {
    const result: DiffReport = {
      added: [],
      removed: [],
      modified: [],
      unchanged: [],
      drift_detected: false,
      drift_summary: "",
      current_hash: current.report_hash,
      previous_hash: previous?.report_hash,
    };

    if (!previous) {
      result.added = [...current.findings];
      result.drift_detected = current.findings.length > 0;
      result.drift_summary = `Initial scan: ${current.findings.length} finding(s) detected`;
      return result;
    }

    // Create maps for efficient lookup
    const currentMap = this.createFindingsMap(current.findings);
    const previousMap = this.createFindingsMap(previous.findings);

    // Find added findings (in current but not in previous)
    Array.from(currentMap.entries()).forEach(([key, finding]) => {
      if (!previousMap.has(key)) {
        result.added.push(finding);
      } else {
        const prevFinding = previousMap.get(key)!;
        if (this.isModified(finding, prevFinding)) {
          result.modified.push(finding);
        } else {
          result.unchanged.push(finding);
        }
      }
    });

    // Find removed findings (in previous but not in current)
    Array.from(previousMap.entries()).forEach(([key, finding]) => {
      if (!currentMap.has(key)) {
        result.removed.push(finding);
      }
    });

    // Determine drift
    result.drift_detected =
      result.added.length > 0 ||
      result.removed.length > 0 ||
      result.modified.length > 0;

    // Generate summary
    result.drift_summary = this.generateSummary(result);

    return result;
  }

  /**
   * Create a map key for a finding
   */
  private createFindingsKey(finding: DiffFinding): string {
    const parts = [
      finding.file || "",
      finding.line?.toString() || "",
      finding.rule || "",
    ];
    return parts.join(":");
  }

  /**
   * Create a map of findings for efficient lookup
   */
  private createFindingsMap(findings: DiffFinding[]): Map<string, DiffFinding> {
    const map = new Map<string, DiffFinding>();
    for (const finding of findings) {
      const key = this.createFindingsKey(finding);
      map.set(key, finding);
    }
    return map;
  }

  /**
   * Check if a finding has been modified
   */
  private isModified(current: DiffFinding, previous: DiffFinding): boolean {
    return (
      current.severity !== previous.severity ||
      current.snippet !== previous.snippet
    );
  }

  /**
   * Generate a human-readable summary
   */
  private generateSummary(result: DiffReport): string {
    const parts: string[] = [];

    if (!result.drift_detected) {
      return "✅ No drift detected - state matches previous scan";
    }

    if (result.added.length > 0) {
      parts.push(`+${result.added.length} new finding(s)`);
    }
    if (result.removed.length > 0) {
      parts.push(`-${result.removed.length} resolved finding(s)`);
    }
    if (result.modified.length > 0) {
      parts.push(`~${result.modified.length} modified finding(s)`);
    }

    return `⚠️ Drift detected: ${parts.join(", ")}`;
  }

  /**
   * Load previous report from disk
   */
  loadPreviousReport(reportPath?: string): ScanReport | null {
    const filePath = reportPath || path.join(this.reportsDir, "latest-scan.json");

    if (!fs.existsSync(filePath)) {
      return null;
    }

    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content) as ScanReport;
    } catch (error) {
      console.error("[DiffEngine] Failed to load previous report:", error);
      return null;
    }
  }

  /**
   * Save current report for future comparisons
   */
  saveCurrentReport(report: ScanReport, reportPath?: string): void {
    const filePath = reportPath || path.join(this.reportsDir, "latest-scan.json");

    // Ensure directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  }

  /**
   * Generate a markdown drift report
   */
  generateMarkdownReport(diff: DiffReport): string {
    let report = "## 📊 State Drift Analysis\n\n";
    report += `${diff.drift_summary}\n\n`;

    if (diff.current_hash) {
      report += `**Current Hash:** \`${diff.current_hash}\`\n`;
    }
    if (diff.previous_hash) {
      report += `**Previous Hash:** \`${diff.previous_hash}\`\n`;
    }
    report += "\n";

    if (diff.added.length > 0) {
      report += "### 🔴 New Findings\n\n";
      for (const finding of diff.added) {
        report += this.formatFinding(finding, "+");
      }
    }

    if (diff.removed.length > 0) {
      report += "### 🟢 Resolved Findings\n\n";
      for (const finding of diff.removed) {
        report += this.formatFinding(finding, "-");
      }
    }

    if (diff.modified.length > 0) {
      report += "### 🟡 Modified Findings\n\n";
      for (const finding of diff.modified) {
        report += this.formatFinding(finding, "~");
      }
    }

    if (!diff.drift_detected) {
      report += "### ✅ State Match\n\n";
      report += `All ${diff.unchanged.length} finding(s) remain unchanged.\n`;
    }

    return report;
  }

  /**
   * Format a single finding for markdown output
   */
  private formatFinding(finding: DiffFinding, prefix: string): string {
    let line = `- ${prefix} **${finding.file}`;
    if (finding.line) {
      line += `:${finding.line}`;
    }
    line += "**";
    if (finding.rule) {
      line += ` [${finding.severity || "UNKNOWN"}] ${finding.rule}`;
    }
    line += "\n";
    return line;
  }
}

export default DiffEngine;
