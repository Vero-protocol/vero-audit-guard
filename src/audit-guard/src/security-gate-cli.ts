/**
 * Standalone CLI entry for the CI/CD security gate.
 */

import * as fs from "fs";
import {
  DEFAULT_SEVERITY_THRESHOLD,
  SEVERITY_RANK,
  evaluateSecurityGateFromJson,
  severityRank,
} from "./security-gate";

const reportPath =
  process.env.SCAN_REPORT_FILE ||
  process.argv[2] ||
  "./reports/latest-scan.json";

/**
 * Resolve SECURITY_SEVERITY_THRESHOLD to a numeric rank.
 *
 * Accepted forms:
 *   - Absent / empty → DEFAULT_SEVERITY_THRESHOLD (3)
 *   - Numeric string  → parsed integer, validated to be within [0, 4]
 *   - Severity name   → mapped through SEVERITY_RANK (e.g. "HIGH" → 3)
 *
 * Any other value causes the process to exit 1 with a clear error message
 * so a misconfigured threshold never silently disables the gate.
 */
function resolveThreshold(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_SEVERITY_THRESHOLD;
  }

  const trimmed = raw.trim();

  // Accept a severity name such as "HIGH" or "high".
  const nameRank = severityRank(trimmed);
  if (nameRank !== null) {
    return nameRank;
  }

  // Accept a numeric string; must be a finite integer within the rank range.
  const parsed = Number(trimmed);
  const validRanks = Object.values(SEVERITY_RANK) as number[];
  const minRank = Math.min(...validRanks); // 0
  const maxRank = Math.max(...validRanks); // 4

  if (
    Number.isInteger(parsed) &&
    Number.isFinite(parsed) &&
    parsed >= minRank &&
    parsed <= maxRank
  ) {
    return parsed;
  }

  // Anything else is a configuration error — fail loudly.
  console.error(
    `❌ Invalid SECURITY_SEVERITY_THRESHOLD: "${raw}". ` +
    `Accepted values are a severity name (INFO, LOW, MEDIUM, HIGH, CRITICAL) ` +
    `or an integer between ${minRank} and ${maxRank}.`
  );
  process.exit(1);
}

const threshold = resolveThreshold(process.env.SECURITY_SEVERITY_THRESHOLD);

if (!fs.existsSync(reportPath)) {
  console.error(`❌ Scan report not found: ${reportPath}`);
  process.exit(1);
}

const json = fs.readFileSync(reportPath, "utf-8");
const result = evaluateSecurityGateFromJson(json, threshold);

console.log("\n🔒 Security Gate\n");
console.log(`Threshold : severity rank > ${result.threshold}`);
console.log(`Findings  : ${result.totalFindings}`);
console.log(`Blocking  : ${result.blockingFindings.length}`);
console.log(`\n${result.summary}\n`);

if (result.blockingFindings.length > 0) {
  console.log("Blocking findings:");
  for (const finding of result.blockingFindings) {
    console.log(
      `  [${finding.severity}] ${finding.file}:${finding.line} — ${finding.rule}`
    );
  }
}

console.log("\n📊 Raw Result:");
console.log(JSON.stringify(result, null, 2));

if (!result.passed) {
  process.exit(1);
}
