/**
 * Standalone CLI entry for the CI/CD security gate.
 */

import * as fs from "fs";
import {
  DEFAULT_SEVERITY_THRESHOLD,
  evaluateSecurityGateFromJson,
} from "./security-gate";

const reportPath =
  process.env.SCAN_REPORT_FILE ||
  process.argv[2] ||
  "./reports/latest-scan.json";
const threshold = Number(
  process.env.SECURITY_SEVERITY_THRESHOLD ?? DEFAULT_SEVERITY_THRESHOLD
);

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
