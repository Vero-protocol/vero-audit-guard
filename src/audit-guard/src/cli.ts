/**
 * CLI for Policy Engine
 * Used by GitHub Actions to evaluate PR compliance and to run
 * logic-error detection on source files (issue #16).
 */

import * as fs from "fs";
import * as dotenv from "dotenv";
import PolicyEngine, { PRData } from "./policy-engine";
import LogicErrorDetector, { LogicScanOptions } from "./logic-detector";
import EventLogScanner from "./event-log-scanner";
import { OnCallRoster } from "./oncall-roster";
import {
  DEFAULT_SEVERITY_THRESHOLD,
  evaluateSecurityGateFromJson,
} from "./security-gate";

// Load environment variables
dotenv.config();

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "evaluate";

  if (command === "pr" || command === "check-pr") {
    await checkPR();
  } else if (command === "detect-logic") {
    await detectLogic(args);
  } else if (command === "scan-events") {
    scanEvents(args);
  } else if (command === "roster") {
    await rosterCommand(args);
  } else if (command === "security-gate") {
    await runSecurityGate(args);
  } else if (command === "help") {
    printHelp();
  } else {
    await evaluate();
  }
}

/**
 * Manage the on‑call roster.
 *
 * Subcommands:
 *   roster status       — Show current on‑call contacts
 *   roster rotate       — Force rotation to next primary
 *   roster page <msg>   — Page current on‑call with an alert
 */
async function rosterCommand(args: string[]): Promise<void> {
  const sub = args[1] || "status";
  const roster = new OnCallRoster();

  if (sub === "status") {
    const onCall = roster.getCurrentOnCall();
    console.log("\n📟 On‑Call Roster Status\n");
    console.log(`  Rotation ID     : ${onCall.rotationId}`);
    console.log(`  Next rotation   : ${onCall.nextRotation}\n`);
    console.log(`  🟢 Primary  : ${onCall.primary.name} <${onCall.primary.email}>`);
    console.log(`  🟡 Secondary: ${onCall.secondary.name} <${onCall.secondary.email}>`);
    console.log(`  🔴 Manager  : ${onCall.manager.name} <${onCall.manager.email}>`);
    console.log("\nActive contacts:");
    for (const c of roster.getActiveContacts()) {
      console.log(`  - [${c.role}] ${c.name} <${c.email}>`);
    }
  } else if (sub === "rotate") {
    roster.rotate();
    const onCall = roster.getCurrentOnCall();
    console.log(`\n🔄 Rotated. New primary: ${onCall.primary.name} <${onCall.primary.email}>\n`);
  } else if (sub === "page") {
    const message = args.slice(2).join(" ") || "Test page from audit‑guard CLI";
    const severity = process.env.PAGE_SEVERITY || "CRITICAL";
    const repository = process.env.PAGE_REPOSITORY || "unknown";
    console.log(`\n📟 Paging on‑call with: ${message}\n`);
    await roster.pageCurrentOnCall(message, severity, repository);
    console.log("\n✅ On‑call contacts paged.\n");
  } else {
    console.log(`Unknown roster subcommand: ${sub}`);
    console.log("Usage: roster <status|rotate|page>");
  }
}

/**
 * Scan JSONL or key=value audit event logs for sensitive access events.
 *
 * Environment variables:
 *   EVENT_LOG_FILE      File to scan (default: positional arg or logs/relay-events.log)
 *   REPORT_FILE         If set, writes a markdown report to this path
 */
function scanEvents(args: string[]): void {
  const eventLogFile =
    process.env.EVENT_LOG_FILE || args[1] || "./logs/relay-events.log";
  if (!fs.existsSync(eventLogFile)) {
    console.error(`Event log file not found: ${eventLogFile}`);
    console.log("Usage: scan-events <event-log-file>");
    process.exit(1);
  }

  const scanner = new EventLogScanner();
  const result = scanner.scanFile(eventLogFile);
  const report = scanner.generateReport(result);

  console.log("\nEvent Log Scan\n");
  console.log(report);
  console.log("\nRaw Result:");
  console.log(JSON.stringify(result, null, 2));

  if (process.env.REPORT_FILE) {
    fs.writeFileSync(process.env.REPORT_FILE, report);
    console.log(`\nReport written to: ${process.env.REPORT_FILE}`);
  }

  const blockingEvent = result.sensitiveEvents.some((event) =>
    event.severity === "HIGH" || event.severity === "CRITICAL"
  );
  if (blockingEvent) {
    process.exit(1);
  }
}

/**
 * Check PR compliance using GitHub Actions context
 */
async function checkPR(): Promise<void> {
  const prDataPath = process.env.PR_DATA_FILE || "./pr-data.json";

  if (!fs.existsSync(prDataPath)) {
    console.error(`❌ PR data file not found: ${prDataPath}`);
    process.exit(1);
  }

  const prData: PRData = JSON.parse(fs.readFileSync(prDataPath, "utf-8"));

  // Add maintenance info from environment
  if (process.env.MAINTENANCE_MODE === "true") {
    prData.maintenance_mode = true;
    if (process.env.MAINTENANCE_MESSAGE) {
      prData.maintenance_message = process.env.MAINTENANCE_MESSAGE;
    }
  }

  const engine = new PolicyEngine();
  const result = await engine.evaluate(prData);

  // Report to dashboard if configured
  await engine.reportToDashboard(result, prData);

  // Output result
  console.log(JSON.stringify(result, null, 2));

  // Output markdown report to file if specified
  if (process.env.REPORT_FILE) {
    const report = engine.generateReport(result);
    fs.writeFileSync(process.env.REPORT_FILE, report);
    console.log(`\n📝 Report written to: ${process.env.REPORT_FILE}`);
  }

  // Exit with error if non-compliant
  if (result.status === "NON_COMPLIANT" && result.high_severity_violations.length > 0) {
    process.exit(1);
  }
}

/**
 * Evaluate a local PR data file
 */
async function evaluate(): Promise<void> {
  const dataFile = process.argv[2] || "./pr-data.json";

  if (!fs.existsSync(dataFile)) {
    console.error(`❌ File not found: ${dataFile}`);
    console.log("Usage: evaluate <pr-data.json>");
    process.exit(1);
  }

  const prData: PRData = JSON.parse(fs.readFileSync(dataFile, "utf-8"));

  // Add maintenance info from environment
  if (process.env.MAINTENANCE_MODE === "true") {
    prData.maintenance_mode = true;
    if (process.env.MAINTENANCE_MESSAGE) {
      prData.maintenance_message = process.env.MAINTENANCE_MESSAGE;
    }
  }

  const engine = new PolicyEngine();
  const result = await engine.evaluate(prData);

  // Report to dashboard if configured
  await engine.reportToDashboard(result, prData);

  console.log("\n📋 Policy Compliance Evaluation\n");
  console.log(engine.generateReport(result));
  console.log("\n📊 Raw Result:");
  console.log(JSON.stringify(result, null, 2));

  process.exit(result.violations.length > 0 ? 1 : 0);
}

/**
 * Scan a source file for logic-bug patterns (reentrancy, integer
 * overflow risk, hardcoded keys, eval, etc.) — issue #16.
 *
 * Environment variables:
 *   SOURCE_FILE            File to scan (default: positional arg or ./src.ts)
 *   LOGIC_PATTERN_FILTER   Comma-separated pattern IDs to restrict the scan to
 *   REPORT_FILE            If set, writes a markdown report to this path
 *
 * Exit codes:
 *   0  — status SAFE
 *   1  — status VULNERABLE or scan error
 */
async function detectLogic(args: string[]): Promise<void> {
  const sourceFile =
    process.env.SOURCE_FILE || args[1] || "./src.ts";
  if (!fs.existsSync(sourceFile)) {
    console.error(`❌ Source file not found: ${sourceFile}`);
    console.log("Usage: detect-logic <file-to-scan>");
    process.exit(1);
  }
  const code = fs.readFileSync(sourceFile, "utf-8");

  const opts: LogicScanOptions = { file: sourceFile };
  if (process.env.LOGIC_PATTERN_FILTER) {
    opts.patterns = process.env.LOGIC_PATTERN_FILTER
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  const detector = new LogicErrorDetector();
  const result = detector.scan(code, opts);
  const report = detector.generateReport(result);

  console.log("\n🔍 Logic Error Scan\n");
  console.log(report);
  console.log("\n📊 Raw Result:");
  console.log(JSON.stringify(result, null, 2));

  if (process.env.REPORT_FILE) {
    fs.writeFileSync(process.env.REPORT_FILE, report);
    console.log(`\n📝 Report written to: ${process.env.REPORT_FILE}`);
  }

  if (result.status === "VULNERABLE") {
    process.exit(1);
  }
}

/**
 * Evaluate a scanner report and fail the build on blocking findings.
 *
 * Environment variables:
 *   SCAN_REPORT_FILE           Path to scanner JSON report (default: ./reports/latest-scan.json)
 *   SECURITY_SEVERITY_THRESHOLD  Block when severity rank > threshold (default: 3)
 *
 * Exit codes:
 *   0  — gate passed
 *   1  — blocking findings or scan report error
 */
async function runSecurityGate(args: string[]): Promise<void> {
  const reportPath =
    process.env.SCAN_REPORT_FILE || args[1] || "./reports/latest-scan.json";
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
}

function printHelp(): void {
  console.log(`
Policy Engine CLI

Usage: policy-engine <command> [options]

Commands:
  pr, check-pr      Check PR compliance using GitHub Actions context
  detect-logic      Scan a source file for logic-bug patterns (issue #16)
  scan-events       Scan audit event logs for sensitive access events
  evaluate          Evaluate PR data from a JSON file (default)
  roster            Manage on‑call rotation (status|rotate|page)
  security-gate     Evaluate scanner report and fail on blocking findings
  help              Show this help message

Environment Variables:
  PR_DATA_FILE          Path to PR data JSON file (default: ./pr-data.json)
  REPORT_FILE           Output path for markdown report
  OPA_POLICIES_DIR      Path to OPA policies directory
  SOURCE_FILE           Source file for 'detect-logic' (default: ./src.ts)
  LOGIC_PATTERN_FILTER  Comma-separated pattern IDs to restrict the scan
  EVENT_LOG_FILE        Event log file for 'scan-events'

Examples:
  node dist/cli.js pr
  node dist/cli.js evaluate ./my-pr-data.json
  PR_DATA_FILE=./data.json REPORT_FILE=./report.md node dist/cli.js pr
  node dist/cli.js detect-logic ./path/to/contract.sol
  LOGIC_PATTERN_FILTER=REENTRANCY_RISK,UNCHECKED_RETURN_VALUE \
    REPORT_FILE=./report.md node dist/cli.js detect-logic ./contract.sol
  node dist/cli.js scan-events ./logs/relay-events.log
`);
}

main().catch((error) => {
  console.error("❌ Error:", error);
  process.exit(1);
});
