/**
 * CLI for Policy Engine
 * Used by GitHub Actions to evaluate PR compliance, run logic-error
 * detection on source files (issue #16), and authorize relayed
 * transactional envelopes (issue #25).
 */

import * as fs from "fs";
import PolicyEngine, { PRData } from "./policy-engine";
import LogicErrorDetector, { LogicScanOptions } from "./logic-detector";
import RelayerTxScanner, {
  RelayerScanOptions,
  RelayerTransaction,
} from "./relayer-scanner";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "evaluate";

  if (command === "pr" || command === "check-pr") {
    await checkPR();
  } else if (command === "detect-logic") {
    await detectLogic(args);
  } else if (command === "scan-tx") {
    await scanTx(args);
  } else if (command === "help") {
    printHelp();
  } else {
    await evaluate();
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
 * scan-tx — load a relayer transaction envelope from disk, apply the
 * operator-supplied authorization policy, and emit a markdown report.
 *
 * Config (all from env vars):
 *   TX_DATA_FILE                     Path to envelope JSON (default: ./tx-data.json)
 *   VERO_RELAYER_AUTHORIZED_SIGNERS  CSV allowlist (required)
 *   VERO_RELAYER_DENYLISTED_SIGNERS  CSV denylist (opt-in)
 *   VERO_RELAYER_TRUSTED_SOURCES     CSV trusted source accounts (opt-in)
 *   VERO_RELAYER_ALLOWED_OPERATIONS  CSV allowed op types (opt-in)
 *   RELAYER_MULTI_SIG_THRESHOLD      Positive integer (opt-in)
 *   RELAYER_MAX_FEE_PER_OP           Positive integer (opt-in)
 *   RELAYER_PATTERN_FILTER           Comma-separated pattern IDs (opt-in)
 *   RELAYER_REPORT_FILE              Where to write the markdown report (opt-in)
 *
 * Exit codes mirror detect-logic:
 *   0  — AUTHORIZED  (or REQUIRES_REVIEW, surfaced in the report)
 *   1  — UNAUTHORIZED (drop the envelope, open an IRP)
 */
async function scanTx(args: string[]): Promise<void> {
  const txPath = process.env.TX_DATA_FILE || args[1] || "./tx-data.json";
  if (!fs.existsSync(txPath)) {
    console.error(`❌ Transaction envelope not found: ${txPath}`);
    console.log("Usage: scan-tx [path/to/tx.json]");
    process.exit(1);
  }

  const tx = JSON.parse(fs.readFileSync(txPath, "utf-8")) as RelayerTransaction;
  const csv = (raw: string | undefined): string[] =>
    (raw ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  const numFromEnv = (raw: string | undefined): number | undefined => {
    if (typeof raw !== "string" || raw.length === 0) return undefined;
    const n = Number(raw);
    return Number.isFinite(n) ? n : undefined;
  };

  const authorized = csv(process.env.VERO_RELAYER_AUTHORIZED_SIGNERS);
  if (authorized.length === 0) {
    console.error(
      "❌ VERO_RELAYER_AUTHORIZED_SIGNERS must contain at least one signer key."
    );
    process.exit(1);
  }

  const patterns = csv(process.env.RELAYER_PATTERN_FILTER);

  const options: RelayerScanOptions = {
    authorizedSigners: authorized,
    denylistedSigners: csv(process.env.VERO_RELAYER_DENYLISTED_SIGNERS),
    trustedSourceAccounts: csv(process.env.VERO_RELAYER_TRUSTED_SOURCES),
    allowedOperationTypes: csv(process.env.VERO_RELAYER_ALLOWED_OPERATIONS),
    multiSigThreshold: numFromEnv(process.env.RELAYER_MULTI_SIG_THRESHOLD),
    maxFeePerOp: numFromEnv(process.env.RELAYER_MAX_FEE_PER_OP),
    patterns: patterns.length > 0 ? patterns : undefined,
  };

  const scanner = new RelayerTxScanner();
  const result = scanner.scan(tx, options);

  console.log("\n🔒 Relayer Authorization Scan\n");
  console.log(scanner.generateReport(result));
  console.log("\n📊 Raw Result:");
  console.log(JSON.stringify(result, null, 2));

  if (process.env.RELAYER_REPORT_FILE) {
    fs.writeFileSync(
      process.env.RELAYER_REPORT_FILE,
      scanner.generateReport(result)
    );
    console.log(`\n📝 Report written to: ${process.env.RELAYER_REPORT_FILE}`);
  }

  if (result.status === "UNAUTHORIZED") {
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
  scan-tx           Authorize a relayer-bound transactional envelope (issue #25)
  evaluate          Evaluate PR data from a JSON file (default)
  help              Show this help message

Environment Variables:
  PR_DATA_FILE          Path to PR data JSON file (default: ./pr-data.json)
  REPORT_FILE           Output path for markdown report
  OPA_POLICIES_DIR      Path to OPA policies directory
  SOURCE_FILE           Source file for 'detect-logic' (default: ./src.ts)
  LOGIC_PATTERN_FILTER  Comma-separated logic-pattern IDs to restrict the scan
  TX_DATA_FILE                  Relayer tx envelope JSON (default: ./tx-data.json)
  RELAYER_REPORT_FILE           Output path for the 'scan-tx' markdown report
  VERO_RELAYER_AUTHORIZED_SIGNERS  CSV allowlist of signer keys (required for scan-tx)
  VERO_RELAYER_DENYLISTED_SIGNERS  CSV denylist of signer keys (opt-in)
  VERO_RELAYER_TRUSTED_SOURCES     CSV trusted source accounts (opt-in)
  VERO_RELAYER_ALLOWED_OPERATIONS  CSV allowed op types (opt-in)
  RELAYER_MULTI_SIG_THRESHOLD       Positive integer multi-sig threshold (opt-in)
  RELAYER_MAX_FEE_PER_OP            Positive integer per-op fee ceiling (opt-in)
  RELAYER_PATTERN_FILTER            Comma-separated relayer pattern IDs (opt-in)

Examples:
  node dist/cli.js pr
  node dist/cli.js evaluate ./my-pr-data.json
  PR_DATA_FILE=./data.json REPORT_FILE=./report.md node dist/cli.js pr
  node dist/cli.js detect-logic ./path/to/contract.sol
  LOGIC_PATTERN_FILTER=REENTRANCY_RISK,UNCHECKED_RETURN_VALUE \
    REPORT_FILE=./report.md node dist/cli.js detect-logic ./contract.sol
  TX_DATA_FILE=./tx.json \
    VERO_RELAYER_AUTHORIZED_SIGNERS="GA..,GB.." \
    node dist/cli.js scan-tx
`);
}

main().catch((error) => {
  console.error("❌ Error:", error);
  process.exit(1);
});
