/**
 * CLI for Policy Engine
 * Used by GitHub Actions to evaluate PR compliance
 */

import * as fs from "fs";
import PolicyEngine, { PRData } from "./policy-engine";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "evaluate";

  if (command === "pr" || command === "check-pr") {
    await checkPR();
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
  const engine = new PolicyEngine();
  const result = await engine.evaluate(prData);

  console.log("\n📋 Policy Compliance Evaluation\n");
  console.log(engine.generateReport(result));
  console.log("\n📊 Raw Result:");
  console.log(JSON.stringify(result, null, 2));

  process.exit(result.violations.length > 0 ? 1 : 0);
}

function printHelp(): void {
  console.log(`
Policy Engine CLI

Usage: policy-engine <command> [options]

Commands:
  pr, check-pr      Check PR compliance using GitHub Actions context
  evaluate          Evaluate PR data from a JSON file (default)
  help              Show this help message

Environment Variables:
  PR_DATA_FILE      Path to PR data JSON file (default: ./pr-data.json)
  REPORT_FILE       Output path for markdown report
  OPA_POLICIES_DIR  Path to OPA policies directory

Examples:
  node dist/cli.js pr
  node dist/cli.js evaluate ./my-pr-data.json
  PR_DATA_FILE=./data.json REPORT_FILE=./report.md node dist/cli.js pr
`);
}

main().catch((error) => {
  console.error("❌ Error:", error);
  process.exit(1);
});
