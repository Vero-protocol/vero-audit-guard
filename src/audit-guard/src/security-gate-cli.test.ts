import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

jest.setTimeout(30_000);

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.join(__dirname, "security-gate-cli.ts");
const TS_NODE_REGISTER = require.resolve("ts-node/register/transpile-only");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function isolatedEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    NODE_ENV: "test",
    PATH: process.env.PATH,
    Path: process.env.Path,
    PATHEXT: process.env.PATHEXT,
    SystemRoot: process.env.SystemRoot,
    WINDIR: process.env.WINDIR,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    TMPDIR: process.env.TMPDIR,
    ...overrides,
  };

  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined)
  );
}

function runCli(args: string[], env: NodeJS.ProcessEnv = {}): CliResult {
  const result = spawnSync(
    process.execPath,
    ["-r", TS_NODE_REGISTER, CLI_PATH, ...args],
    {
      cwd: PACKAGE_ROOT,
      env: isolatedEnv(env),
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      shell: false,
      timeout: 20_000,
      windowsHide: true,
    }
  );

  if (result.error) {
    throw result.error;
  }

  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe("security-gate CLI entrypoint", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-guard-security-gate-cli-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { force: true, recursive: true });
  });

  function writeReport(name: string, value: unknown): string {
    const reportPath = path.join(tempDir, name);
    fs.writeFileSync(reportPath, JSON.stringify(value), "utf8");
    return reportPath;
  }

  it("passes a report with no findings", () => {
    const reportPath = writeReport("clean.json", {
      target: "scanner-test-target",
      findings: [],
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Security Gate");
    expect(result.stdout).toContain("Blocking  : 0");
    expect(result.stdout).toContain('"passed": true');
  });

  it("fails a report containing a critical finding", () => {
    const reportPath = writeReport("critical.json", {
      target: "scanner-test-target",
      findings: [
        {
          file: "contracts/vault.rs",
          line: 42,
          rule: "UNSAFE_BLOCK",
          severity: "CRITICAL",
        },
      ],
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Blocking  : 1");
    expect(result.stdout).toContain("[CRITICAL] contracts/vault.rs:42");
    expect(result.stdout).toContain('"passed": false');
  });

  it("fails closed when a finding has an unknown severity", () => {
    const reportPath = writeReport("unknown-severity.json", {
      target: "scanner-test-target",
      findings: [
        {
          file: "contracts/vault.rs",
          line: 7,
          rule: "UNRECOGNIZED_RULE",
          severity: "UNRECOGNIZED",
        },
      ],
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Blocking  : 1");
    expect(result.stdout).toContain("[UNRECOGNIZED] contracts/vault.rs:7");
  });

  it("honors a stricter severity threshold from the environment", () => {
    const reportPath = writeReport("high.json", {
      target: "scanner-test-target",
      findings: [
        {
          file: "contracts/vault.rs",
          line: 12,
          rule: "UNSAFE_UNWRAP",
          severity: "HIGH",
        },
      ],
    });

    const result = runCli([reportPath], { SECURITY_SEVERITY_THRESHOLD: "2" });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Threshold : severity rank > 2");
    expect(result.stdout).toContain("Blocking  : 1");
  });

  it("gives SCAN_REPORT_FILE precedence over the positional report", () => {
    const positionalPath = writeReport("positional-critical.json", {
      target: "scanner-test-target",
      findings: [
        {
          file: "contracts/vault.rs",
          line: 42,
          rule: "UNSAFE_BLOCK",
          severity: "CRITICAL",
        },
      ],
    });
    const environmentPath = writeReport("environment-clean.json", {
      target: "scanner-test-target",
      findings: [],
    });

    const result = runCli([positionalPath], { SCAN_REPORT_FILE: environmentPath });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Findings  : 0");
    expect(result.stdout).toContain('"passed": true');
  });

  it("accepts a valid report path containing spaces and Unicode", () => {
    const reportPath = writeReport("security report \u00f1 \u6f22\u5b57.json", {
      target: "scanner-test-target",
      findings: [],
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('"passed": true');
  });

  it("rejects a missing report path", () => {
    const missingPath = path.join(tempDir, "missing.json");
    const result = runCli([missingPath]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`Scan report not found: ${missingPath}`);
  });

  it("rejects malformed JSON", () => {
    const reportPath = path.join(tempDir, "malformed.json");
    fs.writeFileSync(reportPath, "{not-json", "utf8");

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"error": "INVALID_JSON"');
    expect(result.stdout).toContain('"passed": false');
  });

  it("rejects a report without a findings array", () => {
    const reportPath = writeReport("invalid-shape.json", {
      target: "scanner-test-target",
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"error": "INVALID_REPORT"');
  });

  it("fails closed when the report JSON is null", () => {
    const reportPath = writeReport("null-report.json", null);

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).not.toContain('"passed": true');
    expect(result.stderr).not.toBe("");
  });

  it("fails when the scanner target is empty", () => {
    const reportPath = writeReport("empty-target.json", {
      target: "",
      findings: [],
    });

    const result = runCli([reportPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Target analysis missing");
    expect(result.stdout).toContain('"passed": false');
  });
});
