import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

jest.setTimeout(30_000);

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.join(__dirname, "cli.ts");
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

describe("cli entrypoint", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-guard-cli-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { force: true, recursive: true });
  });

  it("prints help and exits successfully", () => {
    const result = runCli(["help"]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Policy Engine CLI");
    expect(result.stdout).toContain("Usage: policy-engine <command> [options]");
    expect(result.stderr).toBe("");
  });

  it("accepts the analyze-logs alias and exits zero for clean logs", () => {
    const logsPath = path.join(tempDir, "clean-logs.json");
    fs.writeFileSync(logsPath, "[]\n", "utf8");

    const result = runCli(["analyze-logs", logsPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Log Anomaly Analysis");
    expect(result.stdout).toContain("No log anomalies detected");
  });

  it("handles a clean log file whose path contains spaces and Unicode", () => {
    const logsPath = path.join(tempDir, "clean logs \u00f1 \u6f22\u5b57.json");
    fs.writeFileSync(logsPath, "[]\n", "utf8");

    const result = runCli(["logs", logsPath]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("No log anomalies detected");
    expect(result.stderr).toBe("");
  });

  it("returns a failing exit code when log analysis finds an anomaly", () => {
    const logsPath = path.join(tempDir, "fatal-logs.json");
    fs.writeFileSync(
      logsPath,
      JSON.stringify([
        {
          timestamp: "2026-01-01T00:00:00.000Z",
          level: "fatal",
          message: "relayer crashed",
          service: "relayer",
        },
      ]),
      "utf8"
    );

    const result = runCli(["logs", logsPath]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Detected 1 anomaly/anomalies");
    expect(result.stdout).toContain("[ERROR_PATTERN][CRITICAL]");
  });

  it("rejects a missing log-file argument", () => {
    const missingPath = path.join(tempDir, "missing.json");
    const result = runCli(["analyze-logs", missingPath]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`Log file not found: ${missingPath}`);
    expect(result.stdout).toContain("Usage: analyze-logs <logs.json>");
  });

  it("returns a failing exit code for malformed log JSON", () => {
    const logsPath = path.join(tempDir, "malformed-logs.json");
    fs.writeFileSync(logsPath, "{not-json", "utf8");

    const result = runCli(["analyze-logs", logsPath]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Error:");
    expect(result.stdout).not.toContain("No log anomalies detected");
  });

  it("routes the check-pr alias and honors PR_DATA_FILE", () => {
    const missingPath = path.join(tempDir, "missing-pr-data.json");
    const result = runCli(["check-pr"], { PR_DATA_FILE: missingPath });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`PR data file not found: ${missingPath}`);
    expect(result.stdout).not.toContain("Usage: evaluate <pr-data.json>");
  });

  it("returns a failing exit code for an unrecognized command", () => {
    const unknownCommand = `unknown-command-${path.basename(tempDir)}`;
    const result = runCli([unknownCommand]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`File not found: ${unknownCommand}`);
    expect(result.stdout).toContain("Usage: evaluate <pr-data.json>");
  });
});
