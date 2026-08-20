import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

jest.setTimeout(30_000);

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.join(__dirname, "archive-cli.ts");
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

function runCli(
  env: NodeJS.ProcessEnv = {},
  preloadPath?: string
): CliResult {
  const nodeArgs = ["-r", TS_NODE_REGISTER];
  if (preloadPath) {
    nodeArgs.push("-r", preloadPath);
  }
  nodeArgs.push(CLI_PATH);

  const result = spawnSync(
    process.execPath,
    nodeArgs,
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

describe("archive CLI entrypoint", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-guard-archive-cli-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { force: true, recursive: true });
  });

  /**
   * Replace only the AWS transport before the entrypoint is loaded. The CLI,
   * LogArchiver, gzip stream, retention checks, and local deletion all remain
   * real while the test stays deterministic and cannot contact AWS.
   */
  function writeAwsMockPreload(): string {
    const preloadPath = path.join(tempDir, "mock-aws.cjs");
    fs.writeFileSync(
      preloadPath,
      [
        'const fs = require("fs");',
        'const Module = require("module");',
        "const originalLoad = Module._load;",
        "Module._load = function(request) {",
        '  if (request === "@aws-sdk/client-s3") {',
        "    return {",
        "      PutObjectCommand: class {",
        "        constructor(input) { this.input = input; }",
        "      },",
        "      S3Client: class {",
        "        constructor(config) { this.config = config; }",
        "        async send(command) {",
        '          if (process.env.MOCK_S3_FAILURE === "true") {',
        '            throw new Error("SIMULATED_S3_FAILURE");',
        "          }",
        "          let bytes = 0;",
        "          for await (const chunk of command.input.Body) {",
        "            bytes += chunk.length;",
        "          }",
        "          fs.appendFileSync(",
        "            process.env.MOCK_S3_CAPTURE_FILE,",
        "            JSON.stringify({",
        "              bucket: command.input.Bucket,",
        "              bytes,",
        "              key: command.input.Key,",
        "              region: this.config.region,",
        '            }) + "\\n"',
        "          );",
        "        }",
        "      },",
        "    };",
        "  }",
        "  return originalLoad.apply(this, arguments);",
        "};",
      ].join("\n"),
      "utf8"
    );
    return preloadPath;
  }

  function makeLogFile(logsDir: string, name: string, ageDays: number): string {
    fs.mkdirSync(logsDir, { recursive: true });
    const filePath = path.join(logsDir, name);
    fs.writeFileSync(filePath, "audit log fixture\n", "utf8");
    const modifiedAt = new Date(Date.now() - ageDays * 24 * 60 * 60 * 1000);
    fs.utimesSync(filePath, modifiedAt, modifiedAt);
    return filePath;
  }

  it("rejects configuration without an archive bucket", () => {
    const result = runCli({ ARCHIVE_LOGS_PATH: tempDir });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("ARCHIVE_S3_BUCKET is not set");
  });

  it("completes an empty-directory archive without contacting S3", () => {
    const result = runCli({
      ARCHIVE_LOGS_PATH: tempDir,
      ARCHIVE_RETENTION_DAYS: "30",
      ARCHIVE_S3_BUCKET: "audit-guard-test-bucket",
      ARCHIVE_S3_PREFIX: "test-logs/",
      ARCHIVE_S3_REGION: "us-east-1",
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("[Archive CLI] Archiving completed.");
    expect(result.stderr).toBe("");
  });

  it("uploads and removes an expired log using the CLI configuration", () => {
    const logsDir = path.join(tempDir, "expired logs");
    const logPath = makeLogFile(logsDir, "old.log", 40);
    const capturePath = path.join(tempDir, "s3-calls.jsonl");
    const preloadPath = writeAwsMockPreload();

    const result = runCli(
      {
        ARCHIVE_LOGS_PATH: logsDir,
        ARCHIVE_RETENTION_DAYS: "30",
        ARCHIVE_S3_BUCKET: "audit-guard-test-bucket",
        ARCHIVE_S3_PREFIX: "test-logs/",
        ARCHIVE_S3_REGION: "eu-west-1",
        MOCK_S3_CAPTURE_FILE: capturePath,
      },
      preloadPath
    );
    const upload = JSON.parse(fs.readFileSync(capturePath, "utf8"));

    expect(result.status).toBe(0);
    expect(fs.existsSync(logPath)).toBe(false);
    expect(upload).toMatchObject({
      bucket: "audit-guard-test-bucket",
      key: "test-logs/old.log.gz",
      region: "eu-west-1",
    });
    expect(upload.bytes).toBeGreaterThan(0);
  });

  it("retains logs that have not reached the retention threshold", () => {
    const logsDir = path.join(tempDir, "fresh-logs");
    const logPath = makeLogFile(logsDir, "fresh.log", 1);
    const capturePath = path.join(tempDir, "s3-calls.jsonl");

    const result = runCli(
      {
        ARCHIVE_LOGS_PATH: logsDir,
        ARCHIVE_RETENTION_DAYS: "30",
        ARCHIVE_S3_BUCKET: "audit-guard-test-bucket",
        MOCK_S3_CAPTURE_FILE: capturePath,
      },
      writeAwsMockPreload()
    );

    expect(result.status).toBe(0);
    expect(fs.existsSync(logPath)).toBe(true);
    expect(fs.existsSync(capturePath)).toBe(false);
  });

  it("preserves an expired log when the S3 upload fails", () => {
    const logsDir = path.join(tempDir, "failed-upload");
    const logPath = makeLogFile(logsDir, "old.log", 40);

    const result = runCli(
      {
        ARCHIVE_LOGS_PATH: logsDir,
        ARCHIVE_RETENTION_DAYS: "30",
        ARCHIVE_S3_BUCKET: "audit-guard-test-bucket",
        MOCK_S3_CAPTURE_FILE: path.join(tempDir, "s3-calls.jsonl"),
        MOCK_S3_FAILURE: "true",
      },
      writeAwsMockPreload()
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("SIMULATED_S3_FAILURE");
    expect(fs.existsSync(logPath)).toBe(true);
    expect(result.stdout).not.toContain("Archiving completed");
  });

  it("reports a missing logs directory as an archive failure", () => {
    const missingPath = path.join(tempDir, "missing-logs");
    const result = runCli({
      ARCHIVE_LOGS_PATH: missingPath,
      ARCHIVE_S3_BUCKET: "audit-guard-test-bucket",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("[Archive CLI] Error:");
    expect(result.stderr).toContain("ENOENT");
    expect(result.stdout).not.toContain("Archiving completed");
  });
});
