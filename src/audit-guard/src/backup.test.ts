import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { backupLogs, restoreLogs, isRemoteDestination } from "./backup";

describe("Backup utility", () => {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "vero-backup-test-"));
  const sourceDir = path.join(rootDir, "source");
  const backupDir = path.join(rootDir, "backup");
  const restoreDir = path.join(rootDir, "restore");

  beforeEach(() => {
    fs.rmSync(rootDir, { recursive: true, force: true });
    fs.mkdirSync(sourceDir, { recursive: true });
    fs.writeFileSync(path.join(sourceDir, "audit.log"), "line1\nline2\n", "utf8");
    fs.mkdirSync(path.join(sourceDir, "nested"), { recursive: true });
    fs.writeFileSync(path.join(sourceDir, "nested", "app.log"), "nested log", "utf8");
  });

  afterAll(() => {
    fs.rmSync(rootDir, { recursive: true, force: true });
  });

  it("detects remote destinations", () => {
    expect(isRemoteDestination("user@example.com:/var/backups/logs")).toBe(true);
    expect(isRemoteDestination("ssh://example.com/var/backups/logs")).toBe(true);
    expect(isRemoteDestination("rsync://example.com/var/backups/logs")).toBe(true);
    expect(isRemoteDestination(path.join(rootDir, "backup"))).toBe(false);
  });

  it("backs up a local log directory", () => {
    backupLogs(sourceDir, backupDir);

    expect(fs.existsSync(path.join(backupDir, "audit.log"))).toBe(true);
    expect(fs.readFileSync(path.join(backupDir, "audit.log"), "utf8")).toBe("line1\nline2\n");
    expect(fs.existsSync(path.join(backupDir, "nested", "app.log"))).toBe(true);
  });

  it("restores logs from a local backup", () => {
    backupLogs(sourceDir, backupDir);
    restoreLogs(backupDir, restoreDir);

    expect(fs.existsSync(path.join(restoreDir, "audit.log"))).toBe(true);
    expect(fs.readFileSync(path.join(restoreDir, "nested", "app.log"), "utf8")).toBe("nested log");
  });

  it("fails when source directory does not exist", () => {
    expect(() => backupLogs(path.join(rootDir, "missing"), backupDir)).toThrow(
      /Source directory does not exist|Directory does not exist/
    );
  });
});
