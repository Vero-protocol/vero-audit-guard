import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

export interface BackupOptions {
  dryRun?: boolean;
}

export function isRemoteDestination(destination: string): boolean {
  if (/^[a-zA-Z]:[\\/]/.test(destination)) {
    return false;
  }
  return (
    destination.startsWith("rsync://") ||
    destination.startsWith("ssh://") ||
    /^([\w-]+@)?[\w.-]+:/.test(destination)
  );
}

function normalizePath(input: string): string {
  return path.resolve(input);
}

function ensureLocalDirectory(directory: string): void {
  if (!fs.existsSync(directory)) {
    throw new Error(`Directory does not exist: ${directory}`);
  }

  if (!fs.statSync(directory).isDirectory()) {
    throw new Error(`Path is not a directory: ${directory}`);
  }
}

function copyDirectory(sourceDir: string, destinationDir: string): void {
  const resolvedSource = normalizePath(sourceDir);
  const resolvedDestination = normalizePath(destinationDir);

  fs.mkdirSync(path.dirname(resolvedDestination), { recursive: true });
  if (fs.existsSync(resolvedDestination)) {
    fs.rmSync(resolvedDestination, { recursive: true, force: true });
  }

  fs.cpSync(resolvedSource, resolvedDestination, {
    recursive: true,
    force: true,
  });
}

function runRsync(sourceDir: string, destination: string, options: BackupOptions): void {
  const source = sourceDir.endsWith(path.sep)
    ? sourceDir
    : `${sourceDir}${path.sep}`;
  const flags = ["-a", "--delete"];
  if (options.dryRun) {
    flags.push("--dry-run");
  }

  const command = ["rsync", ...flags, source, destination].join(" ");
  execSync(command, { stdio: "inherit" });
}

export function backupLogs(
  sourceDir: string,
  destination: string,
  options: BackupOptions = {}
): void {
  ensureLocalDirectory(sourceDir);

  if (isRemoteDestination(destination)) {
    runRsync(sourceDir, destination, options);
    return;
  }

  copyDirectory(sourceDir, destination);
}

export function restoreLogs(
  backupSource: string,
  targetDir: string,
  options: BackupOptions = {}
): void {
  if (isRemoteDestination(backupSource)) {
    fs.mkdirSync(path.dirname(normalizePath(targetDir)), {
      recursive: true,
    });
    runRsync(backupSource, targetDir, options);
    return;
  }

  ensureLocalDirectory(backupSource);
  copyDirectory(backupSource, targetDir);
}

function resolvePath(arg: string | undefined, envNames: string[]): string | undefined {
  if (arg && arg.trim() !== "") {
    return arg;
  }

  for (const envName of envNames) {
    if (process.env[envName]) {
      return process.env[envName];
    }
  }

  return undefined;
}

function printHelp(): void {
  console.log(`
Vero Audit Guard Backup Utility

Usage:
  npm run backup -- <source-dir> <destination>
  npm run restore -- <backup-source> <target-dir>

Environment variables:
  BACKUP_SOURCE   Source directory for backup
  BACKUP_DEST     Destination path or remote target for backup
  BACKUP_TARGET   Target directory for restore
  LOG_SRC         Alias for BACKUP_SOURCE
  LOG_DEST        Alias for BACKUP_DEST

Options:
  --dry-run       Show what would be backed up without copying
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const filteredArgs = args.filter((arg) => arg !== "--dry-run");
  const command = filteredArgs[0];

  if (!command || command === "help") {
    printHelp();
    process.exit(command ? 0 : 1);
  }

  if (command === "backup") {
    const source = resolvePath(filteredArgs[1], ["BACKUP_SOURCE", "LOG_SRC"]);
    const destination = resolvePath(filteredArgs[2], ["BACKUP_DEST", "LOG_DEST"]);

    if (!source || !destination) {
      console.error("❌ Backup requires a source and destination.");
      printHelp();
      process.exit(1);
    }

    console.log(`🔁 Backing up logs from ${source} to ${destination}`);
    backupLogs(source, destination, { dryRun });
    process.exit(0);
  }

  if (command === "restore") {
    const backupSource = resolvePath(filteredArgs[1], ["BACKUP_SOURCE", "LOG_SRC"]);
    const target = resolvePath(filteredArgs[2], ["BACKUP_TARGET"]);

    if (!backupSource || !target) {
      console.error("❌ Restore requires a backup source and target directory.");
      printHelp();
      process.exit(1);
    }

    console.log(`🔄 Restoring logs from ${backupSource} to ${target}`);
    restoreLogs(backupSource, target, { dryRun });
    process.exit(0);
  }

  console.error(`❌ Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

if (require.main === module) {
  main().catch((error) => {
    console.error("❌ Backup utility failed:", error.message || error);
    process.exit(1);
  });
}
