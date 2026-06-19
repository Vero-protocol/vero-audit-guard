// src/audit-guard/src/archive-cli.ts
import LogArchiver from "./archiver";

// Configuration via environment variables
const config = {
  bucketName: process.env.ARCHIVE_S3_BUCKET || "",
  region: process.env.ARCHIVE_S3_REGION || "us-east-1",
  retentionDays: Number(process.env.ARCHIVE_RETENTION_DAYS) || 30,
  prefix: process.env.ARCHIVE_S3_PREFIX || "audit-logs/",
};

if (!config.bucketName) {
  console.error("[Archive CLI] ARCHIVE_S3_BUCKET is not set.");
  process.exit(1);
}

(async () => {
  try {
    const archiver = new LogArchiver(config);
    const logsDir = process.env.ARCHIVE_LOGS_PATH || "logs";
    await archiver.archiveDirectory(logsDir);
    console.log("[Archive CLI] Archiving completed.");
  } catch (e) {
    console.error("[Archive CLI] Error:", e);
    process.exit(1);
  }
})();
