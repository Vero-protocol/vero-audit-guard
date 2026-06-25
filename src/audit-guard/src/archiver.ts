// src/audit-guard/src/archiver.ts
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";

export interface ArchiverConfig {
  bucketName: string;
  region: string;
  retentionDays?: number; // days to keep local logs before archiving
  prefix?: string; // optional S3 key prefix
}

/**
 * Archiver class handles moving historical log files from a local directory to an S3 bucket.
 * It compresses each log file using gzip before upload to reduce storage cost.
 * After successful upload, the local file is deleted.
 */
export class LogArchiver {
  private s3: S3Client;
  private config: Required<ArchiverConfig>;

  constructor(config: ArchiverConfig) {
    if (!config.bucketName || !config.region) {
      throw new Error("bucketName and region are required for LogArchiver configuration");
    }
    this.config = {
      retentionDays: 30,
      prefix: "audit-logs/",
      ...config,
    };
    this.s3 = new S3Client({ region: this.config.region });
  }

  /**
   * Archive all files older than retentionDays from the given directory.
   * @param logsDir Local directory containing log files.
   */
  async archiveDirectory(logsDir: string): Promise<void> {
    const files = await fs.promises.readdir(logsDir, { withFileTypes: true });
    const now = Date.now();
    const cutoff = now - (this.config.retentionDays * 24 * 60 * 60 * 1000);
    for (const entry of files) {
      if (entry.isFile()) {
        const filePath = path.join(logsDir, entry.name);
        const stats = await fs.promises.stat(filePath);
        if (stats.mtimeMs < cutoff) {
          await this.archiveFile(filePath);
        }
      }
    }
  }

  /**
   * Compress and upload a single file to S3, then delete the local copy.
   */
  private async archiveFile(filePath: string): Promise<void> {
    const fileStream = fs.createReadStream(filePath);
    const gzip = zlib.createGzip();
    const compressed = fileStream.pipe(gzip);
    const key = `${this.config.prefix}${path.basename(filePath)}.gz`;
    const putCommand = new PutObjectCommand({
      Bucket: this.config.bucketName,
      Key: key,
      Body: compressed,
    });
    await this.s3.send(putCommand);
    await fs.promises.unlink(filePath);
    console.log(`[LogArchiver] Archived and removed ${filePath}`);
  }
}

export default LogArchiver;
