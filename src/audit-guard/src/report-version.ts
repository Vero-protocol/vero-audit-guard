// Utility to manage audit report versioning
import * as fs from "fs";
import * as path from "path";

const VERSION_FILE = path.join(__dirname, "..", "..", ".audit-report-version.json");

export function getNextReportVersion(): number {
  let version = 1;
  try {
    if (fs.existsSync(VERSION_FILE)) {
      const data = JSON.parse(fs.readFileSync(VERSION_FILE, "utf-8"));
      version = (data.version ?? 0) + 1;
    }
  } catch (_) {
    version = 1;
  }
  // Persist the new version
  try {
    fs.writeFileSync(VERSION_FILE, JSON.stringify({ version }, null, 2));
  } catch (_) {}
  return version;
}
