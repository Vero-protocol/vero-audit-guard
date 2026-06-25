#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const REPORTS_DIR = process.argv[2] || path.join(process.cwd(), 'reports');
const OUTPUT_PATH = process.argv[3] || path.join(REPORTS_DIR, 'badge.json');

const SEVERITY_COLORS = {
  critical: 'e11d48',
  high: 'f97316',
  medium: 'eab308',
  low: '22c55e',
  passing: '16a34a',
};

function findLatestReport(dir) {
  if (!fs.existsSync(dir)) {
    throw new Error(`Reports directory not found: ${dir}`);
  }
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json') && f !== 'badge.json')
    .map((f) => ({
      full: path.join(dir, f),
      mtime: fs.statSync(path.join(dir, f)).mtimeMs,
    }))
    .sort((a, b) => b.mtime - a.mtime);

  if (files.length === 0) {
    throw new Error(`No report JSON files found in ${dir}`);
  }
  return files[0].full;
}

function loadReport(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function extractCounts(report) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  if (Array.isArray(report.findings)) {
    for (const f of report.findings) {
      const sev = String(f.severity || '').toLowerCase();
      if (counts[sev] !== undefined) counts[sev] += 1;
    }
  }

  if (report.summary && typeof report.summary === 'object') {
    for (const key of Object.keys(counts)) {
      if (typeof report.summary[key] === 'number') counts[key] += report.summary[key];
    }
  }

  if (Array.isArray(report.violations)) {
    for (const v of report.violations) {
      const sev = String(v.severity || 'high').toLowerCase();
      counts[counts[sev] !== undefined ? sev : 'high'] += 1;
    }
  }

  return counts;
}

function determineStatus(counts) {
  if (counts.critical > 0) return { message: `${counts.critical} critical`, color: SEVERITY_COLORS.critical };
  if (counts.high > 0) return { message: `${counts.high} high`, color: SEVERITY_COLORS.high };
  if (counts.medium > 0) return { message: `${counts.medium} medium`, color: SEVERITY_COLORS.medium };
  if (counts.low > 0) return { message: `${counts.low} low`, color: SEVERITY_COLORS.low };
  return { message: 'passing', color: SEVERITY_COLORS.passing };
}

function main() {
  let reportPath;
  try {
    reportPath = findLatestReport(REPORTS_DIR);
  } catch (err) {
    console.error(`[generate-badge] ${err.message}`);
    process.exit(1);
  }

  const report = loadReport(reportPath);
  const counts = extractCounts(report);
  const status = determineStatus(counts);

  const badge = {
    schemaVersion: 1,
    label: 'security',
    message: status.message,
    color: status.color,
  };

  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(badge, null, 2));

  console.log(`[generate-badge] Source report: ${reportPath}`);
  console.log(`[generate-badge] Counts: ${JSON.stringify(counts)}`);
  console.log(`[generate-badge] Badge written to: ${OUTPUT_PATH}`);
  console.log('');
  console.log('Add this to README.md (host badge.json somewhere public, e.g. raw.githubusercontent.com):');
  console.log('![Security Health](https://img.shields.io/endpoint?url=<RAW_BADGE_JSON_URL>)');

  process.exit(counts.critical > 0 ? 1 : 0);
}

main();
