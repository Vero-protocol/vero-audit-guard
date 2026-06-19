import * as fs from "fs";
import * as path from "path";
import {
  ScanFinding,
  ScanResult,
  Severity,
  countBySeverity,
  generateScanReport,
  getOverallRisk,
  sortFindingsBySeverity,
} from "./report-generator";

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makeFinding(id: string, severity: Severity): ScanFinding {
  return {
    id,
    title: `Test finding ${id}`,
    description: "Test description",
    severity,
    location: "src/test.ts",
    line: 1,
    remediation: "Fix it.",
  };
}

function makeScan(findings: ScanFinding[]): ScanResult {
  return {
    target: "test_contract",
    scannedAt: "2026-06-19T00:00:00Z",
    scannerVersion: "0.1.0-test",
    findings,
    notes: undefined,
  };
}

const TMP_DIR = path.join(__dirname, "__tmp_reports__");

beforeAll(() => {
  if (!fs.existsSync(TMP_DIR)) fs.mkdirSync(TMP_DIR);
});

afterAll(() => {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── Unit tests ───────────────────────────────────────────────────────────────

describe("getOverallRisk", () => {
  it("returns CRITICAL when a critical finding exists", () => {
    const findings = [makeFinding("F1", "LOW"), makeFinding("F2", "CRITICAL")];
    expect(getOverallRisk(findings)).toBe("CRITICAL");
  });

  it("returns HIGH when highest severity is HIGH", () => {
    const findings = [makeFinding("F1", "MEDIUM"), makeFinding("F2", "HIGH")];
    expect(getOverallRisk(findings)).toBe("HIGH");
  });

  it("returns NONE when there are no findings", () => {
    expect(getOverallRisk([])).toBe("NONE");
  });
});

describe("countBySeverity", () => {
  it("counts correctly", () => {
    const findings = [
      makeFinding("F1", "HIGH"),
      makeFinding("F2", "HIGH"),
      makeFinding("F3", "LOW"),
    ];
    expect(countBySeverity(findings, "HIGH")).toBe(2);
    expect(countBySeverity(findings, "LOW")).toBe(1);
    expect(countBySeverity(findings, "CRITICAL")).toBe(0);
  });
});

describe("sortFindingsBySeverity", () => {
  it("sorts CRITICAL before HIGH before LOW", () => {
    const findings = [
      makeFinding("F1", "LOW"),
      makeFinding("F2", "CRITICAL"),
      makeFinding("F3", "HIGH"),
    ];
    const sorted = sortFindingsBySeverity(findings);
    expect(sorted[0].severity).toBe("CRITICAL");
    expect(sorted[1].severity).toBe("HIGH");
    expect(sorted[2].severity).toBe("LOW");
  });

  it("does not mutate the original array", () => {
    const findings = [makeFinding("F1", "LOW"), makeFinding("F2", "CRITICAL")];
    sortFindingsBySeverity(findings);
    expect(findings[0].severity).toBe("LOW");
  });
});

// ── Integration tests ─────────────────────────────────────────────────────────

describe("generateScanReport", () => {
  it("generates a PDF file for a scan with findings", async () => {
    const outputPath = path.join(TMP_DIR, "test_with_findings.pdf");
    const scan = makeScan([
      makeFinding("F1", "CRITICAL"),
      makeFinding("F2", "HIGH"),
    ]);
    await generateScanReport(scan, { outputPath });
    expect(fs.existsSync(outputPath)).toBe(true);
    expect(fs.statSync(outputPath).size).toBeGreaterThan(0);
  });

  it("generates a PDF for an empty scan (no findings)", async () => {
    const outputPath = path.join(TMP_DIR, "test_empty.pdf");
    await generateScanReport(makeScan([]), { outputPath });
    expect(fs.existsSync(outputPath)).toBe(true);
  });

  it("generates a PDF with notes", async () => {
    const outputPath = path.join(TMP_DIR, "test_with_notes.pdf");
    const scan: ScanResult = {
      ...makeScan([makeFinding("F1", "MEDIUM")]),
      notes: "Manual review recommended.",
    };
    await generateScanReport(scan, { outputPath });
    expect(fs.existsSync(outputPath)).toBe(true);
  });

  it("creates the output directory if it does not exist", async () => {
    const outputPath = path.join(TMP_DIR, "nested", "deep", "report.pdf");
    await generateScanReport(makeScan([]), { outputPath });
    expect(fs.existsSync(outputPath)).toBe(true);
  });
});
