/**
 * Tests for DiffEngine - State Drift Detection
 */

import DiffEngine, { ScanReport, DiffReport } from "./diff-engine";

describe("DiffEngine", () => {
  let engine: DiffEngine;

  beforeEach(() => {
    engine = new DiffEngine();
  });

  const createMockReport = (
    findings: Array<{
      file: string;
      line?: number;
      rule?: string;
      severity?: string;
      snippet?: string;
    }>,
    hash?: string
  ): ScanReport => ({
    target: "/app",
    total_files: findings.length,
    findings: findings.map((f) => ({
      file: f.file,
      line: f.line,
      rule: f.rule,
      severity: f.severity,
      snippet: f.snippet,
    })),
    report_hash: hash || `hash-${Date.now()}`,
  });

  describe("compare", () => {
    it("should detect no drift when comparing identical reports", () => {
      const findings = [
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
      ];
      const current = createMockReport(findings, "hash-abc");
      const previous = createMockReport(findings, "hash-abc");

      const result = engine.compare(current, previous);

      expect(result.drift_detected).toBe(false);
      expect(result.unchanged).toHaveLength(1);
      expect(result.added).toHaveLength(0);
      expect(result.removed).toHaveLength(0);
      expect(result.drift_summary).toContain("No drift detected");
    });

    it("should detect added findings as drift", () => {
      const current = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
        { file: "/app/lib.rs", line: 5, rule: "UNSAFE_EXPECT", severity: "HIGH" },
      ]);
      const previous = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
      ]);

      const result = engine.compare(current, previous);

      expect(result.drift_detected).toBe(true);
      expect(result.added).toHaveLength(1);
      expect(result.added[0].file).toBe("/app/lib.rs");
      expect(result.drift_summary).toContain("+1 new finding");
    });

    it("should detect removed findings as drift", () => {
      const current = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
      ]);
      const previous = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
        { file: "/app/lib.rs", line: 5, rule: "UNSAFE_EXPECT", severity: "HIGH" },
      ]);

      const result = engine.compare(current, previous);

      expect(result.drift_detected).toBe(true);
      expect(result.removed).toHaveLength(1);
      expect(result.removed[0].file).toBe("/app/lib.rs");
      expect(result.drift_summary).toContain("-1 resolved finding");
    });

    it("should detect modified findings as drift", () => {
      const current = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "CRITICAL" },
      ]);
      const previous = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
      ]);

      const result = engine.compare(current, previous);

      expect(result.drift_detected).toBe(true);
      expect(result.modified).toHaveLength(1);
      expect(result.drift_summary).toContain("~1 modified finding");
    });

    it("should handle null previous report (initial scan)", () => {
      const current = createMockReport([
        { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
      ]);

      const result = engine.compare(current, null);

      expect(result.drift_detected).toBe(true);
      expect(result.added).toHaveLength(1);
      expect(result.previous_hash).toBeUndefined();
      expect(result.drift_summary).toContain("Initial scan");
    });

    it("should handle empty findings in both reports", () => {
      const current = createMockReport([]);
      const previous = createMockReport([]);

      const result = engine.compare(current, previous);

      expect(result.drift_detected).toBe(false);
      expect(result.added).toHaveLength(0);
      expect(result.removed).toHaveLength(0);
    });

    it("should properly track hash values", () => {
      const current = createMockReport([], "hash-current");
      const previous = createMockReport([], "hash-previous");

      const result = engine.compare(current, previous);

      expect(result.current_hash).toBe("hash-current");
      expect(result.previous_hash).toBe("hash-previous");
    });
  });

  describe("generateMarkdownReport", () => {
    it("should generate report with no drift", () => {
      const diff: DiffReport = {
        added: [],
        removed: [],
        modified: [],
        unchanged: [{ file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP" }],
        drift_detected: false,
        drift_summary: "✅ No drift detected - state matches previous scan",
        current_hash: "hash-current",
        previous_hash: "hash-previous",
      };

      const markdown = engine.generateMarkdownReport(diff);

      expect(markdown).toContain("📊 State Drift Analysis");
      expect(markdown).toContain("No drift detected");
      expect(markdown).toContain("hash-current");
      expect(markdown).toContain("hash-previous");
    });

    it("should generate report with added findings", () => {
      const diff: DiffReport = {
        added: [
          { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "HIGH" },
        ],
        removed: [],
        modified: [],
        unchanged: [],
        drift_detected: true,
        drift_summary: "⚠️ Drift detected: +1 new finding(s)",
        current_hash: "hash-current",
        previous_hash: "hash-previous",
      };

      const markdown = engine.generateMarkdownReport(diff);

      expect(markdown).toContain("New Findings");
      expect(markdown).toContain("/app/main.rs");
    });

    it("should generate report with removed findings", () => {
      const diff: DiffReport = {
        added: [],
        removed: [
          { file: "/app/lib.rs", line: 5, rule: "UNSAFE_EXPECT", severity: "HIGH" },
        ],
        modified: [],
        unchanged: [],
        drift_detected: true,
        drift_summary: "⚠️ Drift detected: -1 resolved finding(s)",
        current_hash: "hash-current",
        previous_hash: "hash-previous",
      };

      const markdown = engine.generateMarkdownReport(diff);

      expect(markdown).toContain("Resolved Findings");
      expect(markdown).toContain("/app/lib.rs");
    });

    it("should generate report with modified findings", () => {
      const diff: DiffReport = {
        added: [],
        removed: [],
        modified: [
          { file: "/app/main.rs", line: 10, rule: "UNSAFE_UNWRAP", severity: "CRITICAL" },
        ],
        unchanged: [],
        drift_detected: true,
        drift_summary: "⚠️ Drift detected: ~1 modified finding(s)",
        current_hash: "hash-current",
        previous_hash: "hash-previous",
      };

      const markdown = engine.generateMarkdownReport(diff);

      expect(markdown).toContain("Modified Findings");
      expect(markdown).toContain("/app/main.rs");
    });
  });
});
