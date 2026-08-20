import {
  DEFAULT_SEVERITY_THRESHOLD,
  evaluateSecurityGate,
  evaluateSecurityGateFromJson,
  isBlockingSeverity,
} from "./security-gate";

function makeReport(
  findings: Array<{
    file: string;
    line: number;
    rule: string;
    severity: string;
  }>
) {
  return {
    target: "test-target",
    findings,
  };
}

describe("security-gate", () => {
  describe("isBlockingSeverity", () => {
    it("blocks CRITICAL when threshold is 3", () => {
      expect(isBlockingSeverity("CRITICAL", 3)).toBe(true);
    });

    it("allows HIGH when threshold is 3", () => {
      expect(isBlockingSeverity("HIGH", 3)).toBe(false);
    });

    it("blocks unknown severities", () => {
      expect(isBlockingSeverity("UNKNOWN", 3)).toBe(true);
    });
  });

  describe("evaluateSecurityGate", () => {
    it("passes with no findings", () => {
      const result = evaluateSecurityGate(makeReport([]));
      expect(result.passed).toBe(true);
      expect(result.blockingFindings).toHaveLength(0);
    });

    it("passes when highest severity is HIGH", () => {
      const result = evaluateSecurityGate(
        makeReport([
          {
            file: "a.rs",
            line: 1,
            rule: "UNSAFE_UNWRAP",
            severity: "HIGH",
          },
        ])
      );
      expect(result.passed).toBe(true);
      expect(result.totalFindings).toBe(1);
    });

    it("fails when a CRITICAL finding is present", () => {
      const result = evaluateSecurityGate(
        makeReport([
          {
            file: "b.rs",
            line: 10,
            rule: "UNSAFE_BLOCK",
            severity: "CRITICAL",
          },
        ])
      );
      expect(result.passed).toBe(false);
      expect(result.blockingFindings).toHaveLength(1);
      expect(result.summary).toContain("Build blocked");
    });

    it("respects a custom threshold", () => {
      const result = evaluateSecurityGate(
        makeReport([
          {
            file: "c.rs",
            line: 2,
            rule: "UNSAFE_UNWRAP",
            severity: "HIGH",
          },
        ]),
        2
      );
      expect(result.passed).toBe(false);
      expect(result.threshold).toBe(2);
    });

    it("uses default threshold of 3", () => {
      expect(DEFAULT_SEVERITY_THRESHOLD).toBe(3);
    });
  });

  describe("evaluateSecurityGateFromJson", () => {
    it("fails on invalid JSON", () => {
      const result = evaluateSecurityGateFromJson("{not-json");
      expect(result.passed).toBe(false);
      expect(result.error).toBe("INVALID_JSON");
    });

    it("fails when findings array is missing", () => {
      const result = evaluateSecurityGateFromJson(
        JSON.stringify({ target: "x" })
      );
      expect(result.passed).toBe(false);
      expect(result.error).toBe("INVALID_REPORT");
    });

    it("evaluates a valid scanner report", () => {
      const result = evaluateSecurityGateFromJson(
        JSON.stringify(
          makeReport([
            {
              file: "d.rs",
              line: 3,
              rule: "EXPLICIT_PANIC",
              severity: "MEDIUM",
            },
          ])
        )
      );
      expect(result.passed).toBe(true);
    });
  });
});
