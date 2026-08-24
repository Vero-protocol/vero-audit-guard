import {
  DEFAULT_SEVERITY_THRESHOLD,
  GovernanceFinding,
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
  }>,
  governanceFindings?: Array<{
    file: string;
    line: number;
    rule: string;
    severity: string;
    description?: string;
  }>
) {
  return {
    target: "test-target",
    findings,
    ...(governanceFindings !== undefined
      ? { governance_findings: governanceFindings }
      : {}),
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
      expect(result.summary).toBe("Security gate passed — no findings.");
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
      expect(result.summary).toBe(
        "Security gate passed — 1 finding(s) within threshold."
      );
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

    it.each(["", "   ", "N/A"])(
      "fails when the scanner target is %p",
      (target) => {
        const result = evaluateSecurityGateFromJson(
          JSON.stringify({ target, findings: [] })
        );

        expect(result.passed).toBe(false);
        expect(result.error).toBe("INVALID_REPORT");
        expect(result.summary).toBe(
          "Build blocked — scan report target is missing or analysis was skipped."
        );
      }
    );

    it("fails when the scanner target is missing", () => {
      const result = evaluateSecurityGateFromJson(
        JSON.stringify({ findings: [] })
      );

      expect(result.passed).toBe(false);
      expect(result.error).toBe("INVALID_REPORT");
      expect(result.summary).toContain("target is missing");
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

  describe("skipped-scan sentinels", () => {
    // The CI workflow used to write {"target":"N/A", ...} whenever the scan
    // target was missing — which was always, since nothing checked the
    // contracts out. "N/A" is truthy, so it satisfied the compliance check and
    // every PR received a passing security verdict from a scan that never ran.
    it("blocks a report whose target is the N/A sentinel", () => {
      const result = evaluateSecurityGate({ target: "N/A", findings: [] });
      expect(result.passed).toBe(false);
      expect(result.error).toBe("INVALID_REPORT");
      expect(result.summary).toContain("analysis was skipped");
    });

    it("blocks a report with an empty or whitespace target", () => {
      expect(evaluateSecurityGate({ target: "", findings: [] }).passed).toBe(false);
      expect(evaluateSecurityGate({ target: "   ", findings: [] }).passed).toBe(false);
    });

    it("still passes a real target with no findings", () => {
      expect(evaluateSecurityGate(makeReport([])).passed).toBe(true);
    });
  });

  describe("governance_findings gating", () => {
    // Core acceptance criterion: a report whose only CRITICAL entry is in
    // governance_findings must cause the gate to return passed: false.
    it("blocks when the only CRITICAL finding is a governance finding (UNSAFE_SINGLE_SIG_WITHDRAWAL)", () => {
      const result = evaluateSecurityGate(
        makeReport([], [
          {
            file: "treasury.rs",
            line: 5,
            rule: "UNSAFE_SINGLE_SIG_WITHDRAWAL",
            severity: "CRITICAL",
            description: "Withdrawal function lacks explicit multi-sig authorization check",
          },
        ])
      );
      expect(result.passed).toBe(false);
      expect(result.blockingGovernanceFindings).toHaveLength(1);
      expect(result.blockingGovernanceFindings[0].rule).toBe("UNSAFE_SINGLE_SIG_WITHDRAWAL");
      expect(result.summary).toContain("Build blocked");
    });

    it("blocks when the only CRITICAL finding is a governance ADMIN_KEY_OVERRIDE", () => {
      const result = evaluateSecurityGate(
        makeReport([], [
          {
            file: "multisig.rs",
            line: 12,
            rule: "ADMIN_KEY_OVERRIDE",
            severity: "CRITICAL",
            description: "Admin key bypasses multi-sig",
          },
        ])
      );
      expect(result.passed).toBe(false);
      expect(result.blockingGovernanceFindings).toHaveLength(1);
    });

    it("passes when governance findings are all below threshold (HIGH)", () => {
      const result = evaluateSecurityGate(
        makeReport([], [
          {
            file: "config.rs",
            line: 3,
            rule: "WEAK_THRESHOLD",
            severity: "HIGH",
          },
        ])
      );
      expect(result.passed).toBe(true);
      expect(result.blockingGovernanceFindings).toHaveLength(0);
    });

    it("blocks when both plain and governance findings have CRITICALs", () => {
      const result = evaluateSecurityGate(
        makeReport(
          [{ file: "a.rs", line: 1, rule: "UNSAFE_BLOCK", severity: "CRITICAL" }],
          [{ file: "b.rs", line: 2, rule: "UNSAFE_SINGLE_SIG_WITHDRAWAL", severity: "CRITICAL" }]
        )
      );
      expect(result.passed).toBe(false);
      expect(result.blockingFindings).toHaveLength(1);
      expect(result.blockingGovernanceFindings).toHaveLength(1);
    });

    it("blocks on governance CRITICAL even when plain findings are empty", () => {
      const result = evaluateSecurityGate(
        makeReport([], [
          { file: "vault.rs", line: 8, rule: "UNSAFE_SINGLE_SIG_WITHDRAWAL", severity: "CRITICAL" },
        ])
      );
      expect(result.passed).toBe(false);
      expect(result.blockingFindings).toHaveLength(0);
      expect(result.blockingGovernanceFindings).toHaveLength(1);
    });

    it("treats absent governance_findings field as empty (backward-compatible)", () => {
      // Reports produced before this change have no governance_findings key.
      const result = evaluateSecurityGate({ target: "vero-core", findings: [] });
      expect(result.passed).toBe(true);
      expect(result.blockingGovernanceFindings).toHaveLength(0);
    });

    it("totalFindings counts plain + governance findings together", () => {
      const result = evaluateSecurityGate(
        makeReport(
          [{ file: "a.rs", line: 1, rule: "UNSAFE_UNWRAP", severity: "HIGH" }],
          [{ file: "b.rs", line: 2, rule: "WEAK_THRESHOLD", severity: "HIGH" }]
        )
      );
      expect(result.totalFindings).toBe(2);
    });

    it("evaluateSecurityGateFromJson blocks on governance CRITICAL in JSON", () => {
      const report = {
        target: "vero-core",
        findings: [],
        governance_findings: [
          {
            file: "treasury.rs",
            line: 5,
            rule: "UNSAFE_SINGLE_SIG_WITHDRAWAL",
            severity: "CRITICAL",
            description: "Withdrawal function lacks explicit multi-sig authorization check",
          },
        ],
      };
      const result = evaluateSecurityGateFromJson(JSON.stringify(report));
      expect(result.passed).toBe(false);
      expect(result.blockingGovernanceFindings).toHaveLength(1);
    });
  });
});
