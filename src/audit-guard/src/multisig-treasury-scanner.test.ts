/**
 * Tests for MultisigTreasuryScanner
 *
 * Covers:
 *  - Input validation (null, undefined, empty source, empty filename)
 *  - Each governance rule detection
 *  - No findings for safe code
 *  - Multiple findings in same file
 *  - Line number and filename accuracy
 *  - Severity level correctness
 *  - generateReport() output shape
 *  - Edge cases (whitespace-only source, special characters)
 */

import MultisigTreasuryScanner from "./multisig-treasury-scanner";
import type { MultisigTreasuryScanResult, GovernanceFinding } from "./multisig-treasury-scanner";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeScanner(): MultisigTreasuryScanner {
  return new MultisigTreasuryScanner();
}

function scan(source: string, filename = "treasury.rs"): MultisigTreasuryScanResult {
  return makeScanner().scan(source, filename);
}

// ---------------------------------------------------------------------------
// Input validation — non-happy-path
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — input validation", () => {
  it("throws when source is null", () => {
    expect(() => scan(null as any, "treasury.rs")).toThrow(
      "source must be a non-empty string"
    );
  });

  it("throws when source is undefined", () => {
    expect(() => scan(undefined as any, "treasury.rs")).toThrow(
      "source must be a non-empty string"
    );
  });

  it("throws when source is empty string", () => {
    expect(() => scan("", "treasury.rs")).toThrow(
      "source must be a non-empty string"
    );
  });

  it("throws when source is whitespace-only", () => {
    expect(() => scan("   \n\t  ", "treasury.rs")).toThrow(
      "source must be a non-empty string"
    );
  });

  it("throws when filename is null", () => {
    expect(() => scan("fn foo() {}", null as any)).toThrow(
      "filename must be a non-empty string"
    );
  });

  it("throws when filename is undefined", () => {
    expect(() => scan("fn foo() {}", undefined as any)).toThrow(
      "filename must be a non-empty string"
    );
  });

  it("throws when filename is empty string", () => {
    expect(() => scan("fn foo() {}", "")).toThrow(
      "filename must be a non-empty string"
    );
  });

  it("throws when filename is whitespace-only", () => {
    expect(() => scan("fn foo() {}", "   ")).toThrow(
      "filename must be a non-empty string"
    );
  });
});

// ---------------------------------------------------------------------------
// Safe code (happy path)
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — safe code", () => {
  it("returns SAFE for properly secured treasury code", () => {
    const source = `
      pub fn execute_proposal(env: Env, proposal_id: u64) {
          let signers = get_confirmed_signers(&env, proposal_id);
          require!(signers.len() >= self.threshold, "insufficient signatures");
          let delay = get_timelock_delay(&env);
          require!(delay >= MIN_TIMELOCK, "timelock too short");
      }
    `;
    const result = scan(source, "safe_treasury.rs");
    expect(result.status).toBe("SAFE");
    expect(result.findings).toHaveLength(0);
    expect(result.totalFiles).toBe(1);
    expect(result.filesScanned).toContain("safe_treasury.rs");
  });

  it("returns summary with no findings message", () => {
    const result = scan("fn safe() {}", "safe.rs");
    expect(result.summary).toBe(
      "✅ No multi-sig treasury governance vulnerabilities detected"
    );
  });
});

// ---------------------------------------------------------------------------
// Individual rule detection
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — rule detection", () => {
  it("detects UNSAFE_SINGLE_SIG_WITHDRAWAL", () => {
    const source = `pub fn withdraw() { transfer(); }`;
    const result = scan(source, "treasury.rs");
    expect(result.status).toBe("VULNERABILITIES_FOUND");
    const finding = result.findings.find((f) => f.rule === "UNSAFE_SINGLE_SIG_WITHDRAWAL");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.line).toBeGreaterThan(0);
  });

  it("detects WEAK_THRESHOLD", () => {
    const source = `const THRESHOLD: u32 = 1; let m = 1;`;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "WEAK_THRESHOLD");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
  });

  it("detects TIMELOCK_BYPASS", () => {
    const source = `const TIMELOCK: u64 = 0; let delay = Duration::ZERO;`;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "TIMELOCK_BYPASS");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
  });

  it("detects HARDCODED_SIGNER", () => {
    const source = `
      pub key: PublicKey = PublicKey::from_str("G...").unwrap();
      const ADMIN: &str = "G...";
    `;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "HARDCODED_SIGNER");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
  });

  it("detects MISSING_SIGNER_VALIDATION", () => {
    const source = `if signers.len() >= 1 { /* execute */ }`;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "MISSING_SIGNER_VALIDATION");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
  });

  it("detects ADMIN_KEY_OVERRIDE", () => {
    const source = `admin.withdraw(amount); authority.transfer(to, amount);`;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "ADMIN_KEY_OVERRIDE");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
  });

  it("detects UNPROTECTED_THRESHOLD_CHANGE", () => {
    const source = `
      pub fn set_threshold(&mut self, new_threshold: u32) {
          self.threshold = new_threshold;
      }
    `;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "UNPROTECTED_THRESHOLD_CHANGE");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
  });

  it("detects NOOP_AUTH_CHECK", () => {
    const source = `require!(true); assert!(true); if true { /* bypass */ }`;
    const result = scan(source, "treasury.rs");
    const finding = result.findings.find((f) => f.rule === "NOOP_AUTH_CHECK");
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
  });
});

// ---------------------------------------------------------------------------
// Multiple findings
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — multiple findings", () => {
  it("detects multiple distinct vulnerabilities in one file", () => {
    const source = `
      pub fn withdraw() { transfer(); }
      const THRESHOLD: u32 = 1;
      pub fn set_threshold(&mut self, t: u32) { self.threshold = t; }
      const TIMELOCK: u64 = 0;
    `;
    const result = scan(source, "treasury.rs");
    expect(result.status).toBe("VULNERABILITIES_FOUND");
    expect(result.findings.length).toBeGreaterThanOrEqual(3);
    expect(result.findings.some((f) => f.rule === "UNSAFE_SINGLE_SIG_WITHDRAWAL")).toBe(true);
    expect(result.findings.some((f) => f.rule === "WEAK_THRESHOLD")).toBe(true);
    expect(result.findings.some((f) => f.rule === "UNPROTECTED_THRESHOLD_CHANGE")).toBe(true);
    expect(result.findings.some((f) => f.rule === "TIMELOCK_BYPASS")).toBe(true);
  });

  it("reports correct line numbers for findings", () => {
    const source = `line1: safe
line2: pub fn withdraw() { transfer(); }
line3: safe
line4: const THRESHOLD: u32 = 1;
line5: safe`;
    const result = scan(source, "treasury.rs");
    const withdrawal = result.findings.find((f) => f.rule === "UNSAFE_SINGLE_SIG_WITHDRAWAL");
    const threshold = result.findings.find((f) => f.rule === "WEAK_THRESHOLD");
    expect(withdrawal).toBeDefined();
    expect(withdrawal!.line).toBe(2);
    expect(threshold).toBeDefined();
    expect(threshold!.line).toBe(4);
  });

  it("reports correct filename for all findings", () => {
    const source = `pub fn withdraw() { transfer(); } const THRESHOLD: u32 = 1;`;
    const result = scan(source, "my_treasury.rs");
    expect(result.findings.every((f) => f.file === "my_treasury.rs")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — edge cases", () => {
  it("handles source with only comments", () => {
    const source = `// This is a safe treasury implementation\n// No vulnerabilities here`;
    const result = scan(source, "treasury.rs");
    expect(result.status).toBe("SAFE");
    expect(result.findings).toHaveLength(0);
  });

  it("handles very long lines", () => {
    const source = `pub fn withdraw() { ${"transfer(); ".repeat(50)} }`;
    const result = scan(source, "treasury.rs");
    expect(result.status).toBe("VULNERABILITIES_FOUND");
  });

  it("handles mixed-case keywords", () => {
    const source = `pub fn WITHDRAW() { TRANSFER(); }`;
    const result = scan(source, "treasury.rs");
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("returns a timestamp in ISO format", () => {
    const result = scan("fn safe() {}", "safe.rs");
    expect(result.scanTimestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ---------------------------------------------------------------------------
// generateReport
// ---------------------------------------------------------------------------

describe("MultisigTreasuryScanner — generateReport", () => {
  it("produces a markdown report string for safe result", () => {
    const result = scan("fn safe() {}", "safe.rs");
    const report = makeScanner().generateReport(result);
    expect(typeof report).toBe("string");
    expect(report).toContain("Multi-Sig Treasury Governance Audit");
    expect(report).toContain("SAFE");
  });

  it("produces a markdown report string for vulnerable result", () => {
    const result = scan(
      "pub fn withdraw() { transfer(); } const THRESHOLD: u32 = 1;",
      "treasury.rs"
    );
    const report = makeScanner().generateReport(result);
    expect(typeof report).toBe("string");
    expect(report).toContain("VULNERABILITIES_FOUND");
    expect(report).toContain("UNSAFE_SINGLE_SIG_WITHDRAWAL");
    expect(report).toContain("WEAK_THRESHOLD");
  });

  it("includes findings sorted by severity (highest first)", () => {
    const result = scan(
      "admin.withdraw(amount); const THRESHOLD: u32 = 1;",
      "treasury.rs"
    );
    const report = makeScanner().generateReport(result);
    const criticalIdx = report.indexOf("CRITICAL");
    const highIdx = report.indexOf("HIGH");
    expect(criticalIdx).toBeGreaterThanOrEqual(0);
    expect(criticalIdx).toBeLessThan(highIdx);
  });

  it("includes snippet in report", () => {
    const result = scan("const THRESHOLD: u32 = 1;", "treasury.rs");
    const report = makeScanner().generateReport(result);
    expect(report).toContain("const THRESHOLD: u32 = 1;");
  });
});
