/**
 * Tests for InputSanitizationMonitor — Issue #14
 *
 * Covers:
 *  - Unsafe inputs flagged (SQL injection, XSS, path traversal, etc.)
 *  - Safe validator reports SAFE
 *  - Sanitizer that leaks payload is flagged
 *  - Over-aggressive validator flagged for boundary probes
 *  - Category filtering
 *  - Extra probes
 *  - generateReport() output shape
 *  - Input validation (non-function throws)
 */

import InputSanitizationMonitor, {
  scanAndReport,
  ValidatorFn,
  InputScanResult,
} from "./input-sanitization-monitor";

// ---------------------------------------------------------------------------
// Validator fixtures
// ---------------------------------------------------------------------------

/** Rejects everything — safe for all "reject" probes. */
const rejectAll: ValidatorFn = () => false;

/** Accepts everything — unsafe for all "reject" probes. */
const acceptAll: ValidatorFn = () => true;

/**
 * Realistic safe validator: rejects null bytes, traversal, injection chars,
 * overlong strings, and empty/whitespace; accepts valid boundary values.
 */
const safeValidator: ValidatorFn = (input: string) => {
  if (!input || input.trim() === "") return false;
  if (input.length > 1000) return false;
  if (/[\x00]/.test(input)) return false;
  if (/[<>"'`;|$`\\]/.test(input)) return false;
  if (/\.\.[\\/]/.test(input)) return false;
  if (/%2e%2e/i.test(input)) return false;
  if (/(union\s+select|drop\s+table|or\s+'1'='1)/i.test(input)) return false;
  if (/javascript:/i.test(input)) return false;
  if (/[\u202e\ufffe\uffff\ufffd\u200b]/.test(input)) return false;
  return input.trim();
};

/** Sanitizer that strips <script> but leaves onerror= intact (leaks payload). */
const leakySanitizer: ValidatorFn = (input: string) =>
  input.replace(/<script[^>]*>.*?<\/script>/gi, "");

/** Validator that rejects valid boundary numbers too aggressively. */
const overRejectingValidator: ValidatorFn = (input: string) => {
  // Only accept single-digit positive integers — too restrictive
  if (/^[1-9]$/.test(input)) return true;
  return false;
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — input validation", () => {
  it("throws when validator is not a function", () => {
    const monitor = new InputSanitizationMonitor();
    expect(() => monitor.scan(null as unknown as ValidatorFn)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Safe validator
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — safe validator", () => {
  it("returns SAFE when the validator correctly rejects all injection probes", () => {
    const monitor = new InputSanitizationMonitor();
    const result = monitor.scan(safeValidator);
    expect(result.status).toBe("SAFE");
    expect(result.unsafeCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Unsafe validator (accept-all)
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — accept-all validator", () => {
  it("returns UNSAFE_INPUTS_FOUND when everything is accepted", () => {
    const monitor = new InputSanitizationMonitor();
    const result = monitor.scan(acceptAll);
    expect(result.status).toBe("UNSAFE_INPUTS_FOUND");
    expect(result.unsafeCount).toBeGreaterThan(0);
  });

  it("flags SQL injection probes", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["sql_injection"] });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.category === "sql_injection")).toBe(true);
  });

  it("flags XSS probes", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["xss"] });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.category === "xss")).toBe(true);
  });

  it("flags path traversal probes", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["path_traversal"] });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.category === "path_traversal")).toBe(true);
  });

  it("flags command injection probes", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["command_injection"] });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.category === "command_injection")).toBe(true);
  });

  it("flags null byte probes", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["null_byte"] });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.category === "null_byte")).toBe(true);
  });

  it("CRITICAL findings are sorted before HIGH", () => {
    const monitor = new InputSanitizationMonitor();
    const result = monitor.scan(acceptAll);
    const ranks = result.findings.map((f) =>
      ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[f.severity])
    );
    const sorted = [...ranks].sort((a, b) => b - a);
    expect(ranks).toEqual(sorted);
  });
});

// ---------------------------------------------------------------------------
// Reject-all validator — boundary probes should be flagged
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — reject-all validator", () => {
  it("flags boundary probes that should be accepted", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["boundary"] });
    const result = monitor.scan(rejectAll);
    // boundary probes have expectedBehaviour "accept" — rejectAll will fail them
    expect(result.findings.some((f) => f.category === "boundary")).toBe(true);
    expect(result.findings[0].actualOutcome).toBe("rejected");
  });

  it("over-aggressive validator also flags valid boundary values", () => {
    // overRejectingValidator only accepts single-digit positives
    const monitor = new InputSanitizationMonitor({ categories: ["boundary"] });
    const result = monitor.scan(overRejectingValidator);
    expect(result.findings.some((f) => f.category === "boundary")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Leaky sanitizer
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — leaky sanitizer", () => {
  it("flags XSS probe whose payload survives sanitization", () => {
    // leakySanitizer strips <script> but leaves onerror= intact
    const monitor = new InputSanitizationMonitor({ categories: ["xss"] });
    const result = monitor.scan(leakySanitizer);
    const onerrorFinding = result.findings.find(
      (f) => f.probeId === "XSS_002" || f.sanitizedOutput?.includes("onerror")
    );
    expect(onerrorFinding).toBeDefined();
    expect(onerrorFinding!.actualOutcome).toBe("sanitized_unsafe");
  });
});

// ---------------------------------------------------------------------------
// Category filtering
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — category filtering", () => {
  it("only runs probes in the specified categories", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["sql_injection"] });
    const result = monitor.scan(acceptAll);
    const categories = new Set(result.findings.map((f) => f.category));
    expect(categories.size).toBe(1);
    expect(categories.has("sql_injection")).toBe(true);
  });

  it("probeIds reflects the filtered set", () => {
    const monitor = new InputSanitizationMonitor({ categories: ["xss"] });
    expect(monitor.probeIds.every((id) => id.startsWith("XSS"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Extra probes
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — extra probes", () => {
  it("custom probes are included and can produce findings", () => {
    const monitor = new InputSanitizationMonitor({
      categories: ["sql_injection"],
      extraProbes: [
        {
          id: "CUSTOM_001",
          label: "Custom sleep injection",
          value: "1; WAITFOR DELAY '0:0:5'--",
          category: "sql_injection",
          expectedBehaviour: "reject",
          severity: "CRITICAL",
        },
      ],
    });
    const result = monitor.scan(acceptAll);
    expect(result.findings.some((f) => f.probeId === "CUSTOM_001")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// totalProbes
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — probe counts", () => {
  it("totalProbes equals probeIds length", () => {
    const monitor = new InputSanitizationMonitor();
    const result = monitor.scan(safeValidator);
    expect(result.totalProbes).toBe(monitor.probeIds.length);
  });
});

// ---------------------------------------------------------------------------
// generateReport
// ---------------------------------------------------------------------------

describe("InputSanitizationMonitor — generateReport", () => {
  let result: InputScanResult;
  let monitor: InputSanitizationMonitor;

  beforeAll(() => {
    monitor = new InputSanitizationMonitor({ validatorName: "testFn" });
    result = monitor.scan(acceptAll);
  });

  it("produces a string report", () => {
    expect(typeof monitor.generateReport(result)).toBe("string");
  });

  it("includes validator name", () => {
    expect(monitor.generateReport(result)).toContain("testFn");
  });

  it("includes status", () => {
    expect(monitor.generateReport(result)).toContain(result.status);
  });

  it("includes category headings for findings", () => {
    const report = monitor.generateReport(result);
    expect(report).toContain("SQL INJECTION");
  });

  it("SAFE report has no findings section", () => {
    const safeMonitor = new InputSanitizationMonitor();
    const safeResult = safeMonitor.scan(safeValidator);
    const report = safeMonitor.generateReport(safeResult);
    expect(report).toContain("SAFE");
    expect(report).not.toContain("Unsafe Input Findings");
  });
});

// ---------------------------------------------------------------------------
// scanAndReport convenience helper
// ---------------------------------------------------------------------------

describe("scanAndReport helper", () => {
  it("returns both result and report", () => {
    const { result, report } = scanAndReport(safeValidator);
    expect(result.status).toBe("SAFE");
    expect(typeof report).toBe("string");
  });

  it("respects options passed through", () => {
    const { result } = scanAndReport(acceptAll, { categories: ["xss"] });
    expect(result.findings.every((f) => f.category === "xss")).toBe(true);
  });
});
