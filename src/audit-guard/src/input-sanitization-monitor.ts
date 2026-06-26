/**
 * Input Sanitization Monitor
 *
 * Issue #14: feat: add input sanitization monitor
 *
 * Fuzz-tests string inputs against boundary and injection probes to detect
 * unsafe handling.  The monitor accepts a validator function (the code under
 * audit) together with a set of named probe categories and returns a
 * structured report of every probe that was not safely handled.
 *
 * Design follows the same conventions as other audit-guard modules:
 *  - Primary class with scan() returning a typed result
 *  - generateReport() producing markdown
 *  - Pure: no I/O, no global state — trivially testable
 */

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export type InputSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

const SEVERITY_RANK: Record<InputSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

// ---------------------------------------------------------------------------
// Probe definitions
// ---------------------------------------------------------------------------

export interface InputProbe {
  /** Unique ID for this probe. */
  id: string;
  /** Short human-readable label. */
  label: string;
  /** The raw string value to feed to the validator. */
  value: string;
  /** Category groups probes for filtering and reporting. */
  category: ProbeCategory;
  /** Expected outcome — what a safe validator should do. */
  expectedBehaviour: "reject" | "sanitize" | "accept";
  severity: InputSeverity;
}

export type ProbeCategory =
  | "sql_injection"
  | "xss"
  | "path_traversal"
  | "command_injection"
  | "overflow"
  | "null_byte"
  | "unicode"
  | "empty"
  | "boundary";

// ---------------------------------------------------------------------------
// Validator contract
// ---------------------------------------------------------------------------

/**
 * The function under audit.
 *
 * Return value semantics:
 *   - Throw / return `false` / return `null` / return `undefined`
 *     → treated as REJECTED (safe for probes where expectedBehaviour is "reject")
 *   - Return any truthy non-string value → treated as ACCEPTED
 *   - Return a string → treated as the sanitized output; the monitor checks
 *     whether dangerous payload survived in the output
 */
export type ValidatorFn = (input: string) => unknown;

// ---------------------------------------------------------------------------
// Finding / result types
// ---------------------------------------------------------------------------

export interface InputFinding {
  probeId: string;
  probeLabel: string;
  category: ProbeCategory;
  severity: InputSeverity;
  input: string;
  /** What actually happened (threw, returned false, returned output …). */
  actualOutcome: "accepted_raw" | "sanitized_unsafe" | "rejected" | "threw";
  /** For "sanitized_unsafe": the output that still contained payload. */
  sanitizedOutput?: string;
  message: string;
  remediation: string;
}

export interface InputScanResult {
  status: "SAFE" | "UNSAFE_INPUTS_FOUND";
  findings: InputFinding[];
  totalProbes: number;
  unsafeCount: number;
  summary: string;
  scanTimestamp: string;
  categoryCounts: Record<ProbeCategory, number>;
}

export interface InputMonitorOptions {
  /** Restrict scan to specific categories. Default: all. */
  categories?: ProbeCategory[];
  /** Custom probes to append to the built-in set. */
  extraProbes?: InputProbe[];
  /** Label for the validator being tested (used in the report). */
  validatorName?: string;
}

// ---------------------------------------------------------------------------
// Built-in probe library
// ---------------------------------------------------------------------------

const BUILT_IN_PROBES: InputProbe[] = [
  // ── SQL injection ─────────────────────────────────────────────────────
  {
    id: "SQL_001",
    label: "Classic OR 1=1 tautology",
    value: "' OR '1'='1",
    category: "sql_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "SQL_002",
    label: "UNION SELECT exfiltration",
    value: "1 UNION SELECT username, password FROM users--",
    category: "sql_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "SQL_003",
    label: "Stacked queries via semicolon",
    value: "1; DROP TABLE users--",
    category: "sql_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "SQL_004",
    label: "Comment stripping bypass",
    value: "ad/**/min",
    category: "sql_injection",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },

  // ── XSS ──────────────────────────────────────────────────────────────
  {
    id: "XSS_001",
    label: "Basic script tag",
    value: "<script>alert(1)</script>",
    category: "xss",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },
  {
    id: "XSS_002",
    label: "Attribute injection onerror",
    value: '<img src=x onerror="alert(1)">',
    category: "xss",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },
  {
    id: "XSS_003",
    label: "JavaScript URI",
    value: "javascript:alert(document.cookie)",
    category: "xss",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },
  {
    id: "XSS_004",
    label: "SVG onload vector",
    value: "<svg onload=alert(1)>",
    category: "xss",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },

  // ── Path traversal ────────────────────────────────────────────────────
  {
    id: "PATH_001",
    label: "Unix dot-dot-slash",
    value: "../../etc/passwd",
    category: "path_traversal",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "PATH_002",
    label: "URL-encoded traversal",
    value: "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    category: "path_traversal",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "PATH_003",
    label: "Windows backslash traversal",
    value: "..\\..\\windows\\system32\\config\\sam",
    category: "path_traversal",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },

  // ── Command injection ─────────────────────────────────────────────────
  {
    id: "CMD_001",
    label: "Semicolon command chaining",
    value: "valid; rm -rf /",
    category: "command_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "CMD_002",
    label: "Backtick command substitution",
    value: "`whoami`",
    category: "command_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "CMD_003",
    label: "Pipe to shell",
    value: "foo | cat /etc/shadow",
    category: "command_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },
  {
    id: "CMD_004",
    label: "Dollar-paren substitution",
    value: "$(id)",
    category: "command_injection",
    expectedBehaviour: "reject",
    severity: "CRITICAL",
  },

  // ── Overflow / boundary ───────────────────────────────────────────────
  {
    id: "OVF_001",
    label: "Very long string (10 000 chars)",
    value: "A".repeat(10_000),
    category: "overflow",
    expectedBehaviour: "reject",
    severity: "MEDIUM",
  },
  {
    id: "OVF_002",
    label: "Max safe integer as string",
    value: String(Number.MAX_SAFE_INTEGER),
    category: "boundary",
    expectedBehaviour: "accept",
    severity: "LOW",
  },
  {
    id: "OVF_003",
    label: "Negative number",
    value: "-1",
    category: "boundary",
    expectedBehaviour: "accept",
    severity: "LOW",
  },
  {
    id: "OVF_004",
    label: "Floating point edge",
    value: "1.7976931348623157e+308",
    category: "boundary",
    expectedBehaviour: "accept",
    severity: "LOW",
  },

  // ── Null byte ─────────────────────────────────────────────────────────
  {
    id: "NULL_001",
    label: "Null byte injection",
    value: "valid\x00.php",
    category: "null_byte",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },
  {
    id: "NULL_002",
    label: "Null byte mid-string",
    value: "admin\x00extra",
    category: "null_byte",
    expectedBehaviour: "reject",
    severity: "HIGH",
  },

  // ── Unicode ───────────────────────────────────────────────────────────
  {
    id: "UNI_001",
    label: "Unicode right-to-left override",
    value: "\u202Eevil",
    category: "unicode",
    expectedBehaviour: "reject",
    severity: "MEDIUM",
  },
  {
    id: "UNI_002",
    label: "Overlong UTF-8 sequence (simulated)",
    value: "\uFFFD\uFFFE\uFFFF",
    category: "unicode",
    expectedBehaviour: "reject",
    severity: "MEDIUM",
  },
  {
    id: "UNI_003",
    label: "Zero-width non-joiner bypass",
    value: "scr\u200Bipt",
    category: "unicode",
    expectedBehaviour: "reject",
    severity: "MEDIUM",
  },

  // ── Empty / whitespace ────────────────────────────────────────────────
  {
    id: "EMPTY_001",
    label: "Empty string",
    value: "",
    category: "empty",
    expectedBehaviour: "reject",
    severity: "LOW",
  },
  {
    id: "EMPTY_002",
    label: "Whitespace only",
    value: "   \t\n",
    category: "empty",
    expectedBehaviour: "reject",
    severity: "LOW",
  },
];

// ---------------------------------------------------------------------------
// Dangerous payload fragments — if these survive sanitization, flag
// ---------------------------------------------------------------------------

const DANGEROUS_FRAGMENTS: string[] = [
  "<script",
  "onerror=",
  "onload=",
  "javascript:",
  "' or ",
  "union select",
  "drop table",
  "../",
  "..\\",
  "%2e%2e",
  "\x00",
  "; rm ",
  "| cat ",
  "`whoami`",
  "$(id)",
  "\u202e",
];

function containsDangerousFragment(output: string): boolean {
  const lower = output.toLowerCase();
  return DANGEROUS_FRAGMENTS.some((frag) => lower.includes(frag.toLowerCase()));
}

// ---------------------------------------------------------------------------
// Main class
// ---------------------------------------------------------------------------

export class InputSanitizationMonitor {
  private readonly probes: InputProbe[];
  private readonly validatorName: string;

  constructor(options: InputMonitorOptions = {}) {
    this.validatorName = options.validatorName ?? "validator";
    const base = BUILT_IN_PROBES.filter(
      (p) =>
        !options.categories || options.categories.includes(p.category)
    );
    this.probes = [...base, ...(options.extraProbes ?? [])];
  }

  /**
   * Run all probes against the supplied validator function and return a
   * structured result.
   */
  public scan(validator: ValidatorFn): InputScanResult {
    if (typeof validator !== "function") {
      throw new Error("InputSanitizationMonitor.scan: validator must be a function");
    }

    const findings: InputFinding[] = [];
    const categoryCounts = {} as Record<ProbeCategory, number>;

    for (const probe of this.probes) {
      const finding = this.runProbe(probe, validator);
      if (finding) {
        findings.push(finding);
        categoryCounts[probe.category] = (categoryCounts[probe.category] ?? 0) + 1;
      }
    }

    // Sort CRITICAL first then by category
    findings.sort((a, b) => {
      const sr = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      return sr !== 0 ? sr : a.category.localeCompare(b.category);
    });

    const status: InputScanResult["status"] =
      findings.length === 0 ? "SAFE" : "UNSAFE_INPUTS_FOUND";

    const summary =
      status === "SAFE"
        ? `✅ All ${this.probes.length} probes handled safely by ${this.validatorName}`
        : `❌ ${findings.length} unsafe input(s) accepted by ${this.validatorName} (${this.probes.length} probes total)`;

    return {
      status,
      findings,
      totalProbes: this.probes.length,
      unsafeCount: findings.length,
      summary,
      scanTimestamp: new Date().toISOString(),
      categoryCounts,
    };
  }

  /** Render a markdown report from a scan result. */
  public generateReport(result: InputScanResult): string {
    const emoji = result.status === "SAFE" ? "✅" : "❌";
    let report = `## ${emoji} Input Sanitization Monitor\n\n`;
    report += `**Validator:** \`${this.validatorName}\`\n\n`;
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `**Probes run:** ${result.totalProbes}  |  **Unsafe:** ${result.unsafeCount}\n\n`;
    report += `${result.summary}\n\n`;

    if (result.findings.length === 0) {
      return report;
    }

    report += "---\n\n### ❌ Unsafe Input Findings\n\n";

    let lastCategory = "";
    for (const f of result.findings) {
      if (f.category !== lastCategory) {
        report += `\n#### ${f.category.replace(/_/g, " ").toUpperCase()}\n\n`;
        lastCategory = f.category;
      }
      const inputDisplay = f.input.length > 60
        ? f.input.slice(0, 57) + "..."
        : f.input;
      report += `- **${f.probeId}** [${f.severity}] ${f.probeLabel}\n`;
      report += `  Input: \`${inputDisplay}\`\n`;
      report += `  Outcome: \`${f.actualOutcome}\`\n`;
      if (f.sanitizedOutput !== undefined) {
        const outDisplay = f.sanitizedOutput.length > 60
          ? f.sanitizedOutput.slice(0, 57) + "..."
          : f.sanitizedOutput;
        report += `  Sanitized output still contained payload: \`${outDisplay}\`\n`;
      }
      report += `  _${f.message}_\n`;
      report += `  Remediation: ${f.remediation}\n\n`;
    }

    if (Object.keys(result.categoryCounts).length > 0) {
      report += "---\n\n### Findings by Category\n\n";
      for (const [cat, count] of Object.entries(result.categoryCounts)) {
        report += `- **${cat.replace(/_/g, " ")}**: ${count}\n`;
      }
      report += "\n";
    }

    return report;
  }

  /** Expose the probe list (read-only) — useful for introspection. */
  public get probeIds(): string[] {
    return this.probes.map((p) => p.id);
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private runProbe(probe: InputProbe, validator: ValidatorFn): InputFinding | null {
    let result: unknown;
    let threw = false;

    try {
      result = validator(probe.value);
    } catch {
      threw = true;
    }

    // Probe expects rejection — validator should throw or return falsy
    if (probe.expectedBehaviour === "reject") {
      if (threw) return null; // threw — safe
      if (result === false || result === null || result === undefined) return null; // falsy — safe

      // Accepted when it should have rejected
      if (typeof result === "string") {
        // Check if dangerous payload survived in the sanitized output
        if (containsDangerousFragment(result)) {
          return this.makeFinding(probe, "sanitized_unsafe", result,
            `Validator returned sanitized output that still contains dangerous payload.`,
            this.remediation(probe.category));
        }
        // Payload was neutralised in the string output — consider safe
        return null;
      }

      // Returned truthy non-string — accepted without sanitizing
      return this.makeFinding(probe, "accepted_raw", undefined,
        `Validator accepted a ${probe.category.replace(/_/g, " ")} payload without rejecting it.`,
        this.remediation(probe.category));
    }

    // Probe expects acceptance — validator should return truthy (not throw / return false)
    if (probe.expectedBehaviour === "accept") {
      if (threw) {
        return this.makeFinding(probe, "threw", undefined,
          `Validator unexpectedly threw on a value that should be accepted (over-aggressive rejection).`,
          "Ensure boundary/valid values are not falsely rejected — review validation bounds.");
      }
      if (result === false || result === null || result === undefined) {
        return this.makeFinding(probe, "rejected", undefined,
          `Validator rejected a value that should be accepted (false positive in validation).`,
          "Ensure valid boundary values pass through — review min/max thresholds.");
      }
      return null; // accepted — correct
    }

    // expectedBehaviour === "sanitize": validator must return a string with
    // no dangerous fragment
    if (probe.expectedBehaviour === "sanitize") {
      if (threw) return null; // safe — threw
      if (result === false || result === null || result === undefined) return null; // rejected — safe
      if (typeof result === "string") {
        if (containsDangerousFragment(result)) {
          return this.makeFinding(probe, "sanitized_unsafe", result,
            `Sanitizer returned output that still contains a dangerous fragment.`,
            this.remediation(probe.category));
        }
        return null;
      }
      // Non-string truthy — cannot verify sanitization
      return this.makeFinding(probe, "accepted_raw", undefined,
        `Sanitizer returned a non-string value — cannot verify payload was neutralised.`,
        "Sanitizers should return a clean string, not a boolean or object.");
    }

    return null;
  }

  private makeFinding(
    probe: InputProbe,
    outcome: InputFinding["actualOutcome"],
    sanitizedOutput: string | undefined,
    message: string,
    remediation: string
  ): InputFinding {
    return {
      probeId: probe.id,
      probeLabel: probe.label,
      category: probe.category,
      severity: probe.severity,
      input: probe.value,
      actualOutcome: outcome,
      sanitizedOutput,
      message,
      remediation,
    };
  }

  private remediation(category: ProbeCategory): string {
    const map: Record<ProbeCategory, string> = {
      sql_injection:
        "Use parameterised queries / prepared statements. Never interpolate user input into SQL strings.",
      xss:
        "HTML-encode output using a trusted library (DOMPurify, he, sanitize-html). Never inject raw user input into the DOM.",
      path_traversal:
        "Resolve and validate the canonical path against an allowed base directory. Reject inputs containing '..' or encoded equivalents.",
      command_injection:
        "Never pass user input to a shell command. Use child_process.execFile with an argument array, not execSync with a string.",
      overflow:
        "Enforce maximum length on all string inputs before processing.",
      null_byte:
        "Strip or reject null bytes (\\x00) from all inputs before passing them to file system, database, or C-extension APIs.",
      unicode:
        "Normalise to NFC before validation, then reject or strip dangerous control characters and direction-override codepoints.",
      empty:
        "Validate that required fields are non-empty and non-whitespace before processing.",
      boundary:
        "Define and enforce explicit min/max bounds for numeric and string length inputs.",
    };
    return map[category] ?? "Validate and sanitize this input before use.";
  }
}

export default InputSanitizationMonitor;

/** Convenience: run a quick scan and get the report string in one call. */
export function scanAndReport(
  validator: ValidatorFn,
  options: InputMonitorOptions = {}
): { result: InputScanResult; report: string } {
  const monitor = new InputSanitizationMonitor(options);
  const result = monitor.scan(validator);
  return { result, report: monitor.generateReport(result) };
}
