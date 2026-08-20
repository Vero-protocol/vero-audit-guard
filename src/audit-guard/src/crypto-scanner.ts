/**
 * Weak Cryptographic Primitive Scanner
 *
 * Issue #103: [Audit-Guard #8] Scan for weak cryptographic primitives
 *
 * Scans a code snippet for weak cryptographic primitives by running each
 * pattern in the pattern library against the input. Findings are aggregated
 * and returned as a `CryptoScanResult` with an overall status and a list of
 * `CryptoFinding`s — one per detected issue, with line numbers and
 * remediation guidance.
 *
 * The scanner itself is a thin orchestrator; all of the actual heuristics
 * live in `crypto-patterns.ts` so they can be unit-tested and composed
 * individually.
 */

import { CRYPTO_PATTERNS, CryptoPattern } from "./crypto-patterns";

export type CryptoSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** A single weak-crypto finding. */
export interface CryptoFinding {
  file?: string;
  /** 1-indexed line number within the scanned snippet. */
  line?: number;
  snippet: string;
  ruleId: string;
  severity: CryptoSeverity;
  message: string;
  remediation: string;
}

/** Aggregated result of a scan. */
export interface CryptoScanResult {
  /** SAFE = no findings; VULNERABLE = at least one finding. */
  status: "SAFE" | "VULNERABLE";
  findings: CryptoFinding[];
  count: number;
  summary: string;
  scanTimestamp: string;
  /** Optional snapshot of the patterns that ran (ids). Useful for triage. */
  patternIds: string[];
}

/** Options accepted by `WeakCryptoScanner.scan`. */
export interface CryptoScanOptions {
  file?: string;
  /** Restrict scanning to a subset of pattern ids. */
  patterns?: string[];
}

const SEVERITY_RANK: Record<CryptoSeverity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * The scanner runs every pattern by default; callers may restrict
 * to a subset via `options.patterns`. The scanner is intentionally
 * pure — no I/O, no side effects.
 */
export class WeakCryptoScanner {
  private readonly patterns: CryptoPattern[];

  constructor(patterns: CryptoPattern[] = CRYPTO_PATTERNS as CryptoPattern[]) {
    this.patterns = patterns;
  }

  /**
   * Scan a snippet and produce an aggregated result.
   * Returns `status: "SAFE"` if no findings fire.
   */
  public scan(code: string, options: CryptoScanOptions = {}): CryptoScanResult {
    if (typeof code !== "string") {
      throw new Error("WeakCryptoScanner.scan: code must be a string");
    }

    const active = options.patterns
      ? this.patterns.filter((p) => options.patterns!.includes(p.id))
      : this.patterns;

    const context = {
      file: options.file,
      lines: code.split(/\r?\n/),
    };

    const findings: CryptoFinding[] = [];
    for (const pattern of active) {
      try {
        const result = pattern.detect(code, context) ?? [];
        for (const f of result) findings.push(f);
      } catch (err) {
        // A buggy pattern must not poison the whole scan — skip and log.
        // eslint-disable-next-line no-console
        console.warn(
          `[WeakCryptoScanner] pattern ${pattern.id} threw: ${(err as Error).message}`
        );
      }
    }

    // Sort by severity (CRITICAL first) then by line number.
    findings.sort((a, b) => {
      const sa = SEVERITY_RANK[a.severity] ?? 0;
      const sb = SEVERITY_RANK[b.severity] ?? 0;
      if (sa !== sb) return sb - sa;
      const la = a.line ?? 0;
      const lb = b.line ?? 0;
      return la - lb;
    });

    const status: CryptoScanResult["status"] =
      findings.length === 0 ? "SAFE" : "VULNERABLE";

    const summary =
      status === "SAFE"
        ? "No weak cryptographic primitives detected"
        : `${findings.length} weak-crypto finding(s) — review before merging`;

    return {
      status,
      findings,
      count: findings.length,
      summary,
      scanTimestamp: new Date().toISOString(),
      patternIds: active.map((p) => p.id),
    };
  }

  /** Render a markdown report for humans. */
  public generateReport(result: CryptoScanResult): string {
    const emoji = result.status === "SAFE" ? "✅" : "❌";
    let report = `## ${emoji} Weak Cryptographic Primitive Scan\n\n`;
    if (result.findings.length > 0 && result.findings[0].file) {
      report += `**File:** \`${result.findings[0].file}\`\n\n`;
    }
    report += `**Status:** ${result.status}\n\n`;
    report += `**Scanned at:** ${result.scanTimestamp}\n\n`;
    report += `${result.summary}\n\n`;
    report += `**Patterns evaluated:** ${result.patternIds.length}\n\n`;

    if (result.findings.length === 0) {
      return report;
    }

    report += `### ❌ Findings\n\n`;
    for (const f of result.findings) {
      const lineLabel = f.line ? `(line ${f.line})` : "";
      report += `- **${f.ruleId}** [${f.severity}] ${lineLabel}\n`;
      report += `  ${f.message}\n`;
      report += `  \`\`\`\n  ${f.snippet}\n  \`\`\`\n`;
      report += `  _Remediation:_ ${f.remediation}\n\n`;
    }
    return report;
  }

  /** Get the patterns this scanner runs (read-only). */
  public get patternIds(): string[] {
    return this.patterns.map((p) => p.id);
  }
}

export default WeakCryptoScanner;
