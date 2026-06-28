/**
 * Vero Audit Guard - Rust Safety Scanner
 * Validates adherence to Rust safety standards and integrates with existing Audit-Guard API.
 */
import type { DetectionContext, LogicFlawFinding } from "./logic-patterns";

export interface RustSafetyFinding extends LogicFlawFinding {
  isUnsafeBlock?: boolean;
}

export class RustSafetyScanner {
  public scan(code: string, context?: DetectionContext): RustSafetyFinding[] {
    const findings: RustSafetyFinding[] = [];
    const lines = context?.lines || code.split(/\r?\n/);
    
    for (let i = 0; i < lines.length; i++) {
      if (/\bunsafe\s*\{/.test(lines[i])) {
        findings.push({
          file: context?.file,
          line: i + 1,
          ruleId: "RUST_UNSAFE_BLOCK",
          severity: "HIGH",
          message: `Unsafe block detected on line ${i + 1}.`,
          remediation: "Ensure all unsafe blocks are strictly necessary and formally verified. Adhere to Rust safety standards.",
          isUnsafeBlock: true,
        });
      }
    }
    
    return findings;
  }
}
export default RustSafetyScanner;
