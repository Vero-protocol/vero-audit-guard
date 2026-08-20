import * as fs from "fs";
import { AbstractInterpreter, VariableState } from "./abstract-interpreter";

export interface OverflowFinding {
  file: string;
  line: number;
  rule: string;
  severity: "HIGH" | "MEDIUM";
  message: string;
  detail: string;
}

export class OverflowChecker {
  private interpreter: AbstractInterpreter;

  constructor() {
    this.interpreter = new AbstractInterpreter();
  }

  /**
   * Scans files for potential integer overflows using abstract interpretation
   */
  async checkFiles(files: string[]): Promise<OverflowFinding[]> {
    const findings: OverflowFinding[] = [];

    for (const file of files) {
      if (!fs.existsSync(file)) continue;

      // Only scan Rust or TS files for now
      if (!file.endsWith(".rs") && !file.endsWith(".ts")) continue;

      try {
        const content = fs.readFileSync(file, "utf-8");
        const fileFindings = this.analyzeContent(content, file);
        findings.push(...fileFindings);
      } catch (error) {
        console.error(`[OverflowChecker] Error reading file ${file}:`, error);
      }
    }

    return findings;
  }

  /**
   * Simple line-by-line analysis to track variable ranges and detect overflows
   */
  private analyzeContent(content: string, filename: string): OverflowFinding[] {
    const findings: OverflowFinding[] = [];
    const lines = content.split("\n");
    const state: VariableState = new Map();

    // Regex for basic Rust/TS assignments: let x = 10; or let y = x + 5;
    const assignmentRegex = /(?:let|const|var)\s+(\w+)(?:\s*:\s*\w+)?\s*=\s*([^;]+)/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const match = line.match(assignmentRegex);

      if (match) {
        const varName = match[1];
        const expression = match[2].trim();

        const interval = this.interpreter.evaluateExpression(expression, state);

        if (interval) {
          state.set(varName, interval);

          // Check for potential overflow (assuming u64 for Rust as a default heuristic if not specified)
          if (interval.max > AbstractInterpreter.U64_MAX) {
            findings.push({
              file: filename,
              line: i + 1,
              rule: "INTEGER_OVERFLOW",
              severity: "HIGH",
              message: `❌ Potential integer overflow detected in '${varName}'`,
              detail: `Expression '${expression}' evaluates to range ${interval.toString()} which exceeds u64 bounds.`,
            });
          } else if (interval.min < BigInt(0)) {
             findings.push({
              file: filename,
              line: i + 1,
              rule: "INTEGER_UNDERFLOW",
              severity: "HIGH",
              message: `❌ Potential integer underflow detected in '${varName}'`,
              detail: `Expression '${expression}' evaluates to range ${interval.toString()} which is negative (unsigned expected).`,
            });
          }
        }
      }
    }

    return findings;
  }
}

export default OverflowChecker;
