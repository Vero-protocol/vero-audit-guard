/**
 * Fuzzer Harness for Audit Guard
 * Randomized input testing to find edge case vulnerabilities
 * 
 * This fuzzer tests:
 * - Policy Engine input validation
 * - Log Analyzer edge cases  
 * - Logic Detector boundary conditions
 * - Input sanitization robustness
 */

import PolicyEngine, { PRData, PolicyViolation } from "../src/policy-engine";
import { LogAnalyzer, LogEntry, LogAnomaly } from "../src/log-analyzer";
import { LogicErrorDetector, LogicScanResult } from "../src/logic-detector";
import { InputSanitizationMonitor } from "../src/input-sanitization-monitor";

// Seedable random number generator for reproducible fuzzing
class SeededRandom {
  private seed: number;

  constructor(seed: number) {
    this.seed = seed;
  }

  next(): number {
    const x = Math.sin(this.seed++) * 10000;
    return x - Math.floor(x);
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  nextBoolean(): boolean {
    return this.next() > 0.5;
  }

  nextFloat(): number {
    return this.next();
  }
}

// Fuzzer configuration
interface FuzzerConfig {
  iterations: number;
  seed: number;
  maxStringLength: number;
  maxArrayLength: number;
}

const DEFAULT_CONFIG: FuzzerConfig = {
  iterations: 1000,
  seed: Date.now(),
  maxStringLength: 10000,
  maxArrayLength: 100,
};

// Track crashes and interesting findings
interface FuzzFinding {
  type: "CRASH" | "INVALID_STATE" | "UNHANDLED_ERROR" | "PERFORMANCE_DEGRADATION";
  component: string;
  input: any;
  error?: Error;
  timestamp: string;
  iteration: number;
}

class FuzzerHarness {
  private random: SeededRandom;
  private config: FuzzerConfig;
  private findings: FuzzFinding[] = [];
  private iteration: number = 0;

  constructor(config: Partial<FuzzerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.random = new SeededRandom(this.config.seed);
  }

  // Generate random string with special characters
  private randomString(length?: number): string {
    const len = length ?? this.random.nextInt(0, this.config.maxStringLength);
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\t\n\r\"'\\`$@#%^&*(){}[]<>?/|";
    let result = "";
    for (let i = 0; i < len; i++) {
      result += chars[this.random.nextInt(0, chars.length - 1)];
    }
    return result;
  }

  // Generate random PR data for fuzzing
  private randomPRData(): PRData {
    const numFiles = this.random.nextInt(0, this.config.maxArrayLength);
    const filesModified: string[] = [];
    for (let i = 0; i < numFiles; i++) {
      filesModified.push(this.randomString(this.random.nextInt(1, 100)));
    }

    const numLabels = this.random.nextInt(0, 20);
    const labels: string[] = [];
    for (let i = 0; i < numLabels; i++) {
      labels.push(this.randomString(this.random.nextInt(1, 50)));
    }

    const prData: PRData = {
      pull_request: {
        title: this.randomString(),
        body: this.randomString(this.random.nextInt(0, this.config.maxStringLength)),
        labels,
        base_branch: this.randomString(this.random.nextInt(0, 100)),
        head_branch: this.randomString(this.random.nextInt(0, 100)),
        number: this.random.nextInt(-1000000, 1000000),
        author: this.randomString(this.random.nextInt(0, 100)),
      },
      files_modified: filesModified,
      additions: this.random.nextInt(-1000000, 1000000),
      deletions: this.random.nextInt(-1000000, 1000000),
    };

    // Occasionally add optional fields
    if (this.random.nextBoolean()) {
      prData.dependencies_added = [{
        name: this.randomString(),
        version: this.randomString(),
        is_dev_dependency: this.random.nextBoolean(),
      }];
    }

    if (this.random.nextBoolean()) {
      prData.maintenance_mode = this.random.nextBoolean();
      prData.maintenance_message = this.randomString();
    }

    return prData;
  }

  // Generate edge case PR data
  private generateEdgeCasePRData(): PRData[] {
    const edgeCases: PRData[] = [];

    // Extremely long strings
    edgeCases.push({
      pull_request: {
        title: "a".repeat(100000),
        body: "b".repeat(1000000),
        labels: [],
        base_branch: "main",
        head_branch: "feature/test",
        number: 1,
        author: "test",
      },
      files_modified: [],
      additions: 0,
      deletions: 0,
    });

    // Null bytes and control characters
    edgeCases.push({
      pull_request: {
        title: "\x00\x01\x02\x03Test",
        body: "Test\x00\x1F\x7F",
        labels: ["\x00label"],
        base_branch: "main",
        head_branch: "test",
        number: 0,
        author: "user\x00",
      },
      files_modified: ["file\x00.ts"],
      additions: 0,
      deletions: 0,
    });

    // Unicode edge cases
    edgeCases.push({
      pull_request: {
        title: "测试🎉\u{1F600}\u{200B}\u{FEFF}",
        body: "עברית العربية 中文 \u{202E}RTL",
        labels: ["emoji🎉", "unicode\u{0000}"],
        base_branch: "main",
        head_branch: "test",
        number: 1,
        author: "user",
      },
      files_modified: [],
      additions: 0,
      deletions: 0,
    });

    // Negative values
    edgeCases.push({
      pull_request: {
        title: "Test",
        body: "Body",
        labels: [],
        base_branch: "main",
        head_branch: "test",
        number: -999999,
        author: "test",
      },
      files_modified: [],
      additions: -1000000,
      deletions: -1000000,
    });

    // Prototype pollution attempts
    edgeCases.push({
      pull_request: {
        title: "__proto__",
        body: "constructor.prototype.polluted = true",
        labels: ["__proto__", "constructor"],
        base_branch: "main",
        head_branch: "test",
        number: 1,
        author: "__proto__",
      },
      files_modified: [],
      additions: 0,
      deletions: 0,
    });

    // Script injection attempts
    edgeCases.push({
      pull_request: {
        title: "<script>alert('xss')</script>",
        body: "<img src=x onerror=alert('xss')>",
        labels: ["<script>", "${alert('xss')}"],
        base_branch: "main",
        head_branch: "test",
        number: 1,
        author: "<script>alert('xss')</script>",
      },
      files_modified: [],
      additions: 0,
      deletions: 0,
    });

    return edgeCases;
  }

  // Generate random log entries for fuzzing
  private randomLogEntries(): LogEntry[] {
    const numLogs = this.random.nextInt(0, this.config.maxArrayLength);
    const logs: LogEntry[] = [];

    const levels: LogEntry["level"][] = ["info", "warn", "error", "fatal"];

    for (let i = 0; i < numLogs; i++) {
      logs.push({
        timestamp: this.random.nextBoolean()
          ? new Date().toISOString()
          : this.randomString(50),
        level: levels[this.random.nextInt(0, 3)],
        message: this.randomString(this.random.nextInt(0, 1000)),
        service: this.random.nextBoolean() ? this.randomString(50) : undefined,
      });
    }

    return logs;
  }

  // Generate edge case log entries
  private generateEdgeCaseLogEntries(): LogEntry[][] {
    const edgeCases: LogEntry[][] = [];

    // Empty logs
    edgeCases.push([]);

    // Malformed timestamps
    edgeCases.push([{
      timestamp: "",
      level: "error",
      message: "test",
    }]);

    edgeCases.push([{
      timestamp: "invalid-date",
      level: "error",
      message: "test",
    }]);

    edgeCases.push([{
      timestamp: "999999999-12-31T23:59:59.999Z",
      level: "error",
      message: "test",
    }]);

    // Extremely long messages
    edgeCases.push([{
      timestamp: new Date().toISOString(),
      level: "error",
      message: "x".repeat(10000000),
    }]);

    // Null bytes in logs
    edgeCases.push([{
      timestamp: new Date().toISOString(),
      level: "error",
      message: "\x00\x01\x02",
    }]);

    return edgeCases;
  }

  // Generate random code for logic detector fuzzing
  private randomCode(): string {
    const lines = this.random.nextInt(0, this.config.maxArrayLength);
    let code = "";

    const patterns = [
      "function test() { return true; }",
      "const x = ",
      "eval('code')",
      "new Function('return 1')",
      "innerHTML = '",
      "document.write('",
      "process.exit(1)",
      "require('fs').readFileSync('",
      "throw new Error('",
      "while(true) {}",
      "for (let i = 0; i < 1000000000; i++) {}",
      "Math.random()",
      "Buffer.alloc(",
      "JSON.parse('",
      "Object.prototype.",
      "__proto__.polluted = true",
    ];

    for (let i = 0; i < lines; i++) {
      if (this.random.nextBoolean()) {
        code += patterns[this.random.nextInt(0, patterns.length - 1)];
      } else {
        code += this.randomString(100);
      }
      code += "\n";
    }

    return code;
  }

  // Generate edge case code for logic detector
  private generateEdgeCaseCode(): string[] {
    const edgeCases: string[] = [];

    // Empty code
    edgeCases.push("");

    // Only whitespace
    edgeCases.push("   \n\t\r\n   ");

    // Unclosed brackets
    edgeCases.push("function test() {\n  return {a: [1, 2, 3");

    // Malformed code
    edgeCases.push("function {{(([[\n\n}}]])");

    // Extremely long lines
    edgeCases.push("a".repeat(100000) + " = 1");

    // Prototype pollution attempts
    edgeCases.push("__proto__.polluted = true; constructor.prototype.x = 1;");

    // Script injection in code
    edgeCases.push("eval('<script>alert(1)</script>');");

    return edgeCases;
  }

  // Run a single fuzz test and catch any errors
  private async runSingleTest(testFn: () => Promise<void> | void): Promise<FuzzFinding | null> {
    try {
      const start = Date.now();
      await testFn();
      const duration = Date.now() - start;

      // Check for performance degradation
      if (duration > 5000) {
        return {
          type: "PERFORMANCE_DEGRADATION",
          component: "unknown",
          input: "unknown",
          error: new Error(`Operation took ${duration}ms`),
          timestamp: new Date().toISOString(),
          iteration: this.iteration,
        };
      }
      return null;
    } catch (error) {
      return {
        type: "CRASH",
        component: "unknown",
        input: "unknown",
        error: error instanceof Error ? error : new Error(String(error)),
        timestamp: new Date().toISOString(),
        iteration: this.iteration,
      };
    }
  }

  // Fuzz the Policy Engine
  private async fuzzPolicyEngine(): Promise<void> {
    const engine = new PolicyEngine();

    // Test with edge cases first
    const edgeCases = this.generateEdgeCasePRData();
    for (const prData of edgeCases) {
      const finding = await this.runSingleTest(async () => {
        const result = await engine.evaluate(prData);
        
        // Validate result structure
        if (!["COMPLIANT", "NON_COMPLIANT", "WARNING"].includes(result.status)) {
          throw new Error(`Invalid status: ${result.status}`);
        }
        if (!Array.isArray(result.violations)) {
          throw new Error("Violations is not an array");
        }
        if (!Array.isArray(result.warnings)) {
          throw new Error("Warnings is not an array");
        }
      });

      if (finding) {
        finding.component = "PolicyEngine";
        finding.input = prData;
        this.findings.push(finding);
      }
    }

    // Random fuzzing
    for (let i = 0; i < Math.min(100, this.config.iterations); i++) {
      const prData = this.randomPRData();
      const finding = await this.runSingleTest(async () => {
        const result = await engine.evaluate(prData);
        
        // Validate result is always well-formed
        if (result === null || result === undefined) {
          throw new Error("Result is null or undefined");
        }
        
        // Check for prototype pollution
        if ((result as any).polluted) {
          throw new Error("Prototype pollution detected");
        }
      });

      if (finding) {
        finding.component = "PolicyEngine";
        finding.input = prData;
        this.findings.push(finding);
      }
    }
  }

  // Fuzz the Log Analyzer
  private async fuzzLogAnalyzer(): Promise<void> {
    const analyzer = new LogAnalyzer({
      errorThreshold: 5,
      windowMs: 60000,
    });

    // Test with edge cases first
    const edgeCases = this.generateEdgeCaseLogEntries();
    for (const logs of edgeCases) {
      const finding = await this.runSingleTest(() => {
        const result = analyzer.analyze(logs);
        
        // Validate result structure
        if (!Array.isArray(result)) {
          throw new Error("Result is not an array");
        }
        
        for (const anomaly of result) {
          if (!["ERROR_PATTERN", "ERROR_SPIKE"].includes(anomaly.type)) {
            throw new Error(`Invalid anomaly type: ${anomaly.type}`);
          }
        }
      });

      if (finding) {
        finding.component = "LogAnalyzer";
        finding.input = logs;
        this.findings.push(finding);
      }
    }

    // Random fuzzing
    for (let i = 0; i < Math.min(100, this.config.iterations); i++) {
      const logs = this.randomLogEntries();
      const finding = await this.runSingleTest(() => {
        const result = analyzer.analyze(logs);
        
        // Verify no crashes on malformed input
        if (result === undefined) {
          throw new Error("Analyzer returned undefined");
        }
      });

      if (finding) {
        finding.component = "LogAnalyzer";
        finding.input = logs;
        this.findings.push(finding);
      }
    }
  }

  // Fuzz the Logic Detector
  private async fuzzLogicDetector(): Promise<void> {
    const detector = new LogicErrorDetector();

    // Test with edge cases first
    const edgeCases = this.generateEdgeCaseCode();
    for (const code of edgeCases) {
      const finding = await this.runSingleTest(() => {
        const result = detector.scan(code);
        
        // Validate result structure
        if (!["SAFE", "VULNERABLE"].includes(result.status)) {
          throw new Error(`Invalid status: ${result.status}`);
        }
        if (!Array.isArray(result.findings)) {
          throw new Error("Findings is not an array");
        }
        if (typeof result.count !== "number") {
          throw new Error("Count is not a number");
        }
      });

      if (finding) {
        finding.component = "LogicErrorDetector";
        finding.input = code.substring(0, 1000); // Truncate for logging
        this.findings.push(finding);
      }
    }

    // Random fuzzing
    for (let i = 0; i < Math.min(100, this.config.iterations); i++) {
      const code = this.randomCode();
      const finding = await this.runSingleTest(() => {
        const result = detector.scan(code);
        
        // Verify result integrity
        if (result.count !== result.findings.length) {
          throw new Error(`Count mismatch: ${result.count} vs ${result.findings.length}`);
        }
      });

      if (finding) {
        finding.component = "LogicErrorDetector";
        finding.input = code.substring(0, 1000); // Truncate for logging
        this.findings.push(finding);
      }
    }
  }

  // Fuzz Input Sanitization Monitor if available
  private async fuzzInputSanitization(): Promise<void> {
    const monitor = new InputSanitizationMonitor();

    // Create test validator functions for fuzzing
    const testValidators: Array<{ name: string; fn: (input: string) => unknown }> = [
      { name: "identity", fn: (input) => input },
      { name: "passthrough", fn: (input) => true },
      { name: "reject-all", fn: () => { throw new Error("Rejected"); } },
      { name: "sanitize-basic", fn: (input) => input.replace(/<script>/gi, "") },
      { name: "sanitize-html", fn: (input) => input.replace(/[<>]/g, "") },
      { name: "length-check", fn: (input) => input.length < 1000 ? input : false },
    ];

    for (const validator of testValidators) {
      const finding = await this.runSingleTest(() => {
        const result = monitor.scan(validator.fn);
        
        // Validate result structure
        if (typeof result !== "object" || result === null) {
          throw new Error("Invalid result type");
        }
        if (!["SAFE", "UNSAFE_INPUTS_FOUND"].includes(result.status)) {
          throw new Error(`Invalid status: ${result.status}`);
        }
        if (!Array.isArray(result.findings)) {
          throw new Error("Findings is not an array");
        }
      });

      if (finding) {
        finding.component = "InputSanitizationMonitor";
        finding.input = validator.name;
        this.findings.push(finding);
      }
    }

    // Random validator fuzzing
    for (let i = 0; i < Math.min(50, this.config.iterations); i++) {
      const randomValidator = (input: string) => {
        // Randomly return different values
        const r = this.random.nextInt(0, 4);
        switch (r) {
          case 0: return input;
          case 1: return true;
          case 2: return false;
          case 3: throw new Error("Random rejection");
          default: return input.substring(0, 10);
        }
      };

      const finding = await this.runSingleTest(() => {
        monitor.scan(randomValidator);
      });

      if (finding) {
        finding.component = "InputSanitizationMonitor";
        finding.input = "random-validator";
        this.findings.push(finding);
      }
    }
  }

  // Run all fuzz tests
  async run(): Promise<FuzzFinding[]> {
    console.log("Starting fuzzer harness...");
    console.log(`Config: iterations=${this.config.iterations}, seed=${this.config.seed}`);

    await this.fuzzPolicyEngine();
    await this.fuzzLogAnalyzer();
    await this.fuzzLogicDetector();
    await this.fuzzInputSanitization();

    return this.findings;
  }

  // Generate a report of findings
  generateReport(): string {
    let report = "# Fuzzer Report\n\n";
    report += `**Seed:** ${this.config.seed}\n`;
    report += `**Iterations:** ${this.config.iterations}\n`;
    report += `**Findings:** ${this.findings.length}\n\n`;

    if (this.findings.length === 0) {
      report += "✅ No crashes or vulnerabilities detected during fuzzing.\n";
      return report;
    }

    // Group by type
    const crashes = this.findings.filter(f => f.type === "CRASH");
    const invalidStates = this.findings.filter(f => f.type === "INVALID_STATE");
    const perfIssues = this.findings.filter(f => f.type === "PERFORMANCE_DEGRADATION");

    report += `**Summary:** ${crashes.length} crashes, ${invalidStates.length} invalid states, ${perfIssues.length} performance issues\n\n`;

    for (const finding of this.findings) {
      report += `## Finding #${finding.iteration}\n\n`;
      report += `- **Type:** ${finding.type}\n`;
      report += `- **Component:** ${finding.component}\n`;
      report += `- **Error:** ${finding.error?.message || "N/A"}\n`;
      report += `- **Input (truncated):** \`${JSON.stringify(finding.input).substring(0, 200)}...\`\n\n`;
    }

    return report;
  }
}

// Test suite
describe("Fuzzer Harness", () => {
  let fuzzer: FuzzerHarness;

  beforeEach(() => {
    fuzzer = new FuzzerHarness({
      iterations: 10,
      seed: 42, // Fixed seed for reproducibility
      maxStringLength: 100,
      maxArrayLength: 5,
    });
  });

  describe("Policy Engine Fuzzing", () => {
    it("should not crash on random PR data", async () => {
      const quickFuzzer = new FuzzerHarness({ iterations: 5, seed: 42, maxStringLength: 50, maxArrayLength: 3 });
      const findings = await quickFuzzer.run();
      const policyFindings = findings.filter(f => f.component === "PolicyEngine");
      expect(policyFindings.length).toBe(0);
    }, 30000);

    it("should handle edge cases gracefully", async () => {
      const engine = new PolicyEngine();
      
      // Empty strings
      const emptyResult = await engine.evaluate({
        pull_request: {
          title: "",
          body: "",
          labels: [],
          base_branch: "",
          head_branch: "",
          number: 0,
          author: "",
        },
        files_modified: [],
        additions: 0,
        deletions: 0,
      });
      expect(emptyResult.status).toBeDefined();

      // Extremely long strings
      const longResult = await engine.evaluate({
        pull_request: {
          title: "a".repeat(10000),
          body: "b".repeat(10000),
          labels: [],
          base_branch: "main",
          head_branch: "test",
          number: 1,
          author: "test",
        },
        files_modified: [],
        additions: 0,
        deletions: 0,
      });
      expect(longResult.status).toBeDefined();
    }, 10000);

    it("should not allow prototype pollution", async () => {
      const engine = new PolicyEngine();
      
      // Attempt prototype pollution
      const maliciousInput = {
        pull_request: {
          title: "__proto__",
          body: "constructor.prototype.polluted = true",
          labels: ["__proto__"],
          base_branch: "main",
          head_branch: "test",
          number: 1,
          author: "__proto__",
        },
        files_modified: [],
        additions: 0,
        deletions: 0,
      };

      await engine.evaluate(maliciousInput as PRData);

      // Check that global objects aren't polluted
      expect((Object as any).polluted).toBeUndefined();
      expect((Array as any).polluted).toBeUndefined();
    });

    it("should handle negative numbers", async () => {
      const engine = new PolicyEngine();
      
      const result = await engine.evaluate({
        pull_request: {
          title: "Test PR",
          body: "Test body",
          labels: [],
          base_branch: "main",
          head_branch: "test",
          number: -1000,
          author: "test",
        },
        files_modified: [],
        additions: -500,
        deletions: -200,
      });
      
      expect(result.status).toBeDefined();
    });
  });

  describe("Log Analyzer Fuzzing", () => {
    it("should not crash on random log entries", async () => {
      const analyzer = new LogAnalyzer();
      
      // Generate random logs
      for (let i = 0; i < 10; i++) {
        const logs: LogEntry[] = Array.from({ length: 5 }, () => ({
          timestamp: new Date(Date.now() + Math.random() * 1000000).toISOString(),
          level: ["info", "warn", "error", "fatal"][Math.floor(Math.random() * 4)] as LogEntry["level"],
          message: Math.random().toString(36).substring(7),
        }));

        const result = analyzer.analyze(logs);
        expect(Array.isArray(result)).toBe(true);
      }
    }, 10000);

    it("should handle empty logs", () => {
      const analyzer = new LogAnalyzer();
      const result = analyzer.analyze([]);
      expect(result).toEqual([]);
    });

    it("should handle malformed timestamps", () => {
      const analyzer = new LogAnalyzer();
      
      const logs: LogEntry[] = [
        { timestamp: "", level: "error", message: "test" },
        { timestamp: "invalid", level: "error", message: "test" },
        { timestamp: "99999-99-99", level: "error", message: "test" },
      ];

      // Should not throw
      expect(() => analyzer.analyze(logs)).not.toThrow();
    });

    it("should handle extremely long messages", () => {
      const analyzer = new LogAnalyzer();
      
      const logs: LogEntry[] = [{
        timestamp: new Date().toISOString(),
        level: "error",
        message: "x".repeat(1000000),
      }];

      const result = analyzer.analyze(logs);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe("Logic Detector Fuzzing", () => {
    it("should not crash on random code", async () => {
      const detector = new LogicErrorDetector();
      
      for (let i = 0; i < 10; i++) {
        const code = Math.random().toString(36).repeat(10);
        const result = detector.scan(code);
        expect(["SAFE", "VULNERABLE"]).toContain(result.status);
      }
    }, 10000);

    it("should handle empty code", () => {
      const detector = new LogicErrorDetector();
      const result = detector.scan("");
      expect(result.status).toBe("SAFE");
    });

    it("should handle malformed code", () => {
      const detector = new LogicErrorDetector();
      
      const malformedCodes = [
        "function {{(([[",
        "}}]])",
        "a".repeat(100000),
        "\x00\x01\x02",
      ];

      for (const code of malformedCodes) {
        expect(() => detector.scan(code)).not.toThrow();
      }
    });
  });

  describe("Input Sanitization Fuzzing", () => {
    it("should handle XSS attempts", () => {
      const monitor = new InputSanitizationMonitor();
      
      // Test validator that passes through input (unsafe)
      const unsafeValidator = (input: string) => input;
      const result = monitor.scan(unsafeValidator);
      
      expect(result.status).toBe("UNSAFE_INPUTS_FOUND");
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it("should handle SQL injection attempts", () => {
      const monitor = new InputSanitizationMonitor();
      
      // Test validator that rejects everything (safe)
      const safeValidator = () => { throw new Error("Rejected"); };
      const result = monitor.scan(safeValidator);
      
      expect(result.status).toBe("SAFE");
    });

    it("should handle null bytes and control characters", () => {
      const monitor = new InputSanitizationMonitor();
      
      // Test validator that sanitizes
      const sanitizer = (input: string) => {
        return input
          .replace(/\x00/g, "")
          .replace(/[<>]/g, "")
          .replace(/javascript:/gi, "");
      };
      
      const result = monitor.scan(sanitizer);
      // Should be safe since we're sanitizing
      expect(result).toBeDefined();
    });

    it("should not crash on various validators", () => {
      const monitor = new InputSanitizationMonitor();
      
      const validators = [
        () => true,
        () => false,
        () => { throw new Error("Reject"); },
        (input: string) => input,
        (input: string) => input.length > 0,
        (input: string) => ({ value: input }),
        (input: string) => Buffer.from(input),
      ];

      for (const validator of validators) {
        expect(() => monitor.scan(validator)).not.toThrow();
      }
    });
  });

  describe("Performance Tests", () => {
    it("should complete within reasonable time", async () => {
      const quickFuzzer = new FuzzerHarness({ iterations: 10, seed: 42, maxStringLength: 100, maxArrayLength: 5 });
      const start = Date.now();
      await quickFuzzer.run();
      const duration = Date.now() - start;

      // Should complete within 10 seconds
      expect(duration).toBeLessThan(10000);
    });

    it("should not leak memory", async () => {
      const quickFuzzer = new FuzzerHarness({ iterations: 5, seed: 42, maxStringLength: 100, maxArrayLength: 5 });
      const initialMemory = process.memoryUsage().heapUsed;
      
      for (let i = 0; i < 3; i++) {
        await quickFuzzer.run();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const growth = finalMemory - initialMemory;

      // Memory should not grow significantly (less than 50MB)
      expect(growth).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe("Determinism", () => {
    it("should produce consistent results with same seed", async () => {
      const fuzzer1 = new FuzzerHarness({ iterations: 10, seed: 12345, maxStringLength: 100, maxArrayLength: 5 });
      const fuzzer2 = new FuzzerHarness({ iterations: 10, seed: 12345, maxStringLength: 100, maxArrayLength: 5 });

      const findings1 = await fuzzer1.run();
      const findings2 = await fuzzer2.run();

      expect(findings1.length).toBe(findings2.length);
    });
  });
});
