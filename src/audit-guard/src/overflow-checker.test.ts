import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import OverflowChecker from "./overflow-checker";

describe("OverflowChecker", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "overflow-checker-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const writeFile = (name: string, content: string): string => {
    const file = path.join(tempDir, name);
    fs.writeFileSync(file, content, "utf8");
    return file;
  };

  it("should detect an integer overflow in a TypeScript file", async () => {
    const file = writeFile(
      "overflow.ts",
      "const huge = 18446744073709551616;",
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("INTEGER_OVERFLOW");
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].file).toBe(file);
    expect(findings[0].line).toBe(1);
  });

  it("should detect overflow from arithmetic expressions", async () => {
    const file = writeFile(
      "arithmetic.ts",
      `const base = 18446744073709551615;
const result = base + 1;`,
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings.some((f) => f.rule === "INTEGER_OVERFLOW")).toBe(true);

    const overflow = findings.find((f) => f.rule === "INTEGER_OVERFLOW");
    expect(overflow?.line).toBe(2);
  });

  it("should detect an unsigned underflow from subtraction", async () => {
    const file = writeFile(
      "underflow.ts",
      `const zero = 0;
const result = zero - 1;`,
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("INTEGER_UNDERFLOW");
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].line).toBe(2);
  });

  it("should not flag values within u64 bounds", async () => {
    const file = writeFile(
      "safe.ts",
      `const small = 100;
const maximum = 18446744073709551615;`,
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings).toHaveLength(0);
  });

  it("should scan Rust files", async () => {
    const file = writeFile(
      "overflow.rs",
      "let huge = 18446744073709551616;",
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("INTEGER_OVERFLOW");
  });

  it("should skip unsupported file extensions", async () => {
    const file = writeFile(
      "overflow.txt",
      "const huge = 18446744073709551616;",
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings).toHaveLength(0);
  });

  it("should skip nonexistent files", async () => {
    const missing = path.join(tempDir, "missing.ts");

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([missing]);

    expect(findings).toHaveLength(0);
  });

  it("should aggregate findings from multiple files", async () => {
    const first = writeFile(
      "first.ts",
      "const huge = 18446744073709551616;",
    );

    const second = writeFile(
      "second.ts",
      `const zero = 0;
const result = zero - 1;`,
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([first, second]);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.file)).toEqual([first, second]);
    expect(findings.map((f) => f.rule)).toEqual([
      "INTEGER_OVERFLOW",
      "INTEGER_UNDERFLOW",
    ]);
  });

  it("should include useful finding details", async () => {
    const file = writeFile(
      "details.ts",
      "const huge = 18446744073709551616;",
    );

    const checker = new OverflowChecker();
    const findings = await checker.checkFiles([file]);

    expect(findings[0].message).toContain("overflow");
    expect(findings[0].detail).toContain("18446744073709551616");
  });
});
