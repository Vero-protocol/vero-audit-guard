import {
  LOGIC_PATTERNS,
  LOGIC_PATTERN_IDS,
} from "./logic-patterns";

describe("logic-patterns", () => {
  const context = { file: "sample.sol" };

  const detect = (id: string, code: string) => {
    const pattern = LOGIC_PATTERNS.find((p) => p.id === id);
    if (!pattern) {
      throw new Error(`Pattern not found: ${id}`);
    }
    return pattern.detect(code, {
      ...context,
      lines: code.split(/\r?\n/),
    });
  };

  describe("pattern library", () => {
    it("exports all documented logic pattern ids", () => {
      expect(LOGIC_PATTERN_IDS).toEqual(
        expect.arrayContaining([
          "REENTRANCY_RISK",
          "INTEGER_OVERFLOW_RAW",
          "UNBOUNDED_LOOP",
          "MISSING_ZERO_ADDRESS_CHECK",
          "HARDCODED_PRIVATE_KEY",
          "ASSERT_VS_REQUIRE",
          "TODO_SECURITY",
          "UNCHECKED_RETURN_VALUE",
          "TX_ORIGIN_AUTHORIZATION",
          "EVAL_USAGE",
          "HARDCODED_API_KEY_LITERAL",
        ]),
      );

      expect(LOGIC_PATTERN_IDS).toHaveLength(11);
      expect(Object.isFrozen(LOGIC_PATTERNS)).toBe(true);
    });

    it("has one detector for every exported pattern id", () => {
      expect(LOGIC_PATTERNS).toHaveLength(LOGIC_PATTERN_IDS.length);

      for (const id of LOGIC_PATTERN_IDS) {
        expect(LOGIC_PATTERNS.find((pattern) => pattern.id === id)).toBeDefined();
      }
    });
  });

  describe("REENTRANCY_RISK", () => {
    it("detects an external call followed by a balance write", () => {
      const findings = detect(
        "REENTRANCY_RISK",
        `msg.sender.call{value: amount}("");
balances[msg.sender] = 0;`,
      );

      expect(findings.some((f) => f.ruleId === "REENTRANCY_RISK")).toBe(true);
    });

    it("does not flag state updated before the external call", () => {
      const findings = detect(
        "REENTRANCY_RISK",
        `balances[msg.sender] = 0;
msg.sender.call{value: amount}("");`,
      );

      expect(findings).toHaveLength(0);
    });
  });

  describe("INTEGER_OVERFLOW_RAW", () => {
    it("detects a large integer literal", () => {
      const findings = detect(
        "INTEGER_OVERFLOW_RAW",
        "uint256 total = 9223372036854775808;",
      );

      expect(findings.some((f) => f.ruleId === "INTEGER_OVERFLOW_RAW")).toBe(true);
    });

    it("does not flag a small integer literal", () => {
      expect(
        detect("INTEGER_OVERFLOW_RAW", "uint256 total = 100;"),
      ).toHaveLength(0);
    });
  });

  describe("UNBOUNDED_LOOP", () => {
    it("detects while(true)", () => {
      expect(
        detect("UNBOUNDED_LOOP", "while (true) { doWork(); }"),
      ).toHaveLength(1);
    });

    it("detects for(;;)", () => {
      expect(
        detect("UNBOUNDED_LOOP", "for (;;) { doWork(); }"),
      ).toHaveLength(1);
    });

    it("detects an unbounded dynamic-array loop", () => {
      const findings = detect(
        "UNBOUNDED_LOOP",
        "for (uint i = 0; i < arr.length; i++) { consume(arr[i]); }",
      );

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("MISSING_ZERO_ADDRESS_CHECK", () => {
    it("detects transfer without a zero-address guard", () => {
      const findings = detect(
        "MISSING_ZERO_ADDRESS_CHECK",
        "recipient.transfer(amount);",
      );

      expect(findings.some((f) => f.ruleId === "MISSING_ZERO_ADDRESS_CHECK")).toBe(true);
    });

    it("does not flag transfer with an upstream zero-address guard", () => {
      const findings = detect(
        "MISSING_ZERO_ADDRESS_CHECK",
        `require(recipient != address(0));
recipient.transfer(amount);`,
      );

      expect(findings).toHaveLength(0);
    });
  });

  describe("HARDCODED_PRIVATE_KEY", () => {
    it("detects a 64-character hexadecimal private-key-like literal", () => {
      const findings = detect(
        "HARDCODED_PRIVATE_KEY",
        'const key = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c0f4d0bb0c7a04d8e0f1";',
      );

      expect(findings.some((f) => f.ruleId === "HARDCODED_PRIVATE_KEY")).toBe(true);
      expect(findings[0].severity).toBe("CRITICAL");
    });

    it("documents that a 64-character hex value can also be flagged", () => {
      const findings = detect(
        "HARDCODED_PRIVATE_KEY",
        'const hash = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";',
      );

      expect(findings.some((f) => f.ruleId === "HARDCODED_PRIVATE_KEY")).toBe(true);
    });
  });

  describe("ASSERT_VS_REQUIRE", () => {
    it("detects assert used for validation", () => {
      const findings = detect("ASSERT_VS_REQUIRE", "assert(amount > 0);");

      expect(findings.some((f) => f.ruleId === "ASSERT_VS_REQUIRE")).toBe(true);
    });

    it("does not flag Node-style assert with a message", () => {
      expect(
        detect("ASSERT_VS_REQUIRE", 'assert(value > 0, "invalid");'),
      ).toHaveLength(0);
    });
  });

  describe("TODO_SECURITY", () => {
    it("detects a security-related TODO", () => {
      const findings = detect(
        "TODO_SECURITY",
        "// TODO: tighten auth check before shipping",
      );

      expect(findings.some((f) => f.ruleId === "TODO_SECURITY")).toBe(true);
    });

    it("does not flag an unrelated TODO", () => {
      expect(
        detect("TODO_SECURITY", "// TODO: rename this variable"),
      ).toHaveLength(0);
    });
  });

  describe("UNCHECKED_RETURN_VALUE", () => {
    it("detects an unchecked Solidity low-level call", () => {
      const findings = detect(
        "UNCHECKED_RETURN_VALUE",
        'target.call(abi.encodeWithSignature("ping()"));',
      );

      expect(findings.some((f) => f.ruleId === "UNCHECKED_RETURN_VALUE")).toBe(true);
    });

    it("does not flag a captured and checked return value", () => {
      const findings = detect(
        "UNCHECKED_RETURN_VALUE",
        `bool ok = target.call(abi.encodeWithSignature("ping()"));
require(ok);`,
      );

      expect(findings).toHaveLength(0);
    });
  });

  describe("TX_ORIGIN_AUTHORIZATION", () => {
    it("detects tx.origin", () => {
      const findings = detect(
        "TX_ORIGIN_AUTHORIZATION",
        "require(tx.origin == owner);",
      );

      expect(findings.some((f) => f.ruleId === "TX_ORIGIN_AUTHORIZATION")).toBe(true);
    });

    it("does not flag msg.sender", () => {
      expect(
        detect("TX_ORIGIN_AUTHORIZATION", "require(msg.sender == owner);"),
      ).toHaveLength(0);
    });
  });

  describe("EVAL_USAGE", () => {
    it("detects eval()", () => {
      const findings = detect("EVAL_USAGE", "eval(userInput);");

      expect(findings.some((f) => f.ruleId === "EVAL_USAGE")).toBe(true);
    });

    it("does not flag ordinary text containing eval", () => {
      expect(
        detect("EVAL_USAGE", 'const name = "evaluate";'),
      ).toHaveLength(0);
    });
  });

  describe("HARDCODED_API_KEY_LITERAL", () => {
    it("detects a hardcoded API key-like value", () => {
      const findings = detect(
        "HARDCODED_API_KEY_LITERAL",
        'const api_key = "AKIA1234567890ABCDEF1234";',
      );

      expect(findings.some((f) => f.ruleId === "HARDCODED_API_KEY_LITERAL")).toBe(true);
    });

    it("does not flag environment-based configuration", () => {
      expect(
        detect(
          "HARDCODED_API_KEY_LITERAL",
          "const api_key = process.env.MY_API_KEY;",
        ),
      ).toHaveLength(0);
    });
  });

  describe("finding metadata", () => {
    it("includes file and line information", () => {
      const findings = detect(
        "EVAL_USAGE",
        `const safe = true;
eval(input);`,
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].file).toBe("sample.sol");
      expect(findings[0].line).toBe(2);
      expect(findings[0].ruleId).toBe("EVAL_USAGE");
      expect(findings[0].message).toBeTruthy();
      expect(findings[0].remediation).toBeTruthy();
    });
  });
});
