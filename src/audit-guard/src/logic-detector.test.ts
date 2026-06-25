/**
 * Tests for LogicErrorDetector
 *
 * Issue #16: feat: add logic error detection
 */

import LogicErrorDetector from "./logic-detector";
import {
  LOGIC_PATTERNS,
  LOGIC_PATTERN_IDS,
} from "./logic-patterns";

describe("LogicErrorDetector", () => {
  let detector: LogicErrorDetector;

  beforeEach(() => {
    detector = new LogicErrorDetector();
  });

  describe("Pattern library", () => {
    it("should expose the documented pattern ids", () => {
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
        ])
      );
      // frozen
      expect(Object.isFrozen(LOGIC_PATTERNS)).toBe(true);
    });

    it("should reject non-string input", () => {
      expect(() => detector.scan(null as unknown as string)).toThrow(/must be a string/);
    });
  });

  describe("Pattern: REENTRANCY_RISK", () => {
    it("should flag external call followed by balance write", () => {
      const code = `
function withdraw(uint amount) public {
    (bool ok,) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0;
}
`;
      const r = detector.scan(code);
      expect(r.status).toBe("VULNERABLE");
      expect(r.findings.some((f) => f.ruleId === "REENTRANCY_RISK")).toBe(true);
    });

    it("should NOT flag when state is updated before the external call", () => {
      const code = `
function withdraw(uint amount) public {
    balances[msg.sender] = 0;
    (bool ok,) = msg.sender.call{value: amount}("");
}
`;
      const r = detector.scan(code);
      expect(r.findings.some((f) => f.ruleId === "REENTRANCY_RISK")).toBe(false);
    });
  });

  describe("Pattern: INTEGER_OVERFLOW_RAW", () => {
    it("should flag large numeric literal assigned to a sized integer", () => {
      const code = `
function init() public {
    uint256 total = 99999999999999999999;
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "INTEGER_OVERFLOW_RAW")
      ).toBe(true);
    });

    it("should NOT flag small literal assignments", () => {
      const code = `
function init() public {
    uint256 total = 100;
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "INTEGER_OVERFLOW_RAW")
      ).toBe(false);
    });
  });

  describe("Pattern: UNBOUNDED_LOOP", () => {
    it("should flag while(true)", () => {
      const code = `
function spin() public {
    while (true) {
        counter += 1;
    }
}
`;
      const r = detector.scan(code);
      const findings = r.findings.filter((f) => f.ruleId === "UNBOUNDED_LOOP");
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it("should flag for(;;)", () => {
      const code = `
function spin() public {
    for (;;) { counter += 1; }
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "UNBOUNDED_LOOP")
      ).toBe(true);
    });

    it("should flag unbounded for-loop over .length", () => {
      const code = `
function drain(address[] memory arr) public {
    for (uint i = 0; i < arr.length; i++) { consume(arr[i]); }
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "UNBOUNDED_LOOP")
      ).toBe(true);
    });
  });

  describe("Pattern: MISSING_ZERO_ADDRESS_CHECK", () => {
    it("should flag transfer without upstream guard", () => {
      const code = `
function pay(address to, uint amt) public {
    recipient.transfer(amt);
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "MISSING_ZERO_ADDRESS_CHECK")
      ).toBe(true);
    });

    it("should NOT flag transfer that has an upstream zero-address guard", () => {
      const code = `
function pay(address to, uint amt) public {
    require(to != address(0), "no zero");
    recipient.transfer(amt);
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "MISSING_ZERO_ADDRESS_CHECK")
      ).toBe(false);
    });
  });

  describe("Pattern: HARDCODED_PRIVATE_KEY", () => {
    it("should flag a 64-char hex literal", () => {
      const code = `
const PRIV = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c0f4d0bb0c7a04d8e0f1";
`;
      const r = detector.scan(code);
      const f = r.findings.find((x) => x.ruleId === "HARDCODED_PRIVATE_KEY");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
    });

    it("should document trade-off: any 64-char hex literal is flagged (a SHA-256 hash hits the same rule)", () => {
      // The pattern can't tell a SHA-256 from a private key; both are
      // 64 hex characters. The trade-off is intentional: false positives
      // on hashes are cheap (the maintainer can mark them safe), while
      // false negatives on committed private keys are catastrophic.
      const sha256LikeHex =
        "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const r = detector.scan(`const H = "${sha256LikeHex}";`);
      const f = r.findings.find((x) => x.ruleId === "HARDCODED_PRIVATE_KEY");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
    });
  });

  describe("Pattern: ASSERT_VS_REQUIRE", () => {
    it("should flag assert(...) validating input", () => {
      const code = `
function gate(uint x) public {
    assert(x > 0);
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "ASSERT_VS_REQUIRE")
      ).toBe(true);
    });
  });

  describe("Pattern: TODO_SECURITY", () => {
    it("should flag TODO mentioning auth", () => {
      const code = `
// TODO: tighten auth check before shipping
function gate() public {}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "TODO_SECURITY")
      ).toBe(true);
    });

    it("should NOT flag TODO with no security keyword", () => {
      const code = `
// TODO: rename variable
function gate() public {}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "TODO_SECURITY")
      ).toBe(false);
    });
  });

  describe("Pattern: UNCHECKED_RETURN_VALUE", () => {
    it("should flag a bare .call() with no capture/check", () => {
      const code = `
function f(address target) public {
    target.call(abi.encodeWithSignature("ping()"));
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "UNCHECKED_RETURN_VALUE")
      ).toBe(true);
    });

    it("should NOT flag when the return is captured and required", () => {
      const code = `
function f(address target) public {
    (bool ok,) = target.call(abi.encodeWithSignature("ping()"));
    require(ok, "call failed");
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "UNCHECKED_RETURN_VALUE")
      ).toBe(false);
    });
  });

  describe("Pattern: TX_ORIGIN_AUTHORIZATION", () => {
    it("should flag tx.origin in auth check", () => {
      const code = `
modifier onlyOwner() {
    require(tx.origin == owner, "not owner");
    _;
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "TX_ORIGIN_AUTHORIZATION")
      ).toBe(true);
    });
  });

  describe("Pattern: EVAL_USAGE", () => {
    it("should flag use of eval()", () => {
      const code = `
function run(script) {
    eval(script);
}
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "EVAL_USAGE")
      ).toBe(true);
    });
  });

  describe("Pattern: HARDCODED_API_KEY_LITERAL", () => {
    it("should flag api_key = \"literal\"", () => {
      const code = `
const api_key = "AKIA1234567890ABCDEF";
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "HARDCODED_API_KEY_LITERAL")
      ).toBe(true);
    });

    it("should NOT flag api_key = process.env.X", () => {
      const code = `
const api_key = process.env.MY_API_KEY;
`;
      const r = detector.scan(code);
      expect(
        r.findings.some((f) => f.ruleId === "HARDCODED_API_KEY_LITERAL")
      ).toBe(false);
    });
  });

  describe("Multi-pattern detection on a single sample", () => {
    it("should fire multiple rules against a deliberately-bad sample", () => {
      const code = `
// TODO: replace eval with proper parser
function bad(address recipient) public payable {
    require(recipient != address(0));
    assert(msg.value > 0);
    (bool ok,) = recipient.call{value: msg.value}("");
    balances[recipient] -= msg.value;
    eval("doSomething()");
    for (uint i = 0; i < arr.length; i++) { consume(arr[i]); }
    sender.transfer(msg.value);
    tx.origin;
    uint256 total = 9999999999999999999999;
}
`;
      const r = detector.scan(code);
      const seen = new Set(r.findings.map((f) => f.ruleId));
      // We expect to see at least 5 distinct rule ids out of this snippet.
      expect(seen.size).toBeGreaterThanOrEqual(5);
      expect(r.status).toBe("VULNERABLE");
      expect(r.count).toBe(seen.size);
    });
  });

  describe("Safe code (no false positives)", () => {
    it("should report SAFE for clean code", () => {
      const code = `
function withdraw(uint amount) public {
    require(amount <= balances[msg.sender]);
    balances[msg.sender] -= amount;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
`;
      const r = detector.scan(code);
      expect(r.status).toBe("SAFE");
      expect(r.count).toBe(0);
    });
  });

  describe("Severity sort & line numbers", () => {
    it("should sort findings by severity (CRITICAL first) then by line", () => {
      const code = `
// TODO: clean up afterwards
function f() public {
    eval("x");
}
`;
      const r = detector.scan(code, { file: "f.sol" });
      // At minimum we expect CRITICAL above MEDIUM above LOW.
      const ranks = r.findings.map(
        (f) =>
          ({
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3,
            CRITICAL: 4,
          }[f.severity])
      );
      const sorted = [...ranks].sort((a, b) => b - a);
      expect(ranks).toEqual(sorted);
      // Each finding should have a file and line when supplied.
      for (const f of r.findings) {
        expect(f.file).toBe("f.sol");
        expect(typeof f.line).toBe("number");
      }
    });
  });

  describe("Pattern subsetting", () => {
    it("should respect options.patterns restriction", () => {
      const code = `
function f() public {
    eval("x");
    recipient.transfer(1);
}
`;
      const r = detector.scan(code, { patterns: ["EVAL_USAGE"] });
      expect(r.findings.length).toBe(1);
      expect(r.findings[0].ruleId).toBe("EVAL_USAGE");
    });
  });

  describe("Report generation", () => {
    it("should produce a markdown report", () => {
      const code = `
function f() public {
    eval("x");
}
`;
      const r = detector.scan(code, { file: "f.sol" });
      const report = detector.generateReport(r);
      expect(report).toContain("Logic Error Scan");
      expect(report).toContain("VULNERABLE");
      expect(report).toContain("f.sol");
      expect(report).toContain("EVAL_USAGE");
    });
  });

  describe("A buggy pattern should not break the scan", () => {
    it("should swallow exceptions from a throwing pattern", () => {
      const throwingPattern = {
        id: "BROKEN",
        title: "broken",
        description: "broken",
        severity: "LOW" as const,
        detect: () => {
          throw new Error("intentional");
        },
      };
      const customDetector = new LogicErrorDetector([throwingPattern]);
      const r = customDetector.scan("hello");
      // Should not throw, should report SAFE because the broken pattern
      // produced no findings.
      expect(r.status).toBe("SAFE");
    });
  });
});
