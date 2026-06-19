/**
 * Logic Error Detection — Pattern Library
 *
 * Issue #16: feat: add logic error detection
 *
 * Each pattern is a small, focused detector that takes a code snippet
 * and emits zero or more `LogicFlawFinding` objects. Patterns are pure
 * (no I/O, no global state) so they can be unit-tested or composed.
 *
 * Heuristics are intentionally conservative: a finding is something a
 * human reviewer should at least glance at. False positives are
 * expected; false negatives are not — when in doubt, flag.
 */

import type { LogicFlawFinding, LogicSeverity } from "./logic-detector";

// Re-export for back-compat: callers may import `LogicSeverity` from
// `./logic-patterns` (it is the same canonical type in `./logic-detector`).
export type { LogicSeverity };

/** Context passed to a pattern detector (file path, line breakdown). */
export interface DetectionContext {
  file?: string;
  /** Pre-split lines of the source. If undefined the detector splits
   *  the input on `\n` itself. Pre-splitting avoids redundant work
   *  when many patterns run on the same snippet. */
  lines?: string[];
}

export interface LogicPattern {
  id: string;
  title: string;
  description: string;
  severity: LogicSeverity;
  /** Reference URL for remediation (used in `details` of the finding). */
  references?: string[];
  detect: (code: string, context?: DetectionContext) => LogicFlawFinding[];
}

/** Helper: get lines lazily and return { lineNumber (1-indexed), text }. */
function lookupLines(
  code: string,
  context?: DetectionContext
): { lines: string[] } {
  if (context?.lines) return { lines: context.lines };
  return { lines: code.split(/\r?\n/) };
}

/** Build a `LogicFlawFinding` with sensible defaults. */
function makeFinding(
  partial: Omit<LogicFlawFinding, "snippet" | "message" | "remediation"> & {
    message: string;
    remediation: string;
    snippet?: string;
  },
  lines: string[]
): LogicFlawFinding {
  const snippet =
    partial.snippet !== undefined
      ? partial.snippet
      : (lines[partial.line! - 1] ?? "").trim();
  return {
    file: partial.file,
    line: partial.line,
    snippet,
    ruleId: partial.ruleId,
    severity: partial.severity,
    message: partial.message,
    remediation: partial.remediation,
  };
}

// ----------------------------------------------------------------------------
// Pattern #1: REENTRANCY_RISK
// Detects an external call (`call`, `send`, `transfer`, `delegatecall`,
// `staticcall`) that is followed within three lines by a state write
// touching balance / amount / state / count fields.
// ----------------------------------------------------------------------------
const REENTRANCY_RISK: LogicPattern = {
  id: "REENTRANCY_RISK",
  title: "Potential reentrancy vulnerability",
  description:
    "An external (low-level) call is followed by a state write on a balance, amount, or counter field. Classic checks-effects-interactions violation.",
  severity: "HIGH",
  references: [
    "https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy",
  ],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const callRe = /\.(call|send|transfer|delegatecall|staticcall)\b/;
    // Note: `\w*\b` after the identifier allows pluralized state vars
    // (`balances`, `totals`, `amounts`, ...) to still match.
    const stateWriteRe =
      /(balance|amount|total|state|status|count|allowance|owner)\w*\b\s*(\[.*?\])?\s*=[^=]/;
    for (let i = 0; i < lines.length; i++) {
      if (!callRe.test(lines[i])) continue;
      const window = Math.min(i + 4, lines.length);
      for (let j = i + 1; j < window; j++) {
        if (stateWriteRe.test(lines[j])) {
          findings.push(
            makeFinding(
              {
                file: context?.file,
                line: i + 1,
                ruleId: REENTRANCY_RISK.id,
                severity: REENTRANCY_RISK.severity,
                message: `External call on line ${i + 1} is followed by a state write on line ${j + 1}. Possible reentrancy.`,
                remediation:
                  "Apply the checks-effects-interactions pattern: update state BEFORE making external calls, or use a reentrancy guard.",
              },
              lines
            )
          );
          break;
        }
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #2: INTEGER_OVERFLOW_RAW
// Detects assignments to a sized unsigned integer when the RHS is a
// numeric literal that exceeds 2^63-1 (out of `int` range) or 2^64-1
// (suggesting a `uint64` overflow on platforms that don't auto-promote).
// ----------------------------------------------------------------------------
const INTEGER_OVERFLOW_RAW: LogicPattern = {
  id: "INTEGER_OVERFLOW_RAW",
  title: "Possible integer overflow without SafeMath",
  description:
    "A sized uint/int is being assigned a numeric literal that exceeds the safe range for that type without an explicit overflow check.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const intAssign =
      /\b(?:u?int(?:8|16|32|64|128|256))\b\s+(\w+)\s*=\s*(\d+)\b/;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(intAssign);
      if (!m) continue;
      const literal = Number(m[2]);
      // uint256 max ≈ 1.16e77, so any assignment below it with int math
      // suspicion is fine; what we want is wide numeric literals that
      // could overflow a narrower type. Heuristic: flag values > 2^62.
      if (literal > 2 ** 62) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: INTEGER_OVERFLOW_RAW.id,
              severity: INTEGER_OVERFLOW_RAW.severity,
              message: `Literal ${m[2]} assigned to '${m[1]}' (type '${m[0].split(/\s+/)[0]}') could overflow at runtime.`,
              remediation:
                "Use a checked arithmetic library (SafeMath, OpenZeppelin Math) or upgrade to a Solidity version with built-in overflow checks.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #3: UNBOUNDED_LOOP
// `while(true)`, `for(;;)`, or `for( ... ; i < something.length ; )` where
// `something` is a dynamic array (no cap, no pagination).
// ----------------------------------------------------------------------------
const UNBOUNDED_LOOP: LogicPattern = {
  id: "UNBOUNDED_LOOP",
  title: "Unbounded loop",
  description:
    "A loop has no exit condition bound (`while(true)`, `for(;;)`) or iterates over a user-controlled dynamic collection without a length cap.",
  severity: "HIGH",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const patterns: RegExp[] = [
      /\bwhile\s*\(\s*true\s*\)/,
      /\bfor\s*\(\s*;\s*;\s*\)/,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const re of patterns) {
        if (re.test(lines[i])) {
          findings.push(
            makeFinding(
              {
                file: context?.file,
                line: i + 1,
                ruleId: UNBOUNDED_LOOP.id,
                severity: UNBOUNDED_LOOP.severity,
                message: `Loop on line ${i + 1} has no finite exit boundary.`,
                remediation:
                  "Add a bounded iteration cap (e.g. `require(i < MAX_ITERATIONS)` or a pull-payment / pagination pattern).",
              },
              lines
            )
          );
        }
      }
      // Heuristic: for-loop condition iterates over a `.length` field on
      // input / external data without a check on the upper bound.
      if (
        /\bfor\s*\(/.test(lines[i]) &&
        /\.length\b/.test(lines[i]) &&
        !/MAX_|limit|bound|<= ?\s*\d/.test(lines[i])
      ) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: UNBOUNDED_LOOP.id,
              severity: "MEDIUM",
              message: `Loop bound on line ${i + 1} depends on a dynamic collection length.`,
              remediation:
                "Cap the loop with a hard maximum and validate the length before entering the loop.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #4: MISSING_ZERO_ADDRESS_CHECK
// `.transfer(...)` / `.send(...)` / safeTransferFrom called on a non
// literal address with no upstream `require(recipient != address(0))`
// guard within the previous 6 lines.
// ----------------------------------------------------------------------------
const MISSING_ZERO_ADDRESS_CHECK: LogicPattern = {
  id: "MISSING_ZERO_ADDRESS_CHECK",
  title: "Missing zero-address check before transfer",
  description:
    "A transfer/send is being made to a non-literal address. Ensure the recipient is checked against `address(0)` (or equivalent) before sending.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/\.(transfer|send|safeTransfer|safeTransferFrom)\s*\(/.test(lines[i]))
        continue;
      // Look back 6 lines for a zero-address guard.
      const windowStart = Math.max(0, i - 6);
      const lookback = lines.slice(windowStart, i).join("\n");
      const hasGuard =
        /address\s*\(\s*0\s*\)/.test(lookback) ||
        /!\s*=\s*address\s*\(\s*0\s*\)/.test(lookback);
      if (hasGuard) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: MISSING_ZERO_ADDRESS_CHECK.id,
            severity: MISSING_ZERO_ADDRESS_CHECK.severity,
            message: `Transfer on line ${i + 1} has no zero-address guard in the preceding 6 lines.`,
            remediation:
              "Add `require(recipient != address(0))` (or the equivalent) before every transfer/send.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #5: HARDCODED_PRIVATE_KEY
// A 64-char hex string literal anywhere in the source.
// ----------------------------------------------------------------------------
const HARDCODED_PRIVATE_KEY: LogicPattern = {
  id: "HARDCODED_PRIVATE_KEY",
  title: "Hardcoded 64-char hex literal (potential private key)",
  description:
    "A 32-byte (64-character) hexadecimal literal in source — strongly indicating a hardcoded private key. Critical security risk if committed.",
  severity: "CRITICAL",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const hexRe = /\b0x[0-9a-fA-F]{64}\b/;
    for (let i = 0; i < lines.length; i++) {
      if (hexRe.test(lines[i])) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: HARDCODED_PRIVATE_KEY.id,
              severity: HARDCODED_PRIVATE_KEY.severity,
              message: `64-character hex literal on line ${i + 1} looks like a hardcoded private key.`,
              remediation:
                "Rotate the key IMMEDIATELY (assume it is compromised), remove from source, and load from environment / KMS / Vault instead.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #6: ASSERT_VS_REQUIRE
// `assert(...)` used for input validation (rather than for invariants).
// ----------------------------------------------------------------------------
const ASSERT_VS_REQUIRE: LogicPattern = {
  id: "ASSERT_VS_REQUIRE",
  title: "Use of `assert` for input validation",
  description:
    "`assert` consumes all remaining gas on failure, so it should only be used for invariants. Use `require` for user-input validation instead.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (/\bassert\s*\(/.test(lines[i])) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: ASSERT_VS_REQUIRE.id,
              severity: ASSERT_VS_REQUIRE.severity,
              message: `assert(...) on line ${i + 1} is unreachable on failure (consumes all gas).`,
              remediation:
                "Use `require(...)` for user-input validation; reserve `assert(...)` for true invariants.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #7: TODO_SECURITY
// A comment containing TODO or FIXME combined with a security-related
// keyword (auth, verify, check, signature, login, password, secret,
// token, key, allow, revoke, grant).
// ----------------------------------------------------------------------------
const TODO_SECURITY: LogicPattern = {
  id: "TODO_SECURITY",
  title: "TODO/FIXME near security-sensitive code",
  description:
    "A TODO or FIXME comment is colocated with a security-sensitive identifier. Open security TODOs frequently backslide into shipped vulnerabilities.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const todoRe =
      /\b(TODO|FIXME|XXX|HACK)\b[^\n]*\b(auth|verify|check|signature|login|password|secret|token|key|allow|revoke|grant|permission|role)\b/i;
    for (let i = 0; i < lines.length; i++) {
      if (todoRe.test(lines[i])) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: TODO_SECURITY.id,
              severity: TODO_SECURITY.severity,
              message: `Security-related TODO/FIXME on line ${i + 1}.`,
              remediation:
                "File a tracked ticket and address the TODO before merging; do not defer security work.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #8: UNCHECKED_RETURN_VALUE
// Low-level call whose boolean result is not captured and not used in
// any condition on the next three lines.
// ----------------------------------------------------------------------------
const UNCHECKED_RETURN_VALUE: LogicPattern = {
  id: "UNCHECKED_RETURN_VALUE",
  title: "Unchecked low-level call return value",
  description:
    "A low-level call (`.send`, `.call`, `.delegatecall`, `.staticcall`) is invoked without capturing or asserting on its return value.",
  severity: "HIGH",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const callRe = /\.(send|call|delegatecall|staticcall)\s*\(/;
    const captureRe = /=\s*[^=]*(send|call|delegatecall|staticcall)/;
    for (let i = 0; i < lines.length; i++) {
      if (!callRe.test(lines[i])) continue;
      // Capture: `bool ok = target.call(...)` ⇒ captured.
      if (captureRe.test(lines[i])) continue;
      // Look ahead 3 lines for a `require(ok)` or `if (ok)` style check.
      const look = lines.slice(i + 1, i + 4).join("\n");
      if (
        /\brequire\s*\(\s*\w+\s*\)/.test(look) ||
        /\bif\s*\(\s*\w+\s*\)/.test(look) ||
        /\brequire\s*\(\s*success/.test(look)
      ) {
        continue;
      }
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: UNCHECKED_RETURN_VALUE.id,
            severity: UNCHECKED_RETURN_VALUE.severity,
            message: `Low-level call on line ${i + 1} discards its boolean return value.`,
            remediation:
              "Capture the return value (`bool ok = target.call(...)`) and either `require(ok)` or handle failure explicitly. Prefer OpenZeppelin `ReentrancyGuard` and `Address.sendValue` helpers.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #9: TX_ORIGIN_AUTHORIZATION (Web3/Solidity)
// ----------------------------------------------------------------------------
const TX_ORIGIN_AUTHORIZATION: LogicPattern = {
  id: "TX_ORIGIN_AUTHORIZATION",
  title: "Use of `tx.origin` for authorization",
  description:
    "`tx.origin` is the original signer of the entire transaction chain; using it for authorization is vulnerable to phishing attacks. Always use `msg.sender`.",
  severity: "HIGH",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (/\btx\.origin\b/.test(lines[i])) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: TX_ORIGIN_AUTHORIZATION.id,
              severity: TX_ORIGIN_AUTHORIZATION.severity,
              message: `tx.origin used on line ${i + 1}.`,
              remediation:
                "Replace `tx.origin` with `msg.sender` in authorization checks.",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #10: EVAL_USAGE (JS/TS)
// Detects use of `eval(` which is widely recognized as a code-injection
// vector.
// ----------------------------------------------------------------------------
const EVAL_USAGE: LogicPattern = {
  id: "EVAL_USAGE",
  title: "Use of `eval`",
  description:
    "`eval` executes arbitrary code at runtime. Use it only as a last resort and never on user-controlled input.",
  severity: "CRITICAL",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (/\beval\s*\(/.test(lines[i])) {
        findings.push(
          makeFinding(
            {
              file: context?.file,
              line: i + 1,
              ruleId: EVAL_USAGE.id,
              severity: EVAL_USAGE.severity,
              message: `eval() invoked on line ${i + 1}.`,
              remediation:
                "Replace with a safer alternative (e.g. JSON.parse for JSON, a parser for DSLs, Function constructor only for static templates).",
            },
            lines
          )
        );
      }
    }
    return findings;
  },
};

// ----------------------------------------------------------------------------
// Pattern #11: HARDCODED_API_KEY_LITERAL
// Detects a quoted-string literal assigned to a variable whose name
// contains api_key / apikey / secret / password / token.
// ----------------------------------------------------------------------------
const HARDCODED_API_KEY_LITERAL: LogicPattern = {
  id: "HARDCODED_API_KEY_LITERAL",
  title: "Hardcoded API key / secret / password literal",
  description:
    "A non-empty string literal is assigned to a variable named like an API key, secret, password, or token.",
  severity: "HIGH",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    const re =
      /\b(api_?key|secret|password|auth_?token|access_?token|client_?secret)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(re);
      if (!m) continue;
      const value = m[2];
      if (!value || value.length < 6) continue;
      if (/\$\{|process\.env|require|import/.test(value)) continue;
      findings.push(
        makeFinding(
          {
            file: context?.file,
            line: i + 1,
            ruleId: HARDCODED_API_KEY_LITERAL.id,
            severity: HARDCODED_API_KEY_LITERAL.severity,
            message: `Hardcoded secret material on line ${i + 1}.`,
            remediation:
              "Rotate the credential (assume it is leaked), then load it from environment, a secrets manager, or a KMS-backed secret store.",
          },
          lines
        )
      );
    }
    return findings;
  },
};

/** Complete pattern library, exposed for callers that want to iterate. */
export const LOGIC_PATTERNS: readonly LogicPattern[] = Object.freeze([
  REENTRANCY_RISK,
  INTEGER_OVERFLOW_RAW,
  UNBOUNDED_LOOP,
  MISSING_ZERO_ADDRESS_CHECK,
  HARDCODED_PRIVATE_KEY,
  ASSERT_VS_REQUIRE,
  TODO_SECURITY,
  UNCHECKED_RETURN_VALUE,
  TX_ORIGIN_AUTHORIZATION,
  EVAL_USAGE,
  HARDCODED_API_KEY_LITERAL,
]);

export const LOGIC_PATTERN_IDS = LOGIC_PATTERNS.map((p) => p.id);
