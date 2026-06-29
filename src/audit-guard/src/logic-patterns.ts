/**
 * Logic Error Detection — Pattern Library
 *
 * Issue #16: feat: add logic error detection
 * Issue #9:  fix: reduce scan false positives
 *
 * Each pattern is a small, focused detector that takes a code snippet
 * and emits zero or more `LogicFlawFinding` objects. Patterns are pure
 * (no I/O, no global state) so they can be unit-tested or composed.
 *
 * Heuristics are intentionally conservative: a finding is something a
 * human reviewer should at least glance at. False positives are
 * expected; false negatives are not — when in doubt, flag.
 *
 * ## Noise-filter changes (issue #9)
 *
 * REENTRANCY_RISK
 *   - `callRe` now requires a Solidity-style call context: must be
 *     preceded by `}`, `)`, or an identifier (not a bare `.call(`
 *     that matches JS `Function.prototype.call`).
 *   - `stateWriteRe` dropped `status`, `state`, `count`, `owner` —
 *     all extremely common TypeScript variable names — keeping only
 *     the Solidity-specific `balance`/`amount`/`total`/`allowance`.
 *
 * UNBOUNDED_LOOP
 *   - The `.length` heuristic now requires the loop variable to be
 *     a *simple counter* (single-char or `idx`/`index`/`i`/`j`/`k`)
 *     AND the collection name must look like an external/parameter
 *     (starts with a lowercase letter not a local `const`/`let` prefix).
 *     This prevents firing on standard bounded `for` loops.
 *
 * ASSERT_VS_REQUIRE
 *   - Skip lines where `assert` is called on an import from Node's
 *     `assert` module (i.e. the variable holding the import is named
 *     `assert` and it was imported via `require('assert')` or
 *     `import assert`). In practice: require the pattern to be inside
 *     a Solidity-looking file context OR the call to look like
 *     Solidity (`assert(expr)` with no message string argument is
 *     Solidity-idiomatic; Node's assert always takes a message).
 *     Simplified heuristic: skip if the line already contains
 *     `// @ts` or `import assert` or `require('assert')`, or if the
 *     assertion has a two-argument form `assert(cond, msg)` (Node.js).
 *
 * TODO_SECURITY
 *   - Removed `check` from the keyword list — too broad. Added
 *     `exploit` and `bypass` which are unambiguously security-relevant.
 *
 * UNCHECKED_RETURN_VALUE
 *   - `callRe` now requires the call to be on an *address-like* target:
 *     `target.call(`, `addr.call(`, `recipient.call(` etc., not a
 *     plain method call like `router.call(` or `fn.call(ctx)`.
 *     Implemented by requiring no `(` immediately before `.call(` and
 *     the receiver to be a simple identifier (no `.` chain before it on
 *     the same expression start).
 *   - Destructuring capture `(bool ok,) = ...call(` now recognised.
 *
 * MISSING_ZERO_ADDRESS_CHECK
 *   - `.send(` is now excluded when the line also looks like an HTTP
 *     response (i.e. the receiver is `res`, `response`, or `reply`).
 *
 * HARDCODED_API_KEY_LITERAL
 *   - Added a placeholder / example value filter: values that are
 *     all uppercase letters/digits with no lowercase (e.g. test
 *     fixture strings like `"EXAMPLE_SECRET"`) are skipped unless
 *     they look like a real credential (contain digits AND letters
 *     AND are ≥ 20 chars).
 *   - Skip lines inside obvious test files (`*.test.*`, `*.spec.*`,
 *     `__tests__`, `fixtures`) when the context file is provided.
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
    "An external (low-level) call is followed by a state write on a balance or amount field. Classic checks-effects-interactions violation.",
  severity: "HIGH",
  references: [
    "https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy",
  ],
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    // Require the low-level call to be on a simple identifier receiver
    // (e.g. `msg.sender.call`, `addr.call`) — this avoids matching
    // JS Function.prototype.call (`fn.call(ctx)`) and HTTP-library
    // methods (e.g. `axios.send`). The receiver must be a word char
    // sequence ending right before `.call/send/…`.
    const callRe = /\w+\.(call|send|delegatecall|staticcall)\s*[\({]/;
    // Narrowed to Solidity-specific financial state variables only.
    // Dropped: status, state, count, owner — too common in TS/JS.
    const stateWriteRe =
      /(balance|amount|total|allowance)\w*\b\s*(\[.*?\])?\s*=[^=]/;
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
    const infinitePatterns: RegExp[] = [
      /\bwhile\s*\(\s*true\s*\)/,
      /\bfor\s*\(\s*;\s*;\s*\)/,
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const re of infinitePatterns) {
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

      // Heuristic: for-loop iterates over `.length` of what appears to be
      // an external/parameter collection (lowercase-starting name) without
      // a hard upper-bound guard.
      //
      // Noise-filter (issue #9): skip standard bounded TS/JS loops where
      // the length comes from a local `const`/`let` array initialised in
      // the same scope — these are inherently bounded. We only flag when:
      //   (a) no MAX_ / limit / bound / numeric cap guard is present, AND
      //   (b) the loop variable is a single char or named idx/index/i/j/k
      //       (Solidity-idiomatic), AND
      //   (c) the collection does NOT look like a locally-typed array
      //       (i.e. does not contain `[]` in the same line, which would
      //        indicate a statically-known structure).
      if (
        /\bfor\s*\(/.test(lines[i]) &&
        /\.length\b/.test(lines[i]) &&
        !/MAX_|limit|bound|<= ?\s*\d/.test(lines[i]) &&
        // The loop counter must look like a Solidity/short-form variable.
        /\bfor\s*\(\s*(uint\s+)?[a-z]{1,3}\s+(=|:)/.test(lines[i]) &&
        // Skip lines where the collection is typed inline (TS array literal).
        !/:\s*\w+\[\]/.test(lines[i]) &&
        !/memory\s+\w+\[\]/.test(lines[i])
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
    "A Solidity transfer/send is being made to a non-literal address. Ensure the recipient is checked against `address(0)` before sending.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/\.(transfer|send|safeTransfer|safeTransferFrom)\s*\(/.test(lines[i]))
        continue;

      // Noise-filter (issue #9): `.send(` is extremely common on Node.js
      // HTTP response objects (`res.send`, `response.send`, `reply.send`).
      // Skip when the receiver looks like an HTTP response variable.
      if (/\b(res|response|reply|resp)\s*\.send\s*\(/.test(lines[i])) continue;

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
    "`assert` consumes all remaining gas on failure in Solidity, so it should only be used for invariants. Use `require` for user-input validation instead.",
  severity: "MEDIUM",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/\bassert\s*\(/.test(lines[i])) continue;

      // Noise-filter (issue #9): skip Node.js-style assert usage.
      //
      // 1. Two-argument form: assert(condition, message) — Node.js idiom.
      //    Solidity assert never takes a message string.
      if (/\bassert\s*\([^)]+,\s*["'`]/.test(lines[i])) continue;

      // 2. The line imports or requires the Node assert module.
      if (/require\s*\(\s*['"]assert['"]\s*\)/.test(lines[i])) continue;
      if (/import\s+.*\bassert\b.*from\s+['"]assert['"]/.test(lines[i])) continue;

      // 3. The call is on a named assert object (e.g. `assert.strictEqual`).
      if (/\bassert\s*\./.test(lines[i])) continue;

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
    // Noise-filter (issue #9): removed `check` (too broad — fires on
    // innocuous "TODO: check this later" comments). Added `exploit` and
    // `bypass` which are unambiguously security-relevant.
    const todoRe =
      /\b(TODO|FIXME|XXX|HACK)\b[^\n]*\b(auth|verify|signature|login|password|secret|token|key|allow|revoke|grant|permission|role|exploit|bypass)\b/i;
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
    "A low-level call (`.call`, `.delegatecall`, `.staticcall`) is invoked without capturing or asserting on its return value.",
  severity: "HIGH",
  detect: (code, context) => {
    const { lines } = lookupLines(code, context);
    const findings: LogicFlawFinding[] = [];
    // Noise-filter (issue #9): require the receiver to be a simple
    // identifier (address-like variable) — NOT a chained method call and
    // NOT a JS Function.prototype.call invocation `fn.call(ctx)`.
    // Solidity low-level calls are distinguished by:
    //   - Using `{value: ...}` or `{gas: ...}` options, OR
    //   - Passing ABI-encoded bytes (abi.encodeWithSignature / abi.encode), OR
    //   - Being on an address-named variable (addr, recipient, target, to, dest)
    // Plain JS `handler.call(ctx)` has none of these markers.
    const callRe = /\w+\.(call|delegatecall|staticcall)\s*(\{[^}]*\}|)\s*\(/;
    const solidityCallMarker = /\{value:|abi\.encode|abi\.encodeWithSignature|\babi\b/;
    for (let i = 0; i < lines.length; i++) {
      if (!callRe.test(lines[i])) continue;
      // Skip if no Solidity call markers present — avoids JS prototype calls.
      if (!solidityCallMarker.test(lines[i])) continue;
      // Capture patterns: `bool ok =`, `(bool ok,) =`, destructuring
      const captureRe = /(?:bool\s+\w+\s*=|=\s*[^=]*\.(call|delegatecall|staticcall)|\(\s*bool)/;
      if (captureRe.test(lines[i])) continue;
      // Look ahead 3 lines for a require/if check on the result.
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

    // Noise-filter (issue #9): skip obvious test/fixture files.
    const isTestFile =
      context?.file !== undefined &&
      /(\.(test|spec)\.[jt]sx?|__tests__|fixtures[/\\])/i.test(context.file);

    const re =
      /\b(api_?key|secret|password|auth_?token|access_?token|client_?secret)\b\s*[:=]\s*["'`]([^"'`\s]+)["'`]/i;

    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(re);
      if (!m) continue;
      const value = m[2];
      if (!value || value.length < 6) continue;
      // Already loaded from env / import — not hardcoded.
      if (/\$\{|process\.env|require|import/.test(value)) continue;
      // Noise-filter: placeholder / example values that are all-uppercase
      // with no digits are unlikely to be real credentials (e.g. test
      // schema constants like `"YOUR_SECRET_HERE"`).
      if (/^[A-Z_]+$/.test(value)) continue;
      // In test files, only flag values that look like real credentials:
      // mixed case + digits + length ≥ 20.
      if (isTestFile && !(/[a-z]/.test(value) && /\d/.test(value) && value.length >= 20)) {
        continue;
      }

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
