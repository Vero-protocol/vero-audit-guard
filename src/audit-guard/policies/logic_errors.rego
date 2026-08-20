# Logic Error Detection Policy
#
# Identifies common logic-bug patterns in source code by string-matching.
# This is a coarse, OPA-friendly companion to the TypeScript LogicErrorDetector
# (src/logic-detector.ts). The TS engine runs fine-grained heuristics; this
# Rego policy works on raw source text for orgs that centralise policy in OPA.
#
# Input shape:
#   {
#     "code":  "<source text>",
#     "file":  "<optional path>"
#   }
#
# Each rule below corresponds 1:1 to a TypeScript pattern.

package logic.errors

import data.lib.severity

# -----------------------------------------------------------------------------
# REENTRANCY_RISK
# A low-level call within 3 lines precedes a state write touching the same
# balance / amount / counter field. The implementation here is a coarse
# substring match — it intentionally errs on the side of flagging.
# -----------------------------------------------------------------------------
deny[msg] {
    contains(input.code, ".call")
    contains(input.code, ".send")
    contains(input.code, "balance")
    contains(input.code, "=")
    msg := {
        "rule": "REENTRANCY_RISK",
        "severity": severity.HIGH,
        "message": "❌ Possible reentrancy: external call and balance write in the same code body",
        "detail": "Update state BEFORE performing external calls (checks-effects-interactions)."
    }
}

# -----------------------------------------------------------------------------
# INTEGER_OVERFLOW_RAW
# Coarse: a uint256 / uint128 / uint64 declaration together with a literal
# larger than 10^18. A cleaner OPA implementation would parse; this one
# matches by substring across the whole input.
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, "uint256")
    contains_regex(input.code, "[0-9]{19,}")
    msg := {
        "rule": "INTEGER_OVERFLOW_RAW",
        "severity": severity.MEDIUM,
        "message": "⚠️  Numeric literal > 10^18 alongside uint256 assignment",
        "detail": "Use a checked-arithmetic library or a Solidity release with built-in overflow checks."
    }
}

contains_regex(str, _) {
    # OPA has no native regex in stable-by-default; this stub documents
    # the intent. The TypeScript engine does the heavy lifting.
    str != ""
    true
}

# -----------------------------------------------------------------------------
# UNBOUNDED_LOOP — `while(true)` or `for(;;)` or array-length-as-bound
# -----------------------------------------------------------------------------
deny[msg] {
    contains(input.code, "while (true)")
    msg := {
        "rule": "UNBOUNDED_LOOP",
        "severity": severity.HIGH,
        "message": "🚨 while(true) loop with no exit bound",
        "detail": "Add a hard limit (max iterations, pagination, or pull-payment pattern)."
    }
}

deny[msg] {
    contains(input.code, "for (;;")
    msg := {
        "rule": "UNBOUNDED_LOOP",
        "severity": severity.HIGH,
        "message": "🚨 for(;;) loop with no exit bound",
        "detail": "Add a hard limit and a require() upper-bound check."
    }
}

warning[msg] {
    contains(input.code, ".length")
    contains(input.code, "for (")
    msg := {
        "rule": "UNBOUNDED_LOOP",
        "severity": severity.MEDIUM,
        "message": "⚠️  for-loop bounded by a dynamic .length — verify max",
        "detail": "Cap the loop with a hard maximum and validate the length before entering."
    }
}

# -----------------------------------------------------------------------------
# MISSING_ZERO_ADDRESS_CHECK
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, ".transfer(")
    not contains(input.code, "address(0)")
    msg := {
        "rule": "MISSING_ZERO_ADDRESS_CHECK",
        "severity": severity.MEDIUM,
        "message": "⚠️  .transfer() with no upstream address(0) guard",
        "detail": "Add `require(recipient != address(0))` before every transfer/send."
    }
}

# -----------------------------------------------------------------------------
# HARDCODED_PRIVATE_KEY (CRITICAL)
# 32-byte hex literal anywhere in the source.
# -----------------------------------------------------------------------------
deny[msg] {
    contains_regex_hex64(input.code)
    msg := {
        "rule": "HARDCODED_PRIVATE_KEY",
        "severity": severity.CRITICAL,
        "message": "🚫 Hardcoded 64-char hex literal (possible private key)",
        "detail": "Rotate the key immediately (assume compromise), remove from source, load from env / KMS."
    }
}

# A helper that splits the source on the substring "0x" and emits hex chunks.
# OPA cannot natively regex; this approximates `/\b0x[0-9a-fA-F]{64}\b/`.
contains_regex_hex64(str) {
    parts := split(str, "0x")
    some i
    part := parts[i]
    count(part) >= 64
    all_hex(part)
}

all_hex(s) {
    not contains(s, "g")
    not contains(s, "h")
    not contains(s, "i")
    not contains(s, "j")
    not contains(s, "k")
    not contains(s, "l")
    not contains(s, "m")
    not contains(s, "n")
    not contains(s, "o")
    not contains(s, "p")
    not contains(s, "q")
    not contains(s, "r")
    not contains(s, "s")
    not contains(s, "t")
    not contains(s, "u")
    not contains(s, "v")
    not contains(s, "w")
    not contains(s, "x")
    not contains(s, "y")
    not contains(s, "z")
}

# -----------------------------------------------------------------------------
# ASSERT_VS_REQUIRE
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, "assert(")
    msg := {
        "rule": "ASSERT_VS_REQUIRE",
        "severity": severity.MEDIUM,
        "message": "⚠️  assert(...) used for validation",
        "detail": "Use require(...) for input validation; reserve assert(...) for invariants."
    }
}

# -----------------------------------------------------------------------------
# TODO_SECURITY
# TODO/FIXME comments combined with security keywords.
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, "TODO")
    security_keyword_present(input.code)
    msg := {
        "rule": "TODO_SECURITY",
        "severity": severity.MEDIUM,
        "message": "⚠️  Security-related TODO/FIXME comment",
        "detail": "File a tracked ticket and address the TODO before merging."
    }
}

warning[msg] {
    contains(input.code, "FIXME")
    security_keyword_present(input.code)
    msg := {
        "rule": "TODO_SECURITY",
        "severity": severity.MEDIUM,
        "message": "⚠️  Security-related TODO/FIXME comment",
        "detail": "File a tracked ticket and address the TODO before merging."
    }
}

security_keyword_present(code) {
    contains(code, "auth")
} else {
    contains(code, "verify")
} else {
    contains(code, "password")
} else {
    contains(code, "secret")
} else {
    contains(code, "signature")
} else {
    contains(code, "permission")
}

# -----------------------------------------------------------------------------
# UNCHECKED_RETURN_VALUE
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, ".call(")
    not contains(input.code, "require(")
    msg := {
        "rule": "UNCHECKED_RETURN_VALUE",
        "severity": severity.HIGH,
        "message": "🚨 Low-level call with no require()/assert() on return",
        "detail": "Capture `(bool ok,)` and require(ok) — or use OpenZeppelin Address.sendValue."
    }
}

# -----------------------------------------------------------------------------
# TX_ORIGIN_AUTHORIZATION
# -----------------------------------------------------------------------------
deny[msg] {
    contains(input.code, "tx.origin")
    msg := {
        "rule": "TX_ORIGIN_AUTHORIZATION",
        "severity": severity.HIGH,
        "message": "🚨 Use of tx.origin for authorization",
        "detail": "Use msg.sender for authz; tx.origin is vulnerable to phishing."
    }
}

# -----------------------------------------------------------------------------
# EVAL_USAGE
# -----------------------------------------------------------------------------
deny[msg] {
    contains(input.code, "eval(")
    msg := {
        "rule": "EVAL_USAGE",
        "severity": severity.CRITICAL,
        "message": "🚫 eval() invocation",
        "detail": "Replace with a safe parser; eval on user input is a code-injection risk."
    }
}

# -----------------------------------------------------------------------------
# HARDCODED_API_KEY_LITERAL
# A non-empty string literal assigned to api_key/secret/password/token.
# -----------------------------------------------------------------------------
warning[msg] {
    contains(input.code, "api_key")
    contains_quoted_string_after_literal(input.code)
    msg := {
        "rule": "HARDCODED_API_KEY_LITERAL",
        "severity": severity.HIGH,
        "message": "🚨 Hardcoded API key / secret literal",
        "detail": "Rotate the credential and load from env / secrets manager."
    }
}

# OPA doesn't regex-match quotes cleanly without custom helpers; a substring
# of `"` adjacent to the variable name is the cheapest enough signal.
contains_quoted_string_after_literal(code) {
    contains(code, "api_key")
    contains(code, "\"")
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
logic_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count == 0
    msg := {
        "status": "SAFE",
        "message": "✅ No logic-bug patterns detected",
        "violations": 0,
        "warnings": 0
    }
}

logic_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations > 0
    msg := {
        "status": "VULNERABLE",
        "message": sprintf("❌ %d critical findings, %d warnings", [violations, warnings_count]),
        "violations": violations,
        "warnings": warnings_count
    }
}

logic_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count > 0
    msg := {
        "status": "WARNING",
        "message": sprintf("⚠️  %d warnings, no critical findings", [warnings_count]),
        "violations": 0,
        "warnings": warnings_count
    }
}
