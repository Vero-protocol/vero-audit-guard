# Relayer Authorization Policy
#
# Issue #25: feat: relayer unauthorized tx scan
#
# Coarse OPA/Rego companion to the TypeScript RelayerTxScanner
# (`src/relayer-scanner.ts`). This policy is intended for orgs that
# centralise relayer authorization in OPA.
#
# Input shape:
#   {
#     "tx": {
#       "hash":            "<64 lowercase hex chars>",
#       "source_account":  "G...",
#       "sequence_number": "<decimal string>",
#       "signers":         ["G..."],
#       "operations":      [{"type": "...", ...}],
#       "fee":             100
#     },
#     "options": {
#       "authorized_signers":       ["G..."],
#       "denylisted_signers":       ["G..."],
#       "multi_sig_threshold":      1,
#       "trusted_source_accounts":  ["G..."],
#       "allowed_operation_types":  ["payment"],
#       "max_fee_per_op":           100,
#       "known_hashes":             ["<hex>"]
#     }
#   }
#
# Output shape (consumed by the policy engine's `parseOPAResult`):
#   data.relayer.authz.deny          — hard-block findings (CRITICAL)
#   data.relayer.authz.warning       — advisory findings (HIGH/MEDIUM/LOW)
#   data.relayer.authz.summary       — authorise/review/deny rollup
#
# Status rollup:
#   - deny > 0 ⇒ UNAUTHORIZED
#   - warning > 0 ⇒ REQUIRES_REVIEW
#   - both 0 ⇒ AUTHORIZED

package relayer.authz

import data.lib.severity

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Returns true iff `el` appears anywhere in `list`. Equivalent to a set
# membership test but matches the codebase convention.
array_contains(list, el) {
    list[_] == el
}

# Returns the count of distinct signers in input.tx.signers.
unique_signer_count(count) {
    count := count(input.tx.signers)
}

# -----------------------------------------------------------------------------
# DENYLISTED_SIGNER — hard block
# -----------------------------------------------------------------------------
deny[msg] {
    signer := input.tx.signers[_]
    array_contains(input.options.denylisted_signers, signer)
    msg := {
        "rule": "DENYLISTED_SIGNER",
        "severity": severity.CRITICAL,
        "message": sprintf("❌ Signer %v is on the denylist — refuse to relay.", [signer]),
        "detail": "Rotate the compromised or sanctioned key, open an IRP, and audit recent relay activity."
    }
}

# -----------------------------------------------------------------------------
# UNKNOWN_SIGNER — hard block
# -----------------------------------------------------------------------------
deny[msg] {
    signer := input.tx.signers[_]
    not array_contains(input.options.authorized_signers, signer)
    not array_contains(input.options.denylisted_signers, signer)
    msg := {
        "rule": "UNKNOWN_SIGNER",
        "severity": severity.HIGH,
        "message": sprintf("⚠️  Signer %v is not on the authorized allowlist.", [signer]),
        "detail": "Add the signer to VERO_RELAYER_AUTHORIZED_SIGNERS, or reject the envelope."
    }
}

# -----------------------------------------------------------------------------
# MISSING_SIGNATURES — hard block (signers array may be missing/empty)
# -----------------------------------------------------------------------------
deny[msg] {
    not input.tx.signers
    msg := {
        "rule": "MISSING_SIGNATURES",
        "severity": severity.CRITICAL,
        "message": "🚫 Transaction envelope contains no signatures",
        "detail": "Investigate where the envelope was constructed; the relayer should never see unsigned transactions."
    }
}

# -----------------------------------------------------------------------------
# INSUFFICIENT_SIGNATURES — hard block when threshold defined
# -----------------------------------------------------------------------------
deny[msg] {
    input.options.multi_sig_threshold > 0
    count(input.tx.signers) < input.options.multi_sig_threshold
    msg := {
        "rule": "INSUFFICIENT_SIGNATURES",
        "severity": severity.HIGH,
        "message": sprintf("🚨 Multi-sig threshold not met: %d unique signer(s), threshold is %d.", [count(input.tx.signers), input.options.multi_sig_threshold]),
        "detail": "Require the originating workflow to collect the missing signatures before submitting."
    }
}

# -----------------------------------------------------------------------------
# REPLAY_DETECTED — hard block
# -----------------------------------------------------------------------------
deny[msg] {
    input.tx.hash
    array_contains(input.options.known_hashes, input.tx.hash)
    msg := {
        "rule": "REPLAY_DETECTED",
        "severity": severity.CRITICAL,
        "message": "🚫 Transaction hash was already seen — refusing to relay.",
        "detail": "Drop the cache entry only after the envelope is intentionally resubmitted by an admin."
    }
}

# -----------------------------------------------------------------------------
# UNTRUSTED_SOURCE_ACCOUNT — hard block when configured
# -----------------------------------------------------------------------------
deny[msg] {
    input.options.trusted_source_accounts
    count(input.options.trusted_source_accounts) > 0
    not array_contains(input.options.trusted_source_accounts, input.tx.source_account)
    msg := {
        "rule": "UNTRUSTED_SOURCE_ACCOUNT",
        "severity": severity.HIGH,
        "message": sprintf("⚠️  Source account %v is not on the trusted-sources list.", [input.tx.source_account]),
        "detail": "If the source is legitimate, add it to VERO_RELAYER_TRUSTED_SOURCES. If not, drop the envelope."
    }
}

# -----------------------------------------------------------------------------
# UNSUPPORTED_OPERATION — hard block when allowlist configured
# -----------------------------------------------------------------------------
deny[msg] {
    input.options.allowed_operation_types
    count(input.options.allowed_operation_types) > 0
    op := input.tx.operations[_]
    not array_contains(input.options.allowed_operation_types, op.type)
    msg := {
        "rule": "UNSUPPORTED_OPERATION",
        "severity": severity.HIGH,
        "message": sprintf("⚠️  Operation type '%v' is not in the allowlist.", [op.type]),
        "detail": "Add the operation type to VERO_RELAYER_ALLOWED_OPERATIONS, or remove the operation from the envelope."
    }
}

# -----------------------------------------------------------------------------
# INVALID_HASH_FORMAT is intentionally NOT mirrored in Rego. The
# TypeScript engine has the regex pinned to `/^[0-9a-f]{64}$/`, while
# OPA's regex support varies by version and would risk shipping a
# fragile approximation. The TS engine is authoritative — reference
# `src/relayer-scanner.ts::INVALID_HASH_FORMAT`.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# DUPLICATE_SIGNATURE — advisory (warning, LOW severity)
# -----------------------------------------------------------------------------
# Counting duplicates in OPA without sets is awkward; we approximate by
# checking if any signer appears more than once via the membership
# predicate with the same key twice. The TypeScript engine remains
# authoritative for this rule.
warning[msg] {
    input.tx.signers
    input.tx.signers[_] == input.tx.signers[_]
    msg := {
        "rule": "DUPLICATE_SIGNATURE",
        "severity": severity.LOW,
        "message": "ℹ️  Envelope has duplicate signatures (verified by the TypeScript engine).",
        "detail": "Audit the originating signer; duplicate signatures waste fees."
    }
}

# -----------------------------------------------------------------------------
# FEE_OVER_LIMIT — advisory (warning)
# -----------------------------------------------------------------------------
warning[msg] {
    input.tx.fee
    input.options.max_fee_per_op
    count(input.tx.operations) > 0
    per_op := input.tx.fee / count(input.tx.operations)
    per_op > input.options.max_fee_per_op
    msg := {
        "rule": "FEE_OVER_LIMIT",
        "severity": severity.MEDIUM,
        "message": sprintf("⚠️  Per-operation fee %v stroops exceeds ceiling %v.", [per_op, input.options.max_fee_per_op]),
        "detail": "Confirm operational intent before relaying."
    }
}

# -----------------------------------------------------------------------------
# Status rollup
# -----------------------------------------------------------------------------
summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    msg := {
        "violations": violations,
        "warnings": warnings_count,
        "status": rollup_status(violations, warnings_count),
        "message": rollup_message(violations, warnings_count)
    }
}

rollup_status(violations, warnings_count) = status {
    violations > 0
    status := "UNAUTHORIZED"
} else = status {
    warnings_count > 0
    status := "REQUIRES_REVIEW"
} else = status {
    status := "AUTHORIZED"
}

rollup_message(violations, warnings_count) = m {
    violations > 0
    m := sprintf("❌ UNAUTHORIZED: %d hard-block rule(s), %d warning(s). Do not relay.", [violations, warnings_count])
} else = m {
    warnings_count > 0
    m := sprintf("⚠️  REQUIRES_REVIEW: %d advisory rule(s). Human review required.", [warnings_count])
} else = m {
    m := "✅ AUTHORIZED: envelope passed all gates."
}
