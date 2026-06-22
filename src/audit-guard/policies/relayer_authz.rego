# Relayer Authorization Policy
#
# Detects relayed transactions that are either:
#   1. Missing signers entirely.
#   2. Signed by an account on the hard denylist.
#   3. Signed by an account NOT on the authorized whitelist.
#   4. Below their declared multi-sig threshold while also having a foreign signer.
#
# Companion TypeScript engine: src/relayer-scanner.ts. Either can be used:
# the OPA CLI is optional and the engine falls back to a pure-TS evaluator when
# OPA is not installed.
#
# Input shape:
#   {
#     "tx": {
#       "sourceAccount": "G...",
#       "sequence": "123",
#       "signers": ["G...", "G..."],
#       "operations": [...],
#       ...
#     },
#     "config": {
#       "authorizedSigners": ["G..."],
#       "denylist": ["G..."],
#       "multisigThreshold": 2,
#       "sourceAccounts": ["G..."]
#     }
#   }

package relayer.authz

import data.lib.severity

# Rule: empty signer set is always rejected (CRITICAL).
deny[msg] {
    count(input.tx.signers) == 0
    msg := {
        "rule": "EMPTY_SIGNERS",
        "severity": severity.CRITICAL,
        "message": "❌ Transaction has no signers",
        "detail": "Every relayed TX must be signed by at least one account; empty signer set is rejected"
    }
}

# Rule: any signer on the denylist immediately triggers a CRITICAL violation.
deny[msg] {
    signer := input.tx.signers[_]
    signer in input.config.denylist
    msg := {
        "rule": "DENYLISTED_SIGNER",
        "severity": severity.CRITICAL,
        "message": sprintf("🚫 Denylisted signer detected: %v", [signer]),
        "detail": "Signer is on the hard-ban list and the TX must be rejected regardless of allowlist"
    }
}

# Rule: foreign signer — signer not in denylist and not in whitelist.
deny[msg] {
    signer := input.tx.signers[_]
    not signer in input.config.denylist
    not signer in input.config.authorizedSigners
    msg := {
        "rule": "UNAUTHORIZED_SIGNER",
        "severity": severity.HIGH,
        "message": sprintf("🚨 Foreign signer detected: %v", [signer]),
        "detail": "Signer is not in the authorised whitelist; this is an access-control violation"
    }
}

# Rule: multi-sig threshold not met (only when no other violation already fired,
# otherwise the threshold miss is rolled into the foreign-signer escalation).
deny[msg] {
    threshold := input.config.multisigThreshold
    threshold > 0
    authorized_count := count([s |
        s := input.tx.signers[_]
        s in input.config.authorizedSigners
        not s in input.config.denylist
    ])
    authorized_count < threshold
    msg := {
        "rule": "MULTISIG_THRESHOLD_NOT_MET",
        "severity": severity.HIGH,
        "message": sprintf("🚨 Multi-sig threshold not met (%v < %v)", [authorized_count, threshold]),
        "detail": sprintf("TX requires %v authorized signers; has %v", [threshold, authorized_count])
    }
}

# Warning: source account is not in the trusted-source list (advisory only).
warning[msg] {
    source_accounts := input.config.sourceAccounts
    count(source_accounts) > 0
    not input.tx.sourceAccount in source_accounts
    msg := {
        "rule": "UNVERIFIED_SOURCE_ACCOUNT",
        "severity": severity.MEDIUM,
        "message": sprintf("⚠️  Source account %v not in trusted-source list", [input.tx.sourceAccount]),
        "detail": "Review the source account before processing this TX"
    }
}

# Summary — returns a status and a numeric count, same shape as pr.compliance.
authz_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count == 0
    msg := {
        "status": "AUTHORIZED",
        "message": "✅ All signers authorized",
        "violations": 0,
        "warnings": 0
    }
}

authz_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations > 0
    msg := {
        "status": "UNAUTHORIZED",
        "message": sprintf("❌ TX rejected: %d violations, %d warnings", [violations, warnings_count]),
        "violations": violations,
        "warnings": warnings_count
    }
}

authz_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count > 0
    msg := {
        "status": "REQUIRES_REVIEW",
        "message": sprintf("⚠️  No violations but %d warnings", [warnings_count]),
        "violations": 0,
        "warnings": warnings_count
    }
}
