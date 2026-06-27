# PR Compliance Policy
# Defines rules that must be satisfied for a PR to be compliant

package pr.compliance

import future.keywords.in
import data.lib.severity

# Rule: PR Title must not be empty and must be meaningful
deny[msg] {
    input.pull_request.title == ""
    msg := {
        "rule": "PR_TITLE_EMPTY",
        "severity": severity.MEDIUM,
        "message": "❌ PR title cannot be empty",
        "detail": "Provide a clear, descriptive title for the PR"
    }
}

deny[msg] {
    count(input.pull_request.title) < 10
    msg := {
        "rule": "PR_TITLE_TOO_SHORT",
        "severity": severity.MEDIUM,
        "message": "❌ PR title is too short",
        "detail": sprintf("Title '%s' is less than 10 characters. Use a descriptive title.", [input.pull_request.title])
    }
}

# Rule: PR Description must be non-empty (required for security review)
deny[msg] {
    input.pull_request.body == ""
    msg := {
        "rule": "PR_DESCRIPTION_MISSING",
        "severity": severity.HIGH,
        "message": "❌ PR description is required",
        "detail": "Provide a detailed description of changes, security implications, and testing performed"
    }
}

# Rule: PR description should mention testing
deny[msg] {
    body := lower(input.pull_request.body)
    not contains(body, "test")
    msg := {
        "rule": "PR_TESTING_UNDOCUMENTED",
        "severity": severity.MEDIUM,
        "message": "⚠️  PR testing not documented",
        "detail": "Describe how you tested these changes"
    }
}

# Rule: Breaking changes must be explicitly documented
deny[msg] {
    labels := {label | label := input.pull_request.labels[_]}
    contains(input.pull_request.body, "breaking") 
    not "breaking-change" in labels
    msg := {
        "rule": "BREAKING_CHANGE_NOT_LABELED",
        "severity": severity.HIGH,
        "message": "❌ Breaking changes must be labeled",
        "detail": "Add 'breaking-change' label if this PR contains breaking changes"
    }
}

# Rule: Security-sensitive changes must have security label or detailed justification
deny[msg] {
    sensitive_keywords := ["auth", "crypto", "signature", "key", "secret", "token", "vulnerability", "exploit"]
    any_sensitive := [keyword | keyword := sensitive_keywords[_]; contains(lower(input.pull_request.body), keyword)]
    count(any_sensitive) > 0
    labels := {label | label := input.pull_request.labels[_]}
    not "security" in labels
    not "audit" in labels
    msg := {
        "rule": "SECURITY_CHANGE_NEEDS_LABEL",
        "severity": severity.HIGH,
        "message": "⚠️  Security-sensitive changes detected",
        "detail": "Add 'security' or 'audit' label for changes involving auth, crypto, keys, or vulnerabilities"
    }
}

# Rule: No direct commits to protected branches (through PR metadata)
deny[msg] {
    input.pull_request.base_branch == "main"
    input.pull_request.head_branch == "main"
    msg := {
        "rule": "DIRECT_TO_MAIN_PROTECTION",
        "severity": severity.CRITICAL,
        "message": "❌ Direct commits to main branch not allowed",
        "detail": "Use feature branches and submit PRs for review"
    }
}

# Rule: Changelog must be updated for non-trivial PRs
warning[msg] {
    labels := {label | label := input.pull_request.labels[_]}
    not "trivial" in labels
    not "docs" in labels
    not contains(input.pull_request.body, "changelog")
    not contains(input.pull_request.body, "CHANGELOG")
    msg := {
        "rule": "CHANGELOG_NOT_UPDATED",
        "severity": severity.MEDIUM,
        "message": "⚠️  Changelog should be updated",
        "detail": "For non-trivial changes, update CHANGELOG.md or mention changelog in PR"
    }
}

# Rule: Multiple files modified should have justification
deny[msg] {
    files_count := count(input.files_modified)
    files_count > 20
    msg := {
        "rule": "TOO_MANY_FILES_MODIFIED",
        "severity": severity.MEDIUM,
        "message": sprintf("⚠️  Many files modified (%d)", [files_count]),
        "detail": "Consider breaking this into smaller, focused PRs"
    }
}

# Rule: Large line changes need justification
deny[msg] {
    additions := input.additions
    deletions := input.deletions
    total_changes := additions + deletions
    total_changes > 1000
    msg := {
        "rule": "LARGE_DIFF_REQUIRES_JUSTIFICATION",
        "severity": severity.MEDIUM,
        "message": sprintf("⚠️  Large changeset (%d lines)", [total_changes]),
        "detail": "Break large changes into smaller PRs for easier review. If necessary, provide detailed justification."
    }
}

# Rule: No potential integer overflows allowed
deny[msg] {
    finding := input.overflow_findings[_]
    msg := {
        "rule": finding.rule,
        "severity": severity.HIGH,
        "message": finding.message,
        "detail": sprintf("%s (at %s:%d)", [finding.detail, finding.file, finding.line])
    }
}

# Warnings (advisory, not blocking)
warning[msg] {
    count(input.pull_request.title) > 100
    msg := {
        "rule": "PR_TITLE_TOO_LONG",
        "severity": severity.LOW,
        "message": "ℹ️  PR title is long",
        "detail": sprintf("Consider shortening title from %d characters", [count(input.pull_request.title)])
    }
}

# Helper: Compliance passing test
compliant {
    count(deny) == 0
}

# Summary message
compliance_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count == 0
    msg := {
        "status": "COMPLIANT",
        "message": "✅ All compliance checks passed!",
        "violations": 0,
        "warnings": 0
    }
}

compliance_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations > 0
    msg := {
        "status": "NON_COMPLIANT",
        "message": sprintf("❌ Policy violations found: %d violations, %d warnings", [violations, warnings_count]),
        "violations": violations,
        "warnings": warnings_count
    }
}

compliance_summary[msg] {
    violations := count(deny)
    warnings_count := count(warning)
    violations == 0
    warnings_count > 0
    msg := {
        "status": "WARNING",
        "message": sprintf("⚠️  No violations but %d warnings", [warnings_count]),
        "violations": 0,
        "warnings": warnings_count
    }
}
