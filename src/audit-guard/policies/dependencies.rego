# Dependency Security Policy
# Validates that new dependencies meet security requirements

package pr.dependencies

import data.lib.severity

# Rule: Disallow known unsafe packages
unsafe_packages := [
    "eval",
    "exec",
    "child_process",  # Must be used with strict validation
]

deny[msg] {
    added_dep := input.dependencies_added[_]
    pkg_name := added_dep.name
    any_unsafe := any(unsafe | unsafe := unsafe_packages[_]; unsafe == pkg_name)
    any_unsafe
    msg := {
        "rule": "UNSAFE_PACKAGE_ADDED",
        "severity": severity.CRITICAL,
        "message": sprintf("❌ Unsafe package '%s' cannot be added", [pkg_name]),
        "detail": "This package has known security risks. Use approved alternatives or document exception."
    }
}

# Rule: Prevent unvetted new dependencies (security review)
deny[msg] {
    added_dep := input.dependencies_added[_]
    pkg_name := added_dep.name
    # Check if it's in approved list
    not pkg_name in approved_dependencies
    # Allow if it's a dev dependency or patch update to existing
    not added_dep.is_dev_dependency
    msg := {
        "rule": "UNVETTED_DEPENDENCY",
        "severity": severity.HIGH,
        "message": sprintf("⚠️  Unvetted dependency: '%s'", [pkg_name]),
        "detail": sprintf("New production dependency '%s' requires security review. Add to approved list or mark as exception.", [pkg_name])
    }
}

# Rule: Check for version pinning (security best practice)
deny[msg] {
    added_dep := input.dependencies_added[_]
    version := added_dep.version
    # Check if using wildcard or loose version specifiers
    starts_with(version, "^") 
    msg := {
        "rule": "DEPENDENCY_VERSION_NOT_PINNED",
        "severity": severity.MEDIUM,
        "message": sprintf("⚠️  Dependency '%s' version not pinned", [added_dep.name]),
        "detail": sprintf("Use exact version (e.g., '%s') instead of '%s' for reproducible builds", [added_dep.version[1:], added_dep.version])
    }
}

# Approved production dependencies that have been vetted
approved_dependencies := [
    "stellar-sdk",
    "lodash",
    "axios",
    "dotenv",
    "express",
    "typescript",
    "jest",
    "ts-jest",
    "@types/node",
    "esbuild",
]

# Rule: Outdated dependencies (encourage updates)
warning[msg] {
    updated_dep := input.dependencies_updated[_]
    current_major := split(updated_dep.current_version, ".")[0]
    latest_major := split(updated_dep.latest_version, ".")[0]
    current_major < latest_major
    msg := {
        "rule": "DEPENDENCY_MAJOR_UPDATE_AVAILABLE",
        "severity": severity.LOW,
        "message": sprintf("ℹ️  Major version available for '%s'", [updated_dep.name]),
        "detail": sprintf("Consider updating '%s' from %s to %s", [updated_dep.name, updated_dep.current_version, updated_dep.latest_version])
    }
}
