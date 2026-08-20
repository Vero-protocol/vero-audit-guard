# Shared Library for OPA Policies

package lib

# Severity levels
severity := {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM", 
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL"
}

# Helper to check if string contains substring (case-insensitive)
contains_ci(str, substr) {
    contains(lower(str), lower(substr))
}

# Helper to get max severity from list of violations
max_severity(violations, max) {
    severities := [severity | violation := violations[_]; severity := violation.severity]
    sort(severities)[count(severities) - 1] == max
}

# Severity ordering
severity_order(sev) = order {
    sev == "CRITICAL"
    order := 4
} else = order {
    sev == "HIGH"
    order := 3
} else = order {
    sev == "MEDIUM"
    order := 2
} else = order {
    sev == "LOW"
    order := 1
} else = order {
    order := 0
}
