/**
 * Example PR data files for testing
 */

// Compliant PR
export const compliantPR = {
  pull_request: {
    title: "Implement OPA policy engine for PR compliance",
    body: `
## Description
This PR implements a comprehensive Policy as Code engine using OPA/Rego for enforcing compliance rules on GitHub PRs.

## Changes
- Created OPA policy definitions (pr_compliance.rego, dependencies.rego)
- Built TypeScript policy engine with fallback implementation
- Integrated with GitHub Actions for automatic PR checks
- Added comprehensive testing suite

## Testing
Tested with npm test: ✅ All tests passing
- 15 compliance rules validated
- 8 dependency checks verified
- Report generation confirmed

## Security Implications
- Enhances security posture by enforcing compliance rules
- Prevents non-compliant code from being merged
- Provides audit trail of policy violations

## Files Modified
- src/audit-guard/src/policy-engine.ts
- src/audit-guard/src/cli.ts
- src/audit-guard/policies/pr_compliance.rego
- .github/workflows/policy-compliance.yml
    `,
    labels: ["feature", "security", "audit"],
    base_branch: "main",
    head_branch: "feature/policy-engine",
    number: 100,
    author: "security-engineer",
  },
  files_modified: [
    "src/audit-guard/src/policy-engine.ts",
    "src/audit-guard/src/cli.ts",
    "src/audit-guard/policies/pr_compliance.rego",
    "src/audit-guard/package.json",
    ".github/workflows/policy-compliance.yml",
  ],
  additions: 450,
  deletions: 50,
};

// Non-compliant PR (missing description)
export const nonCompliantPRNoDescription = {
  pull_request: {
    title: "Fix",
    body: "",
    labels: [],
    base_branch: "main",
    head_branch: "fix/quick-patch",
    number: 101,
    author: "developer",
  },
  files_modified: ["src/index.ts"],
  additions: 5,
  deletions: 5,
};

// Non-compliant PR (too many files)
export const nonCompliantPRTooManyFiles = {
  pull_request: {
    title: "Refactor entire codebase structure",
    body: "Major refactoring of the entire codebase",
    labels: [],
    base_branch: "main",
    head_branch: "refactor/structure",
    number: 102,
    author: "developer",
  },
  files_modified: Array.from({ length: 50 }, (_, i) => `src/module${i}/index.ts`),
  additions: 2000,
  deletions: 1500,
};

// Non-compliant PR (breaking changes without label)
export const nonCompliantPRBreakingChange = {
  pull_request: {
    title: "Redesign authentication API with new interface",
    body: `
This PR contains breaking changes to the authentication API.
The old authenticate() function is now auth() and takes different parameters.
`,
    labels: [],
    base_branch: "main",
    head_branch: "feature/new-auth",
    number: 103,
    author: "developer",
  },
  files_modified: ["src/auth.ts", "src/index.ts"],
  additions: 200,
  deletions: 150,
};

// Borderline compliant PR (has warnings but no violations)
export const warningPR = {
  pull_request: {
    title: "Add comprehensive monitoring and testing utilities",
    body: `
This PR adds new monitoring and testing utilities to the system.
    `,
    labels: [],
    base_branch: "main",
    head_branch: "feature/monitoring",
    number: 104,
    author: "developer",
  },
  files_modified: Array.from({ length: 25 }, (_, i) => `src/util${i}.ts`),
  additions: 300,
  deletions: 50,
};
