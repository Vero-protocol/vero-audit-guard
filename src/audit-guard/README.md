# Vero Audit Guard - Policy as Code Engine

![Policy Compliance](https://img.shields.io/badge/Policy%20Compliance-OPA%2FRego-blueviolet)

A powerful **Policy as Code** engine for enforcing security and compliance rules on GitHub Pull Requests. Uses OPA (Open Policy Agent) and Rego policies to automatically flag non-compliant PRs.

## Overview

`audit-guard` provides an automated compliance checking system that:

- **Validates PR metadata** — Enforces meaningful titles, comprehensive descriptions, and appropriate labeling
- **Checks dependencies** — Prevents unsafe packages and enforces security best practices
- **Detects risky patterns** — Flags large changes, breaking changes, and security-sensitive code modifications
- **Integrates with CI/CD** — Runs automatically on every PR with inline GitHub comments
- **Blocks non-compliant PRs** — Prevents merge of PRs that violate critical policies

## Architecture

```
GitHub PR Event
    ↓
Policy Compliance Workflow (.github/workflows/policy-compliance.yml)
    ↓
Extract PR Data → Evaluate with OPA Policies → Generate Report
    ↓
Comment on PR + Set Check Status
```

### Components

| Component | Purpose |
|-----------|---------|
| `src/policy-engine.ts` | Core evaluation engine (works with or without OPA CLI) |
| `src/cli.ts` | Command-line interface for policy evaluation |
| `policies/*.rego` | OPA/Rego policy definitions |
| `.github/workflows/policy-compliance.yml` | GitHub Actions workflow |

## Policies

### PR Compliance (`pr_compliance.rego`)

Ensures PRs meet minimum quality and documentation standards:

| Rule | Severity | Description |
|------|----------|-------------|
| `PR_TITLE_EMPTY` | MEDIUM | PR title cannot be empty |
| `PR_TITLE_TOO_SHORT` | MEDIUM | PR title must be at least 10 characters |
| `PR_DESCRIPTION_MISSING` | HIGH | PR description is required |
| `PR_TESTING_UNDOCUMENTED` | MEDIUM | Should document testing performed |
| `BREAKING_CHANGE_NOT_LABELED` | HIGH | Breaking changes must have `breaking-change` label |
| `SECURITY_CHANGE_NEEDS_LABEL` | HIGH | Security-sensitive changes need `security` or `audit` label |
| `CHANGELOG_NOT_UPDATED` | MEDIUM | Non-trivial changes should update CHANGELOG |
| `TOO_MANY_FILES_MODIFIED` | MEDIUM | >20 files should be split into smaller PRs |
| `LARGE_DIFF_REQUIRES_JUSTIFICATION` | MEDIUM | >1000 line changes need justification |

### Dependency Security (`dependencies.rego`)

Validates new dependencies for security compliance:

| Rule | Severity | Description |
|------|----------|-------------|
| `UNSAFE_PACKAGE_ADDED` | CRITICAL | Disallows known unsafe packages |
| `UNVETTED_DEPENDENCY` | HIGH | New deps require security review |
| `DEPENDENCY_VERSION_NOT_PINNED` | MEDIUM | Use exact versions, not `^` or `~` |
| `DEPENDENCY_MAJOR_UPDATE_AVAILABLE` | LOW | Informs about available updates |

## Installation

### 1. Install Dependencies

```bash
cd src/audit-guard
npm ci
```

### 2. Build

```bash
npm run build
```

### 3. (Optional) Install OPA

For full OPA support:

```bash
# macOS
brew install opa

# Linux
sudo apt-get install opa

# Or download from https://www.openpolicyagent.org/docs/latest/
```

> Note: The policy engine works without OPA CLI using a fallback TypeScript implementation, but OPA CLI enables more advanced policy features.

## Usage

### Command Line

#### Evaluate a PR

```bash
# Build first
npm run build

# Evaluate local PR data
npm run evaluate ./pr-data.json

# Or via CLI
PR_DATA_FILE=./pr-data.json npm run check-pr
```

#### Generate Report

```bash
REPORT_FILE=./report.md npm run check-pr
```

### Dashboard Integration

The policy engine can push compliance alerts to the **Guardian Dashboard**.

**Environment Variables:**

| Variable | Description |
|----------|-------------|
| `GUARDIAN_DASH_URL` | API endpoint for Guardian Dashboard |
| `GUARDIAN_DASH_TOKEN` | Bearer token for authentication |
| `MAINTENANCE_MODE` | Set to `true` to display a maintenance banner in reports |
| `MAINTENANCE_MESSAGE` | Custom message for maintenance banner |

### GitHub Actions

The policy compliance check runs automatically on:
- PR creation
- PR edits
- PR synchronization

Results appear as:
1. **Inline PR comment** with violations and warnings
2. **Check status** visible in PR merge requirements
3. **Comment reactions** to mark pass/fail

### Programmatic Usage

```typescript
import PolicyEngine, { PRData } from '@vero/audit-guard-policy-engine';

const engine = new PolicyEngine();

const prData: PRData = {
  pull_request: {
    title: "Implement new feature",
    body: "...",
    labels: ["feature"],
    base_branch: "main",
    head_branch: "feature/xyz",
    number: 42,
    author: "user"
  },
  files_modified: ["src/new-feature.ts"],
  additions: 100,
  deletions: 20
};

const result = await engine.evaluate(prData);
console.log(result.status); // 'COMPLIANT', 'WARNING', or 'NON_COMPLIANT'

// Generate markdown report
const report = engine.generateReport(result);
console.log(report);
```

## PR Data Format

```json
{
  "pull_request": {
    "title": "string",
    "body": "string",
    "labels": ["string"],
    "base_branch": "string",
    "head_branch": "string",
    "number": number,
    "author": "string"
  },
  "files_modified": ["string"],
  "additions": number,
  "deletions": number,
  "dependencies_added": [
    {
      "name": "string",
      "version": "string",
      "is_dev_dependency": boolean
    }
  ],
  "dependencies_updated": [
    {
      "name": "string",
      "current_version": "string",
      "latest_version": "string"
    }
  ]
}
```

## Test

```bash
npm test
npm test -- --watch
npm test -- --coverage
```

## Customizing Policies

### Add a New Rule

1. Edit `policies/pr_compliance.rego` or create a new `policies/your-policy.rego`
2. Add a `deny[msg]` or `warning[msg]` rule:

```rego
deny[msg] {
    # Your condition
    condition_met
    
    msg := {
        "rule": "YOUR_RULE_NAME",
        "severity": severity.HIGH,
        "message": "User-facing message",
        "detail": "Detailed explanation"
    }
}
```

3. Rebuild and test:

```bash
npm run build
npm test
```

### Update Approved Dependencies

Edit `dependencies.rego`:

```rego
approved_dependencies := [
    "stellar-sdk",
    "your-new-package",  # Add here
    ...
]
```

## Examples

### Example: Compliant PR

```json
{
  "pull_request": {
    "title": "Add end-to-end audit logging for policy checks",
    "body": "## Description\nImplements comprehensive audit logging.\n\n## Testing\nTested with jest: npm test ✅\n",
    "labels": ["feature", "security"],
    "base_branch": "main",
    "head_branch": "feature/audit-logging",
    "number": 42,
    "author": "developer"
  },
  "files_modified": ["src/logging.ts", "src/audit.ts"],
  "additions": 250,
  "deletions": 50
}
```

**Result:** ✅ COMPLIANT

### Example: Non-Compliant PR

```json
{
  "pull_request": {
    "title": "Fix",
    "body": "",
    "labels": [],
    "base_branch": "main",
    "head_branch": "fix/quick-patch",
    "number": 43,
    "author": "developer"
  },
  "files_modified": ["src/a.ts", "src/b.ts", ..., "src/z.ts"], // 30 files
  "additions": 2000,
  "deletions": 1500
}
```

**Result:** ❌ NON_COMPLIANT

**Violations:**
- PR_TITLE_TOO_SHORT
- PR_DESCRIPTION_MISSING
- TOO_MANY_FILES_MODIFIED
- LARGE_DIFF_REQUIRES_JUSTIFICATION

## Integration Tips

### Enforcing Compliance

Make the check required for merge:

1. Go to **Settings** → **Branches** → **Add Rule**
2. Under **Require status checks to pass**, enable **Policy Compliance**

### Exempting PRs

Add labels to skip warnings:

- `trivial` — Skip changelog check
- `docs` — Skip changelog check
- `breaking-change` — Acknowledge breaking changes
- `security` — Acknowledge security-sensitive changes

### CI/CD Integration

Add to your build pipeline:

```yaml
- name: Run Policy Check
  run: npm run check-pr
  working-directory: src/audit-guard
```

## Troubleshooting

### "OPA CLI not found"

The engine will fall back to TypeScript implementation. To use full OPA features:

```bash
# Install OPA
# Then restart GitHub Actions workflow
```

### "Policy check always passes"

Check if violations are being properly detected:

```bash
npm run evaluate ./pr-data.json
```

### Debugging

Enable debug output:

```bash
DEBUG=* npm run evaluate ./pr-data.json
```

## Performance

- **Evaluation:** < 100ms for typical PRs
- **CI job:** ~30s (includes npm install, build, and evaluation)
- **OPA overhead:** ~20-50ms additional with CLI

## Security

All policies are:
- ✅ Declarative (no code execution)
- ✅ Hermetic (no external calls)
- ✅ Deterministic (same input → same output)
- ✅ Auditable (transparent rules)

## Contributing

To add new policies or improve existing ones:

1. Add rule to `policies/*.rego`
2. Add test cases to `src/policy-engine.test.ts`
3. Update this README
4. Submit PR

## License

MIT — See LICENSE
