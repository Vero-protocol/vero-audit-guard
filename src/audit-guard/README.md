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

## Immutable Audit Trail

`audit-guard` supports anchoring audit results to the Stellar ledger for immutability and anti-tampering.

### Configuration

| Environment Variable | Description |
|----------------------|-------------|
| `ANCHOR_ON_CHAIN` | Set to `true` to enable on-chain anchoring |
| `AUDIT_KEYPAIR_SECRET` | Stellar secret key for transaction signing |
| `STELLAR_NETWORK` | `mainnet` or `testnet` (default: `testnet`) |
| `HORIZON_URL` | Custom Horizon server URL |

### How it works

1. The engine computes a SHA-256 hash of the full `EvaluationResult`.
2. A Stellar transaction is created with the hash in the `MEMO_TEXT` field.
3. The transaction is submitted to the ledger, creating a permanent, timestamped record of the audit.

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

## Log Backup Utility

The audit-guard package includes a simple log backup and restore helper to preserve critical policy and compliance logs across sites.

### Backup Usage

```bash
npm run backup -- ./logs /mnt/offsite/vero-log-backup
```

### Restore Usage

```bash
npm run restore -- /mnt/offsite/vero-log-backup ./logs-restored
```

### Remote Backup

Remote destinations are supported using `rsync` syntax:

```bash
npm run backup -- ./logs user@example.com:/var/backups/vero-logs
```

### Environment Variables

- `BACKUP_SOURCE` / `LOG_SRC`
- `BACKUP_DEST` / `LOG_DEST`
- `BACKUP_TARGET`
- `--dry-run`

## Event Log Scanner

The audit-guard package can also parse relay/audit event logs, index events for
review, and highlight sensitive access activity such as unauthorized access,
privilege changes, admin overrides, secret access, and token exposure.

### Scan an Event Log

```bash
npm run scan-events -- ./logs/relay-events.log
```

The scanner accepts JSONL logs and simple `key=value` lines. It indexes every
event by type, actor, and repository while surfacing sensitive events in a
markdown report.

### Programmatic Usage

```typescript
import { EventLogScanner } from '@vero/audit-guard-policy-engine';

const scanner = new EventLogScanner();
const result = scanner.scanFile('./logs/relay-events.log');

console.log(result.totalEvents);
console.log(result.sensitiveEvents);
console.log(result.index.byType.unauthorized_access);
```

### Environment Variables

- `EVENT_LOG_FILE`
- `REPORT_FILE`

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

## Logic Error Detection (Issue #16)

The `LogicErrorDetector` ships as an extensible pattern library for
finding common logic bugs in source code: reentrancy risk, unbounded
loops, integer overflow risk, hardcoded private keys, use of `eval`,
assertion-instead-of-require, and more.

```typescript
import { LogicErrorDetector } from "@vero/audit-guard-policy-engine";

const detector = new LogicErrorDetector();
const result = detector.scan(sourceCode, { file: "contract.sol" });

if (result.status === "VULNERABLE") {
  for (const f of result.findings) {
    console.log(`[${f.severity}] ${f.ruleId} on line ${f.line}: ${f.message}`);
  }
}
```

### Patterns (issue #16)

| Pattern ID | Severity | Description |
|------------|----------|-------------|
| `REENTRANCY_RISK` | HIGH | External (low-level) call followed by a balance/state write |
| `INTEGER_OVERFLOW_RAW` | MEDIUM | Large numeric literal assigned to a sized integer |
| `UNBOUNDED_LOOP` | HIGH / MEDIUM | `while(true)` / `for(;;)` / for-loop over a dynamic `.length` |
| `MISSING_ZERO_ADDRESS_CHECK` | MEDIUM | `.transfer(...)` without an upstream zero-address guard |
| `HARDCODED_PRIVATE_KEY` | CRITICAL | 32-byte (64-char hex) literal anywhere in the source |
| `ASSERT_VS_REQUIRE` | MEDIUM | `assert(...)` used for input validation |
| `TODO_SECURITY` | MEDIUM | TODO/FIXME containing a security keyword |
| `UNCHECKED_RETURN_VALUE` | HIGH | Low-level call whose return value is discarded |
| `TX_ORIGIN_AUTHORIZATION` | HIGH | `tx.origin` used in an authorization check |
| `EVAL_USAGE` | CRITICAL | Call to `eval()` |
| `HARDCODED_API_KEY_LITERAL` | HIGH | API key / secret literal in source |

Run a single sample to see all that fire on a deliberately-bad Solidity
fragment:

```typescript
const detector = new LogicErrorDetector();
const result = detector.scan(`
function withdraw(uint amount) public {
  (bool ok,) = msg.sender.call{value: amount}("");
  balances[msg.sender] = 0;
}
`);
console.log(detector.generateReport(result));
```

### Restrict to a subset of patterns

```typescript
const result = detector.scan(sourceCode, {
  patterns: ["REENTRANCY_RISK", "UNCHECKED_RETURN_VALUE"],
});
```

### CLI

```bash
# Scan a file and print the markdown report + raw result JSON
node dist/cli.js detect-logic ./contract.sol

# Restrict to two patterns and write a markdown report to ./report.md
LOGIC_PATTERN_FILTER=REENTRANCY_RISK,UNCHECKED_RETURN_VALUE \
  REPORT_FILE=./report.md \
  node dist/cli.js detect-logic ./contract.sol
```

Exit code is `1` when `result.status === "VULNERABLE"`, so the command
can be wired directly into CI gates.

### OPA/Rego Integration

The pattern library has a coarse `policies/logic_errors.rego` mirror for
orgs that prefer to centralise policy in OPA. The TypeScript engine
remains authoritative for the fine-grained heuristics.

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
