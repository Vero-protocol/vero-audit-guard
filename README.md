# vero-audit-guard

[![Security Scan](https://github.com/vero-protocol/vero-audit-guard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/vero-protocol/vero-audit-guard/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built on Stellar](https://img.shields.io/badge/Built%20on-Stellar-blueviolet)](https://stellar.org)

> **The Watchtower for the Vero Protocol.** Automated security monitoring, formal static analysis, and an immutable on-chain audit trail — all in one place.

---

## Security-First Stance

`vero-audit-guard` treats every line of the Vero Protocol as a potential attack surface. Nothing ships without:

1. **Static analysis** — `scanner-engine` catches unsafe Rust patterns, unchecked storage writes, and incomplete code before they reach mainnet.
2. **Real-time monitoring** — `anomaly-detector` watches the relayer service 24/7 for nonce spikes, failed-transaction bursts, and unauthorized address interactions.
3. **Policy compliance** — `audit-guard` enforces Policy as Code on every PR using OPA, flagging non-compliant code before review.
4. **Immutable audit history** — `verifiable-audit-trail` hashes every audit report and anchors it to the Stellar ledger, making tampering detectable by anyone.
5. **Zero-tolerance on CRITICAL** — The CI pipeline hard-blocks any PR containing a CRITICAL static analysis finding or policy violations.

---

## Automated Monitoring Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        VERO ORGANIZATION                        │
│                                                                 │
│  vero-core-contracts ──── scanner-engine ─────────┐            │
│       (Soroban/Rust)       (Rust binary)           │            │
│                                                    ▼            │
│  vero-relayer-service ── anomaly-detector ── /reports/ ──┐      │
│       (Node.js)            (TypeScript)      (JSON)      │      │
│                                                          ▼      │
│                         GitHub PRs ──── audit-guard ──────┐    │
│                         (Pull Requests) (OPA/Rego)       │      │
│                                                          ▼      │
│                                          verifiable-audit-trail │
│                                              (Stellar memo TX)  │
│                                                  │              │
│                                                  ▼              │
│                                          STELLAR LEDGER         │
│                                         (immutable hash store)  │
└─────────────────────────────────────────────────────────────────┘
```

### Component Summary

| Component                  | Language  | Role                                              |
|----------------------------|-----------|---------------------------------------------------|
| `scanner-engine`           | Rust      | Static analysis of Soroban contracts              |
| `anomaly-detector`         | TypeScript| Real-time relayer monitoring                      |
| `audit-guard`              | TypeScript| Policy as Code enforcement on GitHub PRs           |
| `verifiable-audit-trail`   | TypeScript| On-chain report hash anchoring (Stellar)          |
| `BUILD_GUARD.sh`           | Bash      | Local and CI orchestrator                         |
| `.github/workflows/`       | YAML      | PR-gated security pipeline                        |

---

## Directory Structure

```
vero-audit-guard/
├── src/audit-guard/         # OPA policy engine for PR compliance
│   ├── src/policy-engine.ts
│   ├── policies/pr_compliance.rego
│   └── package.json
├── scanner-engine/          # Rust static analyzer
│   └── src/main.rs
├── anomaly-detector/        # TypeScript relayer monitor
│   └── src/index.ts
├── verifiable-audit-trail/  # On-chain audit hash anchoring
│   └── src/index.ts
├── reports/                 # Generated scan reports (gitignored content)
├── .github/workflows/
│   ├── security-scan.yml    # PR-gated CI pipeline
│   └── policy-compliance.yml # OPA policy compliance checks
├── BUILD_GUARD.sh           # Local automation script
├── POLICY_AS_CODE.md        # Policy engine documentation
├── INCIDENT_RESPONSE.md     # Emergency runbook
└── VULNERABILITY_DISCLOSURE.md  # Bug bounty & reporting
```

---

## Incident Response Procedures (IRP)

See [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full runbook.

**Quick Reference:**

| Severity | Response SLA | First Action                          |
|----------|-------------|---------------------------------------|
| P0 (CRITICAL) | 15 min | Page on-call + invoke `emergency_pause` on contract |
| P1 (HIGH)     | 1 hour | Isolate relayer, rotate keys          |
| P2 (MEDIUM)   | 4 hours | Investigate, patch, re-scan           |
| P3 (LOW)      | 24 hours | Track in backlog, schedule patch      |

---

## Getting Started

### Prerequisites
- Rust toolchain (`rustup install stable`)
- Node.js ≥ 20
- `cargo`, `npm`
- `cargo-audit` (`cargo install cargo-audit --locked`)

### Run the Full Guard Locally

```bash
chmod +x BUILD_GUARD.sh
./BUILD_GUARD.sh [path/to/vero-core-contracts]
```

This will:
1. Audit Rust dependencies with `cargo audit` so known vulnerable crates fail the guard.
2. Build and run the Rust static analyzer.
3. Run anomaly-detector tests.
4. Build the audit trail module.
5. Compute and optionally anchor report hashes on Stellar.
6. Report the security health status.

### Environment Variables

| Variable                 | Component            | Description                                    |
|--------------------------|----------------------|------------------------------------------------|
| `AUDIT_KEYPAIR_SECRET`   | audit-trail          | Stellar secret key for on-chain anchoring      |
| `RELAYER_METRICS_URL`    | anomaly-detector     | HTTP endpoint exposing relayer metrics JSON    |
| `AUTHORIZED_ADDRESSES`   | anomaly-detector     | Comma-separated list of allowed relayer addresses |
| `NONCE_SPIKE_THRESHOLD`  | anomaly-detector     | Nonce delta threshold (default: 50)            |
| `FAILED_TX_THRESHOLD`    | anomaly-detector     | Failed TX count threshold (default: 10)        |
| `STELLAR_NETWORK`        | audit-trail          | `mainnet` or `testnet` (default: testnet)      |
| `HORIZON_URL`            | audit-trail          | Horizon server URL                             |

---

## Security Contacts

- **Bug reports:** See [`VULNERABILITY_DISCLOSURE.md`](VULNERABILITY_DISCLOSURE.md)
- **Emergency:** security@vero.xyz
- **PGP:** https://vero.xyz/.well-known/security.txt
