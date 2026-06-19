# Formal Verification Export Report
Generated on: 2026-06-19 14:48:37

## Concurrency Analysis (Deadlock Freedom)
```
[*] Scanning /app/src for shared locks and race conditions...
[+] No shared locks identified. Thread safety verified.
[*] Scanning /app/scanner-engine for shared locks and race conditions...
[+] No shared locks identified. Thread safety verified.
[*] Scanning /app/anomaly-detector for shared locks and race conditions...
[+] No shared locks identified. Thread safety verified.
[*] Scanning /app/verifiable-audit-trail for shared locks and race conditions...
[+] No shared locks identified. Thread safety verified.

```

## Static Analysis (Security Scanner)
**Target:** /app
**Total Files Scanned:** 3
**Report Hash:** `20035afb67269366bff7d0dc7bd0a206736ed5da001f2bd2405a922ebba171d8`

### Findings
| File | Line | Rule | Severity | Snippet |
|------|------|------|----------|---------|
| /app/scanner-engine/src/main.rs | 32 | TRANSFER_FROM_USAGE | MEDIUM | `(r"transfer_from\b", "TRANSFER_FROM_USAGE", "MEDIUM"),` |
| /app/scanner-engine/src/main.rs | 45 | UNSAFE_UNWRAP | HIGH | `.map(|(pat, id, sev)| (Regex::new(pat).unwrap(), *id, *sev))` |
| /app/scanner-engine/src/main.rs | 84 | UNSAFE_UNWRAP | HIGH | `let report_json = serde_json::to_string_pretty(&all_findings).unwrap();` |
| /app/scanner-engine/src/main.rs | 94 | UNSAFE_UNWRAP | HIGH | `let out = serde_json::to_string_pretty(&report).unwrap();` |
| /app/scanner-engine/src/main.rs | 98 | UNSAFE_UNWRAP | HIGH | `let root_dir = env::current_dir().unwrap();` |
| /app/scanner-engine/src/main.rs | 102 | UNSAFE_EXPECT | HIGH | `fs::write(&report_path, &out).expect("Failed to write report");` |
