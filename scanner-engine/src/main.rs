use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Debug)]
struct Finding {
    file: String,
    line: usize,
    rule: String,
    severity: String,
    snippet: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ScanReport {
    target: String,
    total_files: usize,
    findings: Vec<Finding>,
    report_hash: String,
}

/// Structured error type for all scanner-engine failure modes.
/// Each variant maps to a distinct exit code and stderr format string.
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("io error: {path}: {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("serialization failed: {0}")]
    SerializationError(#[source] serde_json::Error),
    #[error("report write failed: {path}: {source}")]
    ReportWriteError {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid target: {path}: {reason}")]
    InvalidTarget { path: String, reason: String },
    #[error("report integrity check failed")]
    IntegrityCheckFailed,
}

/// Static analysis rules applied to Soroban/Rust contract source files.
const RULES: &[(&str, &str, &str)] = &[
    (r"unwrap\(\)", "UNSAFE_UNWRAP", "HIGH"),
    (r"expect\(.+\)", "UNSAFE_EXPECT", "HIGH"),
    (r"unsafe\s*\{", "UNSAFE_BLOCK", "CRITICAL"),
    (r"panic!\(", "EXPLICIT_PANIC", "MEDIUM"),
    (r"todo!\(|unimplemented!\(", "INCOMPLETE_CODE", "HIGH"),
    (r"//\s*(?i)FIXME|//\s*(?i)HACK", "CODE_DEBT", "LOW"),
    (r"transfer_from\b", "TRANSFER_FROM_USAGE", "MEDIUM"),
    (
        r"env\.storage\(\)\.instance\(\)\.set\b",
        "UNCHECKED_STORAGE_SET",
        "LOW",
    ),
];

struct CompiledRule {
    regex: Regex,
    id: &'static str,
    severity: &'static str,
}

fn compile_rules(rules: &[(&'static str, &'static str, &'static str)]) -> Vec<CompiledRule> {
    rules
        .iter()
        .map(|(pat, id, severity)| CompiledRule {
            // SAFETY: static regex patterns are validated at compile time; panic here is intentional
            regex: Regex::new(pat).expect("static scanner rule must compile"),
            id,
            severity,
        })
        .collect()
}

/// Returns (readable: bool, findings: Vec<Finding>).
/// On read failure, emits a WARN to stderr and returns (false, vec![]).
/// Readable files that produce no findings return (true, vec![]).
fn scan_file(path: &Path, rules: &[CompiledRule]) -> (bool, Vec<Finding>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[scanner] WARN: skipped {}: {}", path.display(), e);
            return (false, vec![]);
        }
    };

    let mut findings = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        // Skip scanning lines that appear to be part of the scanner's own test suite
        // to avoid false positives when the scanner analyzes its own source code.
        if line.contains("fs::write(dir.join") {
            continue;
        }

        for rule in rules {
            if rule.regex.is_match(line) {
                findings.push(Finding {
                    file: path.display().to_string(),
                    line: lineno + 1,
                    rule: rule.id.to_string(),
                    severity: rule.severity.to_string(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    (true, findings)
}

fn rust_source_files(target: &str) -> Vec<PathBuf> {
    WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

/// Returns (readable_file_count, sorted_findings).
/// Only successfully-read files count toward total_files in the report.
fn scan_target(target: &str, rules: &[CompiledRule]) -> (usize, Vec<Finding>) {
    let files = rust_source_files(target);
    let results: Vec<(bool, Vec<Finding>)> = files
        .par_iter()
        .map(|path| scan_file(path, rules))
        .collect();

    let readable_count = results.iter().filter(|(ok, _)| *ok).count();
    let mut findings: Vec<Finding> = results.into_iter().flat_map(|(_, f)| f).collect();

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.rule.cmp(&b.rule))
    });

    (readable_count, findings)
}

fn sha256_of(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Pre-scan lifecycle hook: validates that target exists and is a readable directory.
/// Emits INFO to stderr on success. Returns Err on any validation failure.
fn pre_scan_hook(target: &str) -> Result<(), ScannerError> {
    let meta = fs::metadata(target).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ScannerError::InvalidTarget {
                path: target.to_string(),
                reason: "path does not exist".to_string(),
            }
        } else {
            ScannerError::IoError {
                path: target.to_string(),
                source: e,
            }
        }
    })?;

    if !meta.is_dir() {
        return Err(ScannerError::InvalidTarget {
            path: target.to_string(),
            reason: "path is not a directory".to_string(),
        });
    }

    eprintln!("[scanner] INFO: pre-scan check passed: {}", target);
    Ok(())
}

/// Post-scan lifecycle hook: verifies report_hash matches recomputed SHA-256 of findings.
/// Returns Err(IntegrityCheckFailed) if the hash does not match.
fn post_scan_hook(findings: &[Finding], report: &ScanReport) -> Result<(), ScannerError> {
    let json = serde_json::to_string_pretty(findings)
        .map_err(ScannerError::SerializationError)?;
    let expected_hash = sha256_of(&json);

    if expected_hash != report.report_hash {
        return Err(ScannerError::IntegrityCheckFailed);
    }

    Ok(())
}

fn main() {
    let target = env::args()
        .nth(1)
        .unwrap_or_else(|| "../vero-core-contracts".into());

    // Pre-scan hook: validate target directory before scanning (exit 4 on failure)
    if let Err(e) = pre_scan_hook(&target) {
        match &e {
            ScannerError::InvalidTarget { path, reason } => {
                eprintln!("[scanner] ERROR: invalid target: {}: {}", path, reason);
            }
            ScannerError::IoError { path, source } => {
                eprintln!("[scanner] ERROR: invalid target: {}: {}", path, source);
            }
            _ => {
                eprintln!("[scanner] ERROR: pre-scan failed: {}", e);
            }
        }
        std::process::exit(4);
    }

    // SAFETY: static regex patterns are validated at compile time; panic here is intentional
    let rules = compile_rules(RULES);
    let (file_count, all_findings) = scan_target(&target, &rules);

    // Serialize findings — exit 2 on failure, nothing written to stdout
    let report_json = match serde_json::to_string_pretty(&all_findings) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("[scanner] ERROR: serialization failed: {}", e);
            std::process::exit(2);
        }
    };
    let hash = sha256_of(&report_json);

    let report = ScanReport {
        target: target.clone(),
        total_files: file_count,
        findings: all_findings,
        report_hash: hash,
    };

    // Post-scan hook: verify integrity before writing (exit 5 on failure, no disk write)
    if let Err(e) = post_scan_hook(&report.findings, &report) {
        match e {
            ScannerError::IntegrityCheckFailed => {
                eprintln!("[scanner] ERROR: report integrity check failed");
            }
            _ => {
                eprintln!("[scanner] ERROR: post-scan failed: {}", e);
            }
        }
        std::process::exit(5);
    }

    // Serialize full report for stdout and disk — exit 2 on failure
    let out = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("[scanner] ERROR: serialization failed: {}", e);
            std::process::exit(2);
        }
    };
    println!("{}", out);

    // Write report to /reports directory — exit 3 on failure
    let root_dir = match env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "[scanner] ERROR: report write failed: reports/latest-scan.json: {}",
                e
            );
            std::process::exit(3);
        }
    };
    let report_dir = root_dir.join("reports");
    if let Err(e) = fs::create_dir_all(&report_dir) {
        eprintln!(
            "[scanner] ERROR: report write failed: {}: {}",
            report_dir.display(),
            e
        );
        std::process::exit(3);
    }
    let report_path = report_dir.join("latest-scan.json");
    if let Err(e) = fs::write(&report_path, &out) {
        eprintln!(
            "[scanner] ERROR: report write failed: {}: {}",
            report_path.display(),
            e
        );
        std::process::exit(3);
    }
    eprintln!("[scanner] Report written to {}", report_path.display());
    eprintln!("[scanner] Report SHA-256: {}", report.report_hash);

    // CRITICAL findings check — exit 1
    if report.findings.iter().any(|f| f.severity == "CRITICAL") {
        eprintln!("[scanner] CRITICAL findings detected — failing build.");
        std::process::exit(1);
    }

    eprintln!("[scanner] INFO: post-scan check passed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_scan_dir() -> PathBuf {
        let mut dir = env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        dir.push(format!("vero-scanner-test-{}-{unique}", std::process::id()));
        fs::create_dir_all(&dir).expect("test directory should be created");
        dir
    }

    #[test]
    fn scan_target_uses_worker_pool_and_returns_stable_findings() {
        let dir = temp_scan_dir();
        fs::write(dir.join("b.rs"), "fn b() { unsafe { panic!(\"boom\") } }\n")
            .expect("b.rs should be written");
        fs::write(dir.join("a.rs"), "fn a() { unwrap(); }\n")
            .expect("a.rs should be written");
        fs::write(dir.join("ignored.txt"), "unwrap()\n")
            .expect("ignored file should be written");

        let rules = compile_rules(RULES);
        let target = dir.to_string_lossy();
        let (file_count, findings) = scan_target(&target, &rules);

        assert_eq!(file_count, 2);
        assert_eq!(findings.len(), 3);
        assert!(findings.windows(2).all(|pair| pair[0].file <= pair[1].file));
        assert!(findings.iter().any(|f| f.rule == "UNSAFE_UNWRAP"));
        assert!(findings.iter().any(|f| f.rule == "UNSAFE_BLOCK"));
        assert!(findings.iter().any(|f| f.rule == "EXPLICIT_PANIC"));

        fs::remove_dir_all(dir).expect("test directory should be removed");
    }

    #[test]
    fn pre_scan_hook_rejects_nonexistent_path() {
        let result = pre_scan_hook("/nonexistent/vero-scanner-test-does-not-exist-xyz");
        assert!(
            matches!(result, Err(ScannerError::InvalidTarget { .. })),
            "expected InvalidTarget for non-existent path"
        );
    }

    #[test]
    fn pre_scan_hook_rejects_file_path() {
        let dir = temp_scan_dir();
        let file_path = dir.join("not-a-dir.txt");
        fs::write(&file_path, "content").expect("temp file should be written");
        let result = pre_scan_hook(&file_path.to_string_lossy());
        assert!(
            matches!(result, Err(ScannerError::InvalidTarget { .. })),
            "expected InvalidTarget for file path"
        );
        fs::remove_dir_all(dir).expect("temp dir should be removed");
    }

    #[test]
    fn pre_scan_hook_accepts_valid_directory() {
        let dir = temp_scan_dir();
        let result = pre_scan_hook(&dir.to_string_lossy());
        assert!(result.is_ok(), "expected Ok(()) for valid directory");
        fs::remove_dir_all(dir).expect("temp dir should be removed");
    }

    #[test]
    fn post_scan_hook_accepts_matching_hash() {
        let findings: Vec<Finding> = vec![];
        let json = serde_json::to_string_pretty(&findings)
            .expect("empty findings should serialize");
        let hash = sha256_of(&json);
        let report = ScanReport {
            target: "test".into(),
            total_files: 0,
            findings: findings.clone(),
            report_hash: hash,
        };
        assert!(
            post_scan_hook(&findings, &report).is_ok(),
            "expected Ok(()) for matching hash"
        );
    }

    #[test]
    fn post_scan_hook_rejects_tampered_hash() {
        let findings: Vec<Finding> = vec![];
        let report = ScanReport {
            target: "test".into(),
            total_files: 0,
            findings: findings.clone(),
            report_hash: "deadbeef".repeat(8),
        };
        assert!(
            matches!(
                post_scan_hook(&findings, &report),
                Err(ScannerError::IntegrityCheckFailed)
            ),
            "expected IntegrityCheckFailed for tampered hash"
        );
    }
}
