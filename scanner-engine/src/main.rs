use std::{env, fs, path::Path};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// Static analysis rules applied to Soroban/Rust contract source files.
const RULES: &[(&str, &str, &str)] = &[
    (r"unwrap\(\)", "UNSAFE_UNWRAP", "HIGH"),
    (r"expect\(.+\)", "UNSAFE_EXPECT", "HIGH"),
    (r"unsafe\s*\{", "UNSAFE_BLOCK", "CRITICAL"),
    (r"panic!\(", "EXPLICIT_PANIC", "MEDIUM"),
    (r"todo!\(|unimplemented!\(", "INCOMPLETE_CODE", "HIGH"),
    (r"//\s*(?i)FIXME|//\s*(?i)HACK", "CODE_DEBT", "LOW"),
    (r"transfer_from\b", "TRANSFER_FROM_USAGE", "MEDIUM"),
    (r"env\.storage\(\)\.instance\(\)\.set\b", "UNCHECKED_STORAGE_SET", "LOW"),
];

fn scan_file(path: &Path, rules: &[(&str, &str, &str)]) -> Vec<Finding> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();
    let compiled: Vec<(Regex, &str, &str)> = rules
        .iter()
        .map(|(pat, id, sev)| (Regex::new(pat).unwrap(), *id, *sev))
        .collect();

    for (lineno, line) in content.lines().enumerate() {
        for (re, rule_id, severity) in &compiled {
            if re.is_match(line) {
                findings.push(Finding {
                    file: path.display().to_string(),
                    line: lineno + 1,
                    rule: rule_id.to_string(),
                    severity: severity.to_string(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    findings
}

fn sha256_of(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| "../vero-core-contracts".into());
    let mut all_findings = Vec::new();
    let mut file_count = 0;

    for entry in WalkDir::new(&target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false))
    {
        file_count += 1;
        all_findings.extend(scan_file(entry.path(), RULES));
    }

    let report_json = serde_json::to_string_pretty(&all_findings).unwrap();
    let hash = sha256_of(&report_json);

    let report = ScanReport {
        target: target.clone(),
        total_files: file_count,
        findings: all_findings,
        report_hash: hash,
    };

    let out = serde_json::to_string_pretty(&report).unwrap();
    println!("{}", out);

    // Write report to /reports directory
    let root_dir = env::current_dir().unwrap();
    let report_dir = root_dir.join("reports");
    fs::create_dir_all(&report_dir).ok();
    let report_path = report_dir.join("latest-scan.json");
    fs::write(&report_path, &out).expect("Failed to write report");
    eprintln!("[scanner] Report written to {}", report_path.display());
    eprintln!("[scanner] Report SHA-256: {}", report.report_hash);

    if report.findings.iter().any(|f| f.severity == "CRITICAL") {
        eprintln!("[scanner] CRITICAL findings detected — failing build.");
        std::process::exit(1);
    }
}
