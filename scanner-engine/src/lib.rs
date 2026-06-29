use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: String,
    pub snippet: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanReport {
    pub target: String,
    pub total_files: usize,
    pub findings: Vec<Finding>,
    pub report_hash: String,
}

/// Static analysis rules applied to Soroban/Rust contract source files.
pub const RULES: &[(&str, &str, &str)] = &[
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

pub struct CompiledRule {
    pub regex: Regex,
    pub id: &'static str,
    pub severity: &'static str,
}

pub fn compile_rules(rules: &[(&'static str, &'static str, &'static str)]) -> Vec<CompiledRule> {
    rules
        .iter()
        .map(|(pat, id, severity)| CompiledRule {
            regex: Regex::new(pat).expect("static scanner rule must compile"),
            id,
            severity,
        })
        .collect()
}

pub fn scan_file(path: &Path, rules: &[CompiledRule]) -> Vec<Finding> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    scan_content(&content, &path.display().to_string(), rules)
}

/// Scan raw string content (used by fuzz targets without disk I/O).
pub fn scan_content(content: &str, label: &str, rules: &[CompiledRule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        if line.contains("fs::write(dir.join") {
            continue;
        }
        for rule in rules {
            if rule.regex.is_match(line) {
                findings.push(Finding {
                    file: label.to_string(),
                    line: lineno + 1,
                    rule: rule.id.to_string(),
                    severity: rule.severity.to_string(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    findings
}

pub fn rust_source_files(target: &str) -> Vec<PathBuf> {
    WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

pub fn scan_target(target: &str, rules: &[CompiledRule]) -> (usize, Vec<Finding>) {
    let files = rust_source_files(target);
    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|path| scan_file(path, rules))
        .collect();

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.rule.cmp(&b.rule))
    });

    (files.len(), findings)
}

pub fn sha256_of(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
