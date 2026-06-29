use std::{env, fs};
use vero_scanner_engine::{compile_rules, scan_target, sha256_of, ScanReport, RULES};

fn main() {
    let target = env::args()
        .nth(1)
        .unwrap_or_else(|| "../vero-core-contracts".into());
    let rules = compile_rules(RULES);
    let (file_count, all_findings) = scan_target(&target, &rules);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    use std::path::PathBuf;

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
        fs::write(dir.join("a.rs"), "fn a() { unwrap(); }\n").expect("a.rs should be written");
        fs::write(dir.join("ignored.txt"), "unwrap()\n").expect("ignored file should be written");

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
}
