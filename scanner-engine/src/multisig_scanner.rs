use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GovernanceFinding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: String,
    pub snippet: String,
    pub description: String,
}

#[derive(Debug, Error)]
pub enum MultisigScannerError {
    #[error("invalid governance input: {0}")]
    InvalidInput(String),

    #[error("threshold validation failed: expected >= 2, got {0}")]
    InvalidThreshold(u32),

    #[error("signer count mismatch: expected {expected}, got {actual}")]
    SignerCountMismatch { expected: u32, actual: u32 },

    #[error("timelock configuration error: {0}")]
    TimelockError(String),

    #[error("regex compilation failed for rule '{rule}': {source}")]
    RuleCompilation {
        rule: &'static str,
        source: regex::Error,
    },
}

pub type MultisigResult<T> = Result<T, MultisigScannerError>;

#[derive(Debug)]
struct CompiledGovernanceRule {
    regex: Regex,
    id: &'static str,
    severity: &'static str,
    description: &'static str,
}

fn compile_governance_rules() -> MultisigResult<Vec<CompiledGovernanceRule>> {
    let raw_rules: &[(&str, &str, &str, &str)] = &[
        (
            r"fn\s+withdraw\b[^\{]*\{[^}]*transfer\b",
            "UNSAFE_SINGLE_SIG_WITHDRAWAL",
            "CRITICAL",
            "Withdrawal function lacks explicit multi-sig authorization check",
        ),
        (
            r"(?i)\bthreshold\b(\s*:\s*\w+)?\s*=\s*1(u32)?\b|\b[mn]\s*=\s*1(u32)?\b",
            "WEAK_THRESHOLD",
            "HIGH",
            "Multi-sig threshold is set to 1, effectively disabling multi-sig protection",
        ),
        (
            r"timelock\s*=\s*0\b|delay\s*=\s*0\b|Duration::ZERO|ZERO_DURATION",
            "TIMELOCK_BYPASS",
            "HIGH",
            "Timelock or delay is zero, allowing immediate execution without waiting period",
        ),
        (
            r"pub\s+key\s*:\s*PublicKey|hardcoded|const\s+ADMIN\s*:|const\s+OWNER\s*:",
            "HARDCODED_SIGNER",
            "MEDIUM",
            "Signer or admin key appears hardcoded instead of using configurable multi-sig set",
        ),
        (
            r"signers\s*\.\s*len\s*\(\)\s*>=?\s*1\b|signers\s*\.\s*count\s*\(\)\s*>=?\s*1\b|require!\s*\(\s*signers\s*\.\s*len\s*\(\)\s*>=\s*1",
            "MISSING_SIGNER_VALIDATION",
            "HIGH",
            "Signer count is validated against a hardcoded minimum of 1 instead of the configured threshold",
        ),
        (
            r"admin\s*\.\s*withdraw|admin\s*\.\s*transfer|authority\s*\.\s*transfer",
            "ADMIN_KEY_OVERRIDE",
            "CRITICAL",
            "Admin or authority key can bypass multi-sig requirements for transfers",
        ),
        (
            r"set_threshold\s*\([^)]*\)|update_threshold\s*\([^)]*\)|change_threshold\s*\([^)]*\)",
            "UNPROTECTED_THRESHOLD_CHANGE",
            "HIGH",
            "Threshold change function lacks multi-sig confirmation requirement",
        ),
        (
            r"require!\s*\(\s*true\s*\)|assert!\s*\(\s*true\s*\)|if\s+true\s*\{",
            "NOOP_AUTH_CHECK",
            "HIGH",
            "Authorization check is a no-op (always true), bypassing security logic",
        ),
    ];

    raw_rules
        .iter()
        .map(|(pat, id, severity, description)| {
            let regex = Regex::new(pat).map_err(|source| MultisigScannerError::RuleCompilation {
                rule: *id,
                source,
            })?;
            Ok(CompiledGovernanceRule {
                regex,
                id: *id,
                severity: *severity,
                description: *description,
            })
        })
        .collect()
}

fn scan_governance_content(content: &str, file: &str, rules: &[CompiledGovernanceRule]) -> Vec<GovernanceFinding> {
    let mut findings = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        for rule in rules {
            if rule.regex.is_match(line) {
                findings.push(GovernanceFinding {
                    file: file.to_string(),
                    line: lineno + 1,
                    rule: rule.id.to_string(),
                    severity: rule.severity.to_string(),
                    snippet: line.trim().to_string(),
                    description: rule.description.to_string(),
                });
            }
        }
    }

    findings
}

pub fn scan_multisig_governance(content: &str, file: &str) -> MultisigResult<Vec<GovernanceFinding>> {
    if content.is_empty() {
        return Err(MultisigScannerError::InvalidInput(
            "source content is empty".into(),
        ));
    }

    if file.is_empty() {
        return Err(MultisigScannerError::InvalidInput(
            "file name is empty".into(),
        ));
    }

    let rules = compile_governance_rules()?;
    Ok(scan_governance_content(content, file, &rules))
}

pub fn validate_threshold(threshold: u32, min_threshold: u32) -> MultisigResult<()> {
    if threshold < 2 {
        return Err(MultisigScannerError::InvalidThreshold(threshold));
    }
    if threshold < min_threshold {
        return Err(MultisigScannerError::InvalidThreshold(threshold));
    }
    Ok(())
}

pub fn validate_signer_count(expected: u32, actual: u32) -> MultisigResult<()> {
    if actual < expected {
        return Err(MultisigScannerError::SignerCountMismatch { expected, actual });
    }
    Ok(())
}

pub fn validate_timelock(seconds: u64, min_seconds: u64) -> MultisigResult<()> {
    if seconds < min_seconds {
        return Err(MultisigScannerError::TimelockError(format!(
            "timelock {}s is below minimum {}s",
            seconds, min_seconds
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_detects_single_sig_withdrawal() {
        let source = r#"pub fn withdraw() { transfer(); }"#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "UNSAFE_SINGLE_SIG_WITHDRAWAL"));
    }

    #[test]
    fn scan_detects_weak_threshold() {
        let source = r#"
            const THRESHOLD: u32 = 1;
            let m = 1;
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "WEAK_THRESHOLD"));
    }

    #[test]
    fn scan_detects_timelock_bypass() {
        let source = r#"
            const TIMELOCK: u64 = 0;
            let delay = Duration::ZERO;
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "TIMELOCK_BYPASS"));
    }

    #[test]
    fn scan_detects_hardcoded_signer() {
        let source = r#"
            pub key: PublicKey = PublicKey::from_str("G...").unwrap();
            const ADMIN: &str = "G...";
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "HARDCODED_SIGNER"));
    }

    #[test]
    fn scan_detects_missing_signer_validation() {
        let source = r#"
            if signers.len() >= 1 {
                // execute
            }
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "MISSING_SIGNER_VALIDATION"));
    }

    #[test]
    fn scan_detects_admin_key_override() {
        let source = r#"
            admin.withdraw(amount);
            authority.transfer(to, amount);
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "ADMIN_KEY_OVERRIDE"));
    }

    #[test]
    fn scan_detects_unprotected_threshold_change() {
        let source = r#"
            pub fn set_threshold(&mut self, new_threshold: u32) {
                self.threshold = new_threshold;
            }
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "UNPROTECTED_THRESHOLD_CHANGE"));
    }

    #[test]
    fn scan_detects_noop_auth_check() {
        let source = r#"
            require!(true);
            assert!(true);
            if true {
                // bypass
            }
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.iter().any(|f| f.rule == "NOOP_AUTH_CHECK"));
    }

    #[test]
    fn scan_returns_no_findings_for_safe_code() {
        let source = r#"
            pub fn execute_proposal(env: Env, proposal_id: u64) {
                let signers = get_confirmed_signers(&env, proposal_id);
                require!(signers.len() >= self.threshold, "insufficient signatures");
                let delay = get_timelock_delay(&env);
                require!(delay >= MIN_TIMELOCK, "timelock too short");
                // safe execution
            }
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.is_empty(), "expected no findings for safe code, got: {:?}", findings);
    }

    #[test]
    fn scan_handles_empty_content_error() {
        let result = scan_multisig_governance("", "treasury.rs");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigScannerError::InvalidInput(_)
        ));
    }

    #[test]
    fn scan_handles_empty_filename_error() {
        let result = scan_multisig_governance("fn foo() {}", "");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigScannerError::InvalidInput(_)
        ));
    }

    #[test]
    fn validate_threshold_rejects_weak_value() {
        let result = validate_threshold(1, 2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigScannerError::InvalidThreshold(1)
        ));
    }

    #[test]
    fn validate_threshold_accepts_valid_value() {
        validate_threshold(3, 2).unwrap();
    }

    #[test]
    fn validate_signer_count_rejects_insufficient() {
        let result = validate_signer_count(3, 2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigScannerError::SignerCountMismatch { expected: 3, actual: 2 }
        ));
    }

    #[test]
    fn validate_signer_count_accepts_exact_match() {
        validate_signer_count(3, 3).unwrap();
    }

    #[test]
    fn validate_timelock_rejects_too_short() {
        let result = validate_timelock(10, 60);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MultisigScannerError::TimelockError(_)
        ));
    }

    #[test]
    fn validate_timelock_accepts_valid_duration() {
        validate_timelock(3600, 60).unwrap();
    }

    #[test]
    fn scan_detects_multiple_findings_in_same_file() {
        let source = r#"
            pub fn withdraw() { transfer(); }
            const THRESHOLD: u32 = 1;
            pub fn set_threshold(&mut self, t: u32) { self.threshold = t; }
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|f| f.rule == "UNSAFE_SINGLE_SIG_WITHDRAWAL"));
        assert!(findings.iter().any(|f| f.rule == "WEAK_THRESHOLD"));
        assert!(findings.iter().any(|f| f.rule == "UNPROTECTED_THRESHOLD_CHANGE"));
    }

    #[test]
    fn scan_findings_include_line_numbers() {
        let source = r#"line 1: safe
            line 2: pub fn withdraw() { transfer(); }
            line 3: safe
        "#;
        let findings = scan_multisig_governance(source, "treasury.rs").unwrap();
        let withdrawal = findings.iter().find(|f| f.rule == "UNSAFE_SINGLE_SIG_WITHDRAWAL");
        assert!(withdrawal.is_some());
        assert_eq!(withdrawal.unwrap().line, 2);
    }

    #[test]
    fn scan_findings_include_file_name() {
        let source = "pub fn withdraw() { transfer(); }";
        let findings = scan_multisig_governance(source, "my_treasury.rs").unwrap();
        assert!(findings.iter().all(|f| f.file == "my_treasury.rs"));
    }
}
