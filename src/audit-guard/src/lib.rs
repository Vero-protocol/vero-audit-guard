use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types — issue #165: zero-address protection
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq)]
pub enum AuditGuardError {
    #[error("zero address is not permitted")]
    ZeroAddress,
}

/// Rejects a zero (all-bytes-zero) address before it reaches any downstream
/// logic. A "zero address" is any string that, after stripping the optional
/// `0x` prefix, consists entirely of ASCII `'0'` characters — equivalent to
/// the Solidity/Soroban address(0) sentinel.
///
/// Returns `Ok(address)` unchanged so callers can use `?` inline.
pub fn require_nonzero_address(address: &str) -> Result<&str, AuditGuardError> {
    let stripped = address.strip_prefix("0x").unwrap_or(address);
    if stripped.is_empty() || stripped.chars().all(|c| c == '0') {
        return Err(AuditGuardError::ZeroAddress);
    }
    Ok(address)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

pub struct AuditGuardClient {
    client: Client,
    api_url: String,
}

impl AuditGuardClient {
    /// Creates a new AuditGuardClient
    ///
    /// # Arguments
    ///
    /// * `api_url` - The base URL of the existing Audit-Guard API
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        }
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);
        
        let response = self.client.post(&endpoint)
            .json(report)
            .send()
            .await?;
            
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to submit report. Status: {}", response.status()).into())
        }
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);
        
        let report: AuditReport = self.client.get(&endpoint)
            .send()
            .await?
            .json()
            .await?;
            
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_report_creation() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: true,
            violations: vec![],
        };
        assert_eq!(report.policy_name, "test-policy");
        assert!(report.compliant);
    }

    // --- issue #165 regression tests ---

    #[test]
    fn zero_address_is_rejected() {
        // plain all-zeros
        assert_eq!(
            require_nonzero_address("0000000000000000000000000000000000000000"),
            Err(AuditGuardError::ZeroAddress)
        );
        // 0x-prefixed all-zeros (EVM / Soroban address(0) form)
        assert_eq!(
            require_nonzero_address("0x0000000000000000000000000000000000000000"),
            Err(AuditGuardError::ZeroAddress)
        );
    }

    #[test]
    fn valid_nonzero_address_passes_through() {
        let addr = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
        assert_eq!(require_nonzero_address(addr), Ok(addr));
    }
}
