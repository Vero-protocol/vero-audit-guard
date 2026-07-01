use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub mod math;
pub mod security_config;
pub mod validation;

// Re-export commonly used types for convenience
pub use security_config::{SecurityConfig, SecuritySeverity, SecurityFinding, SecurityEvent};
pub use validation::{ValidationError, ValidationResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

pub struct AuditGuardClient {
    client: Client,
    api_url: String,
    security_config: SecurityConfig,
}

impl AuditGuardClient {
    /// Creates a new AuditGuardClient with default security configuration
    ///
    /// # Arguments
    ///
    /// * `api_url` - The base URL of the existing Audit-Guard API
    pub fn new(api_url: &str) -> Self {
        Self::with_config(api_url, SecurityConfig::default())
    }

    /// Creates a new AuditGuardClient with custom security configuration
    ///
    /// # Arguments
    ///
    /// * `api_url` - The base URL of the existing Audit-Guard API
    /// * `config` - Security configuration to use
    pub fn with_config(api_url: &str, security_config: SecurityConfig) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
            security_config,
        }
    }

    /// Get a reference to the security configuration
    pub fn security_config(&self) -> &SecurityConfig {
        &self.security_config
    }

    /// Update the security configuration
    pub fn set_security_config(&mut self, config: SecurityConfig) {
        self.security_config = config;
    }

    /// Validate an audit report before submission
    fn validate_report(&self, report: &AuditReport) -> Result<(), ValidationError> {
        use validation::input;

        // Validate policy name
        input::validate_length(&report.policy_name, 1, 100, "policy_name")?;
        input::validate_alphanumeric(&report.policy_name, "policy_name")?;

        // Validate violations don't contain injection patterns
        for (i, violation) in report.violations.iter().enumerate() {
            input::validate_no_sql_injection(violation)
                .map_err(|e| ValidationError::new(
                    format!("violations[{}]", i),
                    e.message,
                    e.code,
                ))?;
        }

        Ok(())
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    /// Reports are validated before submission to prevent injection attacks.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), Box<dyn Error>> {
        // Validate report before submission
        self.validate_report(report)?;

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
        // Validate ID to prevent injection attacks
        use validation::input;
        input::validate_alphanumeric(id, "report_id")?;
        input::validate_length(id, 1, 64, "report_id")?;

        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);
        
        let report: AuditReport = self.client.get(&endpoint)
            .send()
            .await?
            .json()
            .await?;
            
        Ok(report)
    }

    /// Submit a security finding
    pub async fn submit_finding(&self, finding: &SecurityFinding) -> Result<(), Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/findings", self.api_url);
        
        let response = self.client.post(&endpoint)
            .json(finding)
            .send()
            .await?;
            
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to submit finding. Status: {}", response.status()).into())
        }
    }

    /// Submit a security event
    pub async fn submit_event(&self, event: &SecurityEvent) -> Result<(), Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/events", self.api_url);
        
        let response = self.client.post(&endpoint)
            .json(event)
            .send()
            .await?;
            
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to submit event. Status: {}", response.status()).into())
        }
    }

    /// Check if the client should block based on findings
    pub fn should_block_on_findings(&self, findings: &[SecurityFinding]) -> bool {
        findings.iter()
            .any(|f| f.should_block(&self.security_config))
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

    #[test]
    fn test_client_with_default_config() {
        let client = AuditGuardClient::new("https://api.example.com");
        assert_eq!(
            client.security_config().block_threshold,
            SecuritySeverity::Critical
        );
    }

    #[test]
    fn test_client_with_custom_config() {
        let config = SecurityConfig::strict();
        let client = AuditGuardClient::with_config("https://api.example.com", config);
        assert_eq!(
            client.security_config().block_threshold,
            SecuritySeverity::High
        );
    }

    #[test]
    fn test_validate_report_valid() {
        let client = AuditGuardClient::new("https://api.example.com");
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: true,
            violations: vec!["Missing documentation".to_string()],
        };
        assert!(client.validate_report(&report).is_ok());
    }

    #[test]
    fn test_validate_report_invalid_policy_name() {
        let client = AuditGuardClient::new("https://api.example.com");
        let report = AuditReport {
            policy_name: "test@policy".to_string(), // invalid character
            compliant: true,
            violations: vec![],
        };
        assert!(client.validate_report(&report).is_err());
    }

    #[test]
    fn test_validate_report_sql_injection() {
        let client = AuditGuardClient::new("https://api.example.com");
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: false,
            violations: vec!["'; DROP TABLE users--".to_string()],
        };
        let result = client.validate_report(&report);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_block_on_findings() {
        let client = AuditGuardClient::new("https://api.example.com");
        
        let critical_finding = SecurityFinding::new(
            "001".to_string(),
            SecuritySeverity::Critical,
            "vulnerability".to_string(),
            "Critical Issue".to_string(),
            "This is critical".to_string(),
        );

        let low_finding = SecurityFinding::new(
            "002".to_string(),
            SecuritySeverity::Low,
            "info".to_string(),
            "Low Priority".to_string(),
            "This is low priority".to_string(),
        );

        assert!(client.should_block_on_findings(&[critical_finding.clone()]));
        assert!(!client.should_block_on_findings(&[low_finding.clone()]));
        assert!(client.should_block_on_findings(&[low_finding, critical_finding]));
    }
}
