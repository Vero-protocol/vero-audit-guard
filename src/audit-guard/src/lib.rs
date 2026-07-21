use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditGuardError {
    #[error("API URL cannot be empty")]
    EmptyUrl,

    #[error("Invalid API URL format: {0}")]
    InvalidUrlFormat(String),

    #[error("Policy name cannot be empty")]
    EmptyPolicyName,

    #[error("Invalid policy name character in: {0}")]
    InvalidPolicyName(String),

    #[error("Compliant report must not contain any violations, but found {0} violations")]
    ViolationsInCompliantReport(usize),

    #[error("Non-compliant report must have at least one violation")]
    NoViolationsInNonCompliantReport,

    #[error("Violation details cannot be empty")]
    EmptyViolation,

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API response failed with status {status}")]
    ApiFailure {
        status: reqwest::StatusCode,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

impl AuditReport {
    pub fn validate(&self) -> Result<(), AuditGuardError> {
        if self.policy_name.trim().is_empty() {
            return Err(AuditGuardError::EmptyPolicyName);
        }
        
        // Ensure policy name only contains alphanumeric characters, dashes, or underscores
        if !self.policy_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(AuditGuardError::InvalidPolicyName(self.policy_name.clone()));
        }

        if self.compliant {
            if !self.violations.is_empty() {
                return Err(AuditGuardError::ViolationsInCompliantReport(self.violations.len()));
            }
        } else {
            if self.violations.is_empty() {
                return Err(AuditGuardError::NoViolationsInNonCompliantReport);
            }
            for violation in &self.violations {
                if violation.trim().is_empty() {
                    return Err(AuditGuardError::EmptyViolation);
                }
            }
        }

        Ok(())
    }
}

pub struct AuditGuardClient {
    client: Client,
    api_url: String,
}

fn validate_url(url: &str) -> Result<(), AuditGuardError> {
    if url.trim().is_empty() {
        return Err(AuditGuardError::EmptyUrl);
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(AuditGuardError::InvalidUrlFormat(url.to_string()));
    }
    Ok(())
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

    /// Creates a new AuditGuardClient and validates the URL immediately
    pub fn new_validated(api_url: &str) -> Result<Self, AuditGuardError> {
        validate_url(api_url)?;
        Ok(Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        })
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), AuditGuardError> {
        validate_url(&self.api_url)?;
        report.validate()?;
        
        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);
        
        let response = self.client.post(&endpoint)
            .json(report)
            .send()
            .await?;
            
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AuditGuardError::ApiFailure { status: response.status() })
        }
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, AuditGuardError> {
        validate_url(&self.api_url)?;
        if id.trim().is_empty() {
            return Err(AuditGuardError::InvalidUrlFormat("Empty report ID".to_string()));
        }
        
        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);
        
        let report: AuditReport = self.client.get(&endpoint)
            .send()
            .await?
            .json()
            .await?;
            
        report.validate()?;
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
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_invalid_policy_name() {
        let report = AuditReport {
            policy_name: "invalid name!".to_string(),
            compliant: true,
            violations: vec![],
        };
        assert!(matches!(
            report.validate(),
            Err(AuditGuardError::InvalidPolicyName(_))
        ));

        let report_empty = AuditReport {
            policy_name: "".to_string(),
            compliant: true,
            violations: vec![],
        };
        assert!(matches!(
            report_empty.validate(),
            Err(AuditGuardError::EmptyPolicyName)
        ));
    }

    #[test]
    fn test_violations_in_compliant_report() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: true,
            violations: vec!["some violation".to_string()],
        };
        assert!(matches!(
            report.validate(),
            Err(AuditGuardError::ViolationsInCompliantReport(1))
        ));
    }

    #[test]
    fn test_empty_violations_in_non_compliant_report() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: false,
            violations: vec![],
        };
        assert!(matches!(
            report.validate(),
            Err(AuditGuardError::NoViolationsInNonCompliantReport)
        ));
    }

    #[test]
    fn test_empty_violation_description() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: false,
            violations: vec!["".to_string()],
        };
        assert!(matches!(
            report.validate(),
            Err(AuditGuardError::EmptyViolation)
        ));
    }

    #[test]
    fn test_url_validation() {
        assert!(validate_url("https://api.vero.audit").is_ok());
        assert!(validate_url("http://localhost:8080").is_ok());
        assert!(matches!(
            validate_url(""),
            Err(AuditGuardError::EmptyUrl)
        ));
        assert!(matches!(
            validate_url("ftp://invalid-scheme"),
            Err(AuditGuardError::InvalidUrlFormat(_))
        ));
    }
}
