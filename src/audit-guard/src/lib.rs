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

    // ---- Anomaly dispatch errors (Issue #177) ----

    #[error("Dashboard channel unavailable: {reason}")]
    DashboardChannelUnavailable { reason: String },

    #[error("Invalid anomaly alert payload: {reason}")]
    InvalidAnomalyPayload { reason: String },

    #[error("Anomaly dispatch failed after {attempts} attempt(s): {last_error}")]
    AnomalyDispatchFailed {
        attempts: u32,
        last_error: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

/// Anomaly alert as dispatched to the Guardian Dashboard (Issue #177).
/// Observational-only — no on-chain halt authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    /// Alert type identifier (e.g., "NONCE_SPIKE", "FAILED_TX_BURST").
    pub alert_type: String,
    /// Severity level.
    pub severity: AnomalySeverity,
    /// Affected address, if applicable.
    pub address: Option<String>,
    /// Human-readable detail about the anomaly.
    pub detail: String,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Source service identifier.
    pub source: Option<String>,
}

/// Severity levels for anomaly alerts (aligned with Vero security taxonomy).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AnomalyAlert {
    /// Validates the alert payload. Returns Ok(()) if valid.
    pub fn validate(&self) -> Result<(), AuditGuardError> {
        if self.alert_type.trim().is_empty() {
            return Err(AuditGuardError::InvalidAnomalyPayload {
                reason: "alert_type is empty".to_string(),
            });
        }
        if self.detail.trim().is_empty() {
            return Err(AuditGuardError::InvalidAnomalyPayload {
                reason: "detail is empty".to_string(),
            });
        }
        if self.timestamp_ms == 0 {
            return Err(AuditGuardError::InvalidAnomalyPayload {
                reason: "timestamp_ms must be positive".to_string(),
            });
        }
        Ok(())
    }
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

    /// Dispatches an anomaly alert to the Guardian Dashboard (Issue #177).
    ///
    /// This is an observational-only operation — it does not affect on-chain
    /// state or halt authority. Failures are propagated via the error type
    /// for the caller to log and handle (e.g., retry or alerting).
    pub async fn dispatch_anomaly_alert(
        &self,
        alert: &AnomalyAlert,
    ) -> Result<(), AuditGuardError> {
        validate_url(&self.api_url)?;
        alert.validate()?;

        let endpoint = format!("{}/api/v1/anomaly/alerts", self.api_url);

        let response = self
            .client
            .post(&endpoint)
            .json(alert)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            Err(AuditGuardError::DashboardChannelUnavailable {
                reason: format!("Dashboard returned HTTP {}", status.as_u16()),
            })
        }
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

    // ---- Anomaly alert tests (Issue #177) ----

    #[test]
    fn test_anomaly_alert_valid() {
        let alert = AnomalyAlert {
            alert_type: "NONCE_SPIKE".to_string(),
            severity: AnomalySeverity::High,
            address: Some("GABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKL".to_string()),
            detail: "Nonce jumped by 100".to_string(),
            timestamp_ms: 1700000000000,
            source: Some("anomaly-detector".to_string()),
        };
        assert!(alert.validate().is_ok());
    }

    #[test]
    fn test_anomaly_alert_empty_type() {
        let alert = AnomalyAlert {
            alert_type: "".to_string(),
            severity: AnomalySeverity::High,
            address: None,
            detail: "Something happened".to_string(),
            timestamp_ms: 1700000000000,
            source: None,
        };
        assert!(matches!(
            alert.validate(),
            Err(AuditGuardError::InvalidAnomalyPayload { .. })
        ));
    }

    #[test]
    fn test_anomaly_alert_whitespace_type() {
        let alert = AnomalyAlert {
            alert_type: "   ".to_string(),
            severity: AnomalySeverity::Medium,
            address: None,
            detail: "Something happened".to_string(),
            timestamp_ms: 1700000000000,
            source: None,
        };
        assert!(matches!(
            alert.validate(),
            Err(AuditGuardError::InvalidAnomalyPayload { .. })
        ));
    }

    #[test]
    fn test_anomaly_alert_empty_detail() {
        let alert = AnomalyAlert {
            alert_type: "FAILED_TX_BURST".to_string(),
            severity: AnomalySeverity::Critical,
            address: None,
            detail: "".to_string(),
            timestamp_ms: 1700000000000,
            source: None,
        };
        assert!(matches!(
            alert.validate(),
            Err(AuditGuardError::InvalidAnomalyPayload { .. })
        ));
    }

    #[test]
    fn test_anomaly_alert_zero_timestamp() {
        let alert = AnomalyAlert {
            alert_type: "THREAT_FEED_MATCH".to_string(),
            severity: AnomalySeverity::Critical,
            address: None,
            detail: "Blocklisted address".to_string(),
            timestamp_ms: 0,
            source: None,
        };
        assert!(matches!(
            alert.validate(),
            Err(AuditGuardError::InvalidAnomalyPayload { .. })
        ));
    }

    #[test]
    fn test_anomaly_severity_serialization() {
        let json = serde_json::to_string(&AnomalySeverity::Critical).unwrap();
        assert_eq!(json, "\"CRITICAL\"");
        let json = serde_json::to_string(&AnomalySeverity::Low).unwrap();
        assert_eq!(json, "\"LOW\"");
    }

    #[test]
    fn test_anomaly_alert_serialization() {
        let alert = AnomalyAlert {
            alert_type: "NONCE_SPIKE".to_string(),
            severity: AnomalySeverity::High,
            address: Some("GABC".to_string()),
            detail: "Spike".to_string(),
            timestamp_ms: 1700000000000,
            source: Some("anomaly-detector".to_string()),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: AnomalyAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.alert_type, "NONCE_SPIKE");
        assert_eq!(parsed.severity, AnomalySeverity::High);
        assert_eq!(parsed.detail, "Spike");
    }

    #[test]
    fn test_dashboard_channel_unavailable_error_format() {
        let err = AuditGuardError::DashboardChannelUnavailable {
            reason: "HTTP 503".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Dashboard channel unavailable: HTTP 503"
        );
    }

    #[test]
    fn test_invalid_anomaly_payload_error_format() {
        let err = AuditGuardError::InvalidAnomalyPayload {
            reason: "type is missing".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid anomaly alert payload: type is missing"
        );
    }

    #[test]
    fn test_anomaly_dispatch_failed_error_format() {
        let err = AuditGuardError::AnomalyDispatchFailed {
            attempts: 3,
            last_error: "timeout".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Anomaly dispatch failed after 3 attempt(s): timeout"
        );
    }
}
