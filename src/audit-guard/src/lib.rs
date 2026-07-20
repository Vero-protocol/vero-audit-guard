use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AuditGuardError {
    #[error("API request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("invalid report payload: {0}")]
    InvalidReport(String),
}

pub type AuditGuardResult<T> = Result<T, AuditGuardError>;

pub struct AuditGuardClient {
    client: Client,
    api_url: String,
}

impl AuditGuardClient {
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        }
    }

    pub async fn submit_report(&self, report: &AuditReport) -> AuditGuardResult<()> {
        if report.policy_name.is_empty() {
            return Err(AuditGuardError::InvalidReport(
                "policy_name must not be empty".into(),
            ));
        }

        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);
        
        let response = self.client.post(&endpoint)
            .json(report)
            .send()
            .await?;
            
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(AuditGuardError::InvalidReport(format!(
                "Failed to submit report. Status: {}, body: {}",
                status, body
            )))
        }
    }

    pub async fn get_report(&self, id: &str) -> AuditGuardResult<AuditReport> {
        if id.is_empty() {
            return Err(AuditGuardError::InvalidReport(
                "report id must not be empty".into(),
            ));
        }

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

    #[test]
    fn test_empty_policy_name_rejected() {
        let client = AuditGuardClient::new("http://example.com");
        let report = AuditReport {
            policy_name: String::new(),
            compliant: true,
            violations: vec![],
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.submit_report(&report));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuditGuardError::InvalidReport(_)));
    }

    #[test]
    fn test_empty_report_id_rejected() {
        let client = AuditGuardClient::new("http://example.com");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(client.get_report(""));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuditGuardError::InvalidReport(_)));
    }
}
