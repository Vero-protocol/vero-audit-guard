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
    #[error("audit guard API URL must use http or https")]
    InvalidApiUrl,
    #[error("report id must be a non-empty path segment")]
    InvalidReportId,
    #[error("audit report policy name must not be empty")]
    InvalidReport,
    #[error("audit guard request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("audit guard API returned status {0}")]
    ApiStatus(reqwest::StatusCode),
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
    pub fn new(api_url: &str) -> Result<Self, AuditGuardError> {
        let api_url = api_url.trim().trim_end_matches('/');
        if !(api_url.starts_with("http://") || api_url.starts_with("https://")) {
            return Err(AuditGuardError::InvalidApiUrl);
        }

        Ok(Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        })
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), AuditGuardError> {
        if report.policy_name.trim().is_empty() {
            return Err(AuditGuardError::InvalidReport);
        }
        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);

        let response = self.client.post(&endpoint).json(report).send().await?;

        response
            .error_for_status()
            .map(|_| ())
            .map_err(|error| match error.status() {
                Some(status) => AuditGuardError::ApiStatus(status),
                None => AuditGuardError::Request(error),
            })
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, AuditGuardError> {
        if id.trim().is_empty()
            || id
                .chars()
                .any(|character| matches!(character, '/' | '?' | '#'))
        {
            return Err(AuditGuardError::InvalidReportId);
        }
        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);

        let response = self
            .client
            .get(&endpoint)
            .send()
            .await?
            .error_for_status()
            .map_err(|error| match error.status() {
                Some(status) => AuditGuardError::ApiStatus(status),
                None => AuditGuardError::Request(error),
            })?;

        let report: AuditReport = response.json().await?;

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
    fn rejects_invalid_api_urls() {
        assert!(matches!(
            AuditGuardClient::new("localhost:8080"),
            Err(AuditGuardError::InvalidApiUrl)
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_report_input() {
        let client = AuditGuardClient::new("http://localhost:8080").unwrap();
        let report = AuditReport {
            policy_name: "  ".to_string(),
            compliant: true,
            violations: vec![],
        };

        assert!(matches!(
            client.submit_report(&report).await,
            Err(AuditGuardError::InvalidReport)
        ));
        assert!(matches!(
            client.get_report("../etc/passwd").await,
            Err(AuditGuardError::InvalidReportId)
        ));
    }
}
