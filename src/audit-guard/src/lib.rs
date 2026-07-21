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

    #[error("Invalid report payload: {0}")]
    InvalidReport(String),
}

pub type AuditGuardResult<T> = Result<T, AuditGuardError>;

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
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        }
    }

    pub fn new_validated(api_url: &str) -> Result<Self, AuditGuardError> {
        validate_url(api_url)?;
        Ok(Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        })
    }

    pub async fn submit_report(&self, report: &AuditReport) -> AuditGuardResult<()> {
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

    pub async fn get_report(&self, id: &str) -> AuditGuardResult<AuditReport> {
        validate_url(&self.api_url)?;
        if id.trim().is_empty() {
            return Err(AuditGuardError::InvalidReport("report id must not be empty".into()));
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
