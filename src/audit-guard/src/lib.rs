use serde::{Deserialize, Serialize};
use thiserror::Error;
use reqwest::Client; // using async client for flexibility

#[derive(Error, Debug, Serialize, Deserialize)]
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
    ApiFailure { status: reqwest::StatusCode },

    #[error("failed to deserialize response: {0}")]
    DeserializationError(String),

    #[error("report validation failed: {0}")]
    ValidationError(String),
}

pub type Result<T> = std::result::Result<T, AuditGuardError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

impl AuditReport {
    pub fn validate(&self) -> Result<()> {
        if self.policy_name.trim().is_empty() {
            return Err(AuditGuardError::EmptyPolicyName);
        }

        if !self.policy_name.chars().all(|c| c.is_alphanumeric