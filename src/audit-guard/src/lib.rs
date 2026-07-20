use serde::{Deserialize, Serialize};
use thiserror::Error;
use attohttpc::{body::Json, Response};

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum AuditGuardError {
    #[error("invalid API URL: {0}")]
    InvalidApiUrl(String),

    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("server returned error status {status}: {body}")]
    ServerError { status: u16, body: String },

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

#[derive(Debug)]
pub struct AuditGuardClient {
    api_url: String,
}

impl AuditGuardClient {
    pub fn new(api_url: &str) -> Result<Self> {
        let trimmed = api_url.trim();
        if trimmed.is_empty() {
            return Err(AuditGuardError::InvalidApiUrl(
                "API URL must not be empty".to_string(),
            ));
        }

        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            return Err(AuditGuardError::InvalidApiUrl(format!(
                "unsupported scheme in URL '{trimmed}'; expected http or https"
            )));
        }

        Ok(Self {
            api_url: trimmed.to_string(),
        })
    }

    pub fn submit_report(&self, report: &AuditReport) -> Result<()> {
        if report.policy_name.trim().is_empty() {
            return Err(AuditGuardError::ValidationError(
                "policy_name must not be empty".to_string(),
            ));
        }

        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);

        let response = attohttpc::post(&endpoint)
            .header("Content-Type", "application/json")
            .body(Json(report))
            .send()
            .map_err(|e| AuditGuardError::HttpError(e.to_string()))?;

        self.handle_response(response)
    }

    pub fn get_report(&self, id: &str) -> Result<AuditReport> {
        let trimmed_id = id.trim();
        if trimmed_id.is_empty() {
            return Err(AuditGuardError::ValidationError(
                "report ID must not be empty".to_string(),
            ));
        }

        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, trimmed_id);

        let response = attohttpc::get(&endpoint)
            .send()
            .map_err(|e| AuditGuardError::HttpError(e.to_string()))?;

        let status = response.status().as_u16();

        if response.status().is_success() {
            let report = response
                .json()
                .map_err(|e| AuditGuardError::DeserializationError(e.to_string()))?;
            Ok(report)
        } else if status == 404 {
            let body = Self::read_body(response).unwrap_or_else(|_| "<unreadable body>".to_string());
            Err(AuditGuardError::ServerError { status, body })
        } else {
            let body = Self::read_body(response).unwrap_or_else(|_| "<unreadable body>".to_string());
            Err(AuditGuardError::ServerError { status, body })
        }
    }

    fn handle_response(&self, response: Response) -> Result<()> {
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status().as_u16();
            let body = Self::read_body(response).unwrap_or_else(|_| "<unreadable body>".to_string());
            Err(AuditGuardError::ServerError { status, body })
        }
    }

    fn read_body(response: Response) -> Result<String> {
        String::from_utf8(response.bytes().map(|b| b.to_vec()).map_err(|e| AuditGuardError::HttpError(e.to_string()))?)
            .map_err(|e| AuditGuardError::HttpError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

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
    fn test_new_rejects_empty_url() {
        let err = AuditGuardClient::new("").unwrap_err();
        matches!(err, AuditGuardError::InvalidApiUrl(_));
    }

    #[test]
    fn test_new_rejects_whitespace_url() {
        let err = AuditGuardClient::new("   ").unwrap_err();
        matches!(err, AuditGuardError::InvalidApiUrl(_));
    }

    #[test]
    fn test_new_rejects_invalid_scheme() {
        let err = AuditGuardClient::new("ftp://example.com").unwrap_err();
        matches!(err, AuditGuardError::InvalidApiUrl(_));
    }

    #[test]
    fn test_new_accepts_valid_http_url() {
        let client = AuditGuardClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.api_url, "http://localhost:8080");
    }

    #[test]
    fn test_new_accepts_valid_https_url() {
        let client = AuditGuardClient::new("https://api.example.com").unwrap();
        assert_eq!(client.api_url, "https://api.example.com");
    }

    #[test]
    fn test_submit_report_rejects_empty_policy_name() {
        let client = AuditGuardClient::new("http://localhost:8080").unwrap();
        let report = AuditReport {
            policy_name: "".to_string(),
            compliant: true,
            violations: vec![],
        };
        let err = client.submit_report(&report);
        assert!(err.is_err());
    }

    #[test]
    fn test_get_report_rejects_empty_id() {
        let client = AuditGuardClient::new("http://localhost:8080").unwrap();
        let err = client.get_report("").unwrap_err();
        matches!(err, AuditGuardError::ValidationError(_));
    }

    #[test]
    fn test_get_report_rejects_whitespace_id() {
        let client = AuditGuardClient::new("http://localhost:8080").unwrap();
        let err = client.get_report("  ").unwrap_err();
        matches!(err, AuditGuardError::ValidationError(_));
    }

    #[test]
    fn test_error_display_messages() {
        let err = AuditGuardError::InvalidApiUrl("bad url".to_string());
        assert!(err.to_string().contains("invalid API URL"));

        let err = AuditGuardError::HttpError("timeout".to_string());
        assert!(err.to_string().contains("HTTP request failed"));

        let err = AuditGuardError::ServerError {
            status: 500,
            body: "boom".to_string(),
        };
        assert!(err.to_string().contains("500"));
        assert!(err.to_string().contains("boom"));

        let err = AuditGuardError::ValidationError("missing field".to_string());
        assert!(err.to_string().contains("report validation failed"));
    }

    #[test]
    fn test_error_source_chains() {
        let err = AuditGuardError::InvalidApiUrl("test".to_string());
        assert!(err.source().is_none());

        let err = AuditGuardError::ServerError {
            status: 404,
            body: "n/a".to_string(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn test_audit_report_serialization_roundtrip() {
        let report = AuditReport {
            policy_name: "roundtrip".to_string(),
            compliant: false,
            violations: vec!["v1".to_string(), "v2".to_string()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy_name, "roundtrip");
        assert!(!parsed.compliant);
        assert_eq!(parsed.violations.len(), 2);
    }
}
