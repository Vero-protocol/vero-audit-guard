//! Authenticated, centralized write path for confirmed audit records.
//!
//! This module deliberately has no control-plane operations.  It can only submit
//! an observation to the verifiable-audit-trail service; it cannot pause, reject,
//! or otherwise affect the monitored system.

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ERROR_BODY_BYTES: usize = 4096;
const RECORDS_PATH: &str = "api/v1/audit/records";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfirmedAuditRecord {
    /// A stable, caller-generated id used for idempotency and deduplication.
    pub record_id: String,
    /// RFC3339 timestamp supplied by the observer.
    pub observed_at: String,
    /// SHA-256 (or equivalent) digest of the evidence represented by `payload`.
    pub evidence_hash: String,
    /// The confirmed observation.  No executable/control data is accepted.
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum WritePathError {
    #[error("audit write path URL is invalid: {0}")]
    InvalidUrl(String),
    #[error("audit write path authentication token is empty")]
    MissingAuthentication,
    #[error("audit record field `{0}` is empty")]
    InvalidRecordField(&'static str),
    #[error("audit record evidence hash must be a 64-character hexadecimal SHA-256 digest")]
    InvalidEvidenceHash,
    #[error("audit record payload must not be null")]
    NullPayload,
    #[error("could not serialize audit record: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("audit write request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("audit trail rejected record (HTTP {status}): {body}")]
    Rejected { status: StatusCode, body: String },
}

/// The sole write client used by the observational guard.
#[derive(Clone)]
pub struct AuditTrailClient {
    client: Client,
    endpoint: Url,
    bearer_token: String,
}

impl AuditTrailClient {
    /// Construct a client.  The token is retained privately and is never put in
    /// errors or logs.  `base_url` must be an absolute HTTP(S) URL.
    pub fn new(base_url: &str, bearer_token: &str) -> Result<Self, WritePathError> {
        let mut endpoint = Url::parse(base_url)
            .map_err(|error| WritePathError::InvalidUrl(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(WritePathError::InvalidUrl(
                "an absolute http(s) URL is required".to_string(),
            ));
        }
        if bearer_token.trim().is_empty() {
            return Err(WritePathError::MissingAuthentication);
        }
        // Avoid accepting a base path that can escape the service namespace.
        let mut path = endpoint.path().trim_end_matches('/').to_string();
        path.push('/');
        path.push_str(RECORDS_PATH);
        endpoint.set_path(&path);

        let client = Client::builder().timeout(DEFAULT_TIMEOUT).build()?;
        Ok(Self { client, endpoint, bearer_token: bearer_token.to_owned() })
    }

    /// Submit one confirmed observation.  This is intentionally the only write
    /// operation exposed by the client.
    pub async fn submit(&self, record: &ConfirmedAuditRecord) -> Result<(), WritePathError> {
        validate_record(record)?;
        let body = serde_json::to_vec(record)?;
        let response = match self.client
            .post(self.endpoint.clone())
            .bearer_auth(&self.bearer_token)
            .header("content-type", "application/json")
            .header("x-audit-record-id", &record.record_id)
            .header("x-audit-observational-only", "true")
            .body(body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(record_id = %record.record_id, "verifiable audit trail transport failure: {error}");
                return Err(WritePathError::Transport(error));
            }
        };

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let bytes = response.bytes().await?;
        let body = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_ERROR_BODY_BYTES)])
            .replace(['\r', '\n'], " ");
        // The error is returned to the caller so it can alert/retry according to
        // policy; it is never silently discarded and contains no bearer token.
        tracing::error!(%status, record_id = %record.record_id, "verifiable audit trail rejected record");
        Err(WritePathError::Rejected { status, body })
    }
}

fn validate_record(record: &ConfirmedAuditRecord) -> Result<(), WritePathError> {
    if record.record_id.trim().is_empty() {
        return Err(WritePathError::InvalidRecordField("record_id"));
    }
    if record.observed_at.trim().is_empty() {
        return Err(WritePathError::InvalidRecordField("observed_at"));
    }
    if record.evidence_hash.len() != 64
        || !record.evidence_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WritePathError::InvalidEvidenceHash);
    }
    if record.payload.is_null() {
        return Err(WritePathError::NullPayload);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record() -> ConfirmedAuditRecord {
        ConfirmedAuditRecord {
            record_id: "obs-123".into(),
            observed_at: "2026-07-19T18:00:00Z".into(),
            evidence_hash: "a".repeat(64),
            payload: json!({"confirmed": true}),
        }
    }

    #[test]
    fn rejects_missing_credentials_and_unsafe_urls() {
        assert!(matches!(AuditTrailClient::new("https://trail.example", " "), Err(WritePathError::MissingAuthentication)));
        assert!(matches!(AuditTrailClient::new("file:///tmp/trail", "secret"), Err(WritePathError::InvalidUrl(_))));
        assert!(matches!(AuditTrailClient::new("not a url", "secret"), Err(WritePathError::InvalidUrl(_))));
    }

    #[test]
    fn rejects_adversarial_record_values_before_network_access() {
        let mut invalid = record();
        invalid.record_id = "  ".into();
        assert!(matches!(validate_record(&invalid), Err(WritePathError::InvalidRecordField("record_id"))));
        invalid = record(); invalid.evidence_hash = "not-a-hash".into();
        assert!(matches!(validate_record(&invalid), Err(WritePathError::InvalidEvidenceHash)));
        invalid = record(); invalid.payload = Value::Null;
        assert!(matches!(validate_record(&invalid), Err(WritePathError::NullPayload)));
    }

    #[tokio::test]
    async fn submits_confirmed_record_with_authentication_and_observational_header() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("Bearer secret-token"));
            assert!(request.contains("x-audit-observational-only: true"));
            assert!(request.contains("\"record_id\":\"obs-123\""));
            stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        let client = AuditTrailClient::new(&format!("http://{address}"), "secret-token").unwrap();
        assert!(client.submit(&record()).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_non_success_without_leaking_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("authorization: Bearer secret-token") || request.contains("Authorization: Bearer secret-token"));
            stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 14\r\n\r\nnot authorized").unwrap();
        });
        let client = AuditTrailClient::new(&format!("http://{address}"), "secret-token").unwrap();
        let error = client.submit(&record()).await.unwrap_err();
        assert!(matches!(error, WritePathError::Rejected { status, .. } if status == StatusCode::UNAUTHORIZED));
        assert!(!error.to_string().contains("secret-token"));
    }
}
