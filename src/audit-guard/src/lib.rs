use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

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

        if self
            .violations
            .iter()
            .any(|violation| violation.trim().is_empty())
        {
            return Err(AuditGuardError::EmptyViolationEntry);
        }

        if self.compliant && !self.violations.is_empty() {
            return Err(AuditGuardError::CompliantReportHasViolations);
        }

        if !self.compliant && self.violations.is_empty() {
            return Err(AuditGuardError::NonCompliantReportMissingViolations);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryOutflowTimeLockConfig {
    pub min_delay_secs: u64,
    pub max_delay_secs: u64,
    pub max_amount: u64,
    pub grace_period_secs: u64,
    pub max_pending_requests: usize,
}

impl TreasuryOutflowTimeLockConfig {
    pub fn validate(&self) -> Result<(), AuditGuardError> {
        if self.min_delay_secs == 0 {
            return Err(AuditGuardError::InvalidTimeLockConfig(
                "min_delay_secs must be greater than zero".to_string(),
            ));
        }

        if self.max_delay_secs < self.min_delay_secs {
            return Err(AuditGuardError::InvalidTimeLockConfig(
                "max_delay_secs must be greater than or equal to min_delay_secs".to_string(),
            ));
        }

        if self.max_amount == 0 {
            return Err(AuditGuardError::InvalidTimeLockConfig(
                "max_amount must be greater than zero".to_string(),
            ));
        }

        if self.grace_period_secs == 0 {
            return Err(AuditGuardError::InvalidTimeLockConfig(
                "grace_period_secs must be greater than zero".to_string(),
            ));
        }

        if self.max_pending_requests == 0 {
            return Err(AuditGuardError::InvalidTimeLockConfig(
                "max_pending_requests must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryOutflowRequest {
    pub request_id: String,
    pub treasury_id: String,
    pub beneficiary: String,
    pub amount: u64,
    pub created_at: u64,
    pub execute_after: u64,
    pub justification: String,
}

impl TreasuryOutflowRequest {
    fn validate(&self, config: &TreasuryOutflowTimeLockConfig) -> Result<(), AuditGuardError> {
        if self.request_id.trim().is_empty() {
            return Err(AuditGuardError::EmptyRequestId);
        }

        if self.treasury_id.trim().is_empty() {
            return Err(AuditGuardError::InvalidTreasuryId);
        }

        if self.beneficiary.trim().is_empty() {
            return Err(AuditGuardError::InvalidBeneficiary);
        }

        if self.amount == 0 {
            return Err(AuditGuardError::ZeroOutflowAmount);
        }

        if self.amount > config.max_amount {
            return Err(AuditGuardError::AmountExceedsLimit {
                amount: self.amount,
                max_amount: config.max_amount,
            });
        }

        if self.justification.trim().len() < 10 {
            return Err(AuditGuardError::JustificationTooShort);
        }

        if self.execute_after <= self.created_at {
            return Err(AuditGuardError::InvalidExecutionWindow);
        }

        let delay_secs = self.execute_after - self.created_at;
        if delay_secs < config.min_delay_secs {
            return Err(AuditGuardError::DelayBelowMinimum {
                delay_secs,
                min_delay_secs: config.min_delay_secs,
            });
        }

        if delay_secs > config.max_delay_secs {
            return Err(AuditGuardError::DelayAboveMaximum {
                delay_secs,
                max_delay_secs: config.max_delay_secs,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TreasuryOutflowStatus {
    Pending,
    Ready,
    Executed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledTreasuryOutflow {
    pub request: TreasuryOutflowRequest,
    pub status: TreasuryOutflowStatus,
    pub expires_at: u64,
    pub executed_at: Option<u64>,
    pub cancelled_at: Option<u64>,
    pub cancellation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeLockVerificationReport {
    pub checked_requests: usize,
    pub ready_requests: usize,
    pub expired_requests: usize,
}

#[derive(Debug, Error)]
pub enum AuditGuardError {
    #[error("API URL must not be empty")]
    EmptyApiUrl,
    #[error("invalid API URL: {0}")]
    InvalidApiUrl(String),
    #[error("failed to construct endpoint URL: {0}")]
    InvalidEndpoint(String),
    #[error("audit report policy name must not be empty")]
    EmptyPolicyName,
    #[error("audit report contains an empty violation entry")]
    EmptyViolationEntry,
    #[error("compliant audit report cannot contain violations")]
    CompliantReportHasViolations,
    #[error("non-compliant audit report must contain at least one violation")]
    NonCompliantReportMissingViolations,
    #[error("report id must not be empty")]
    EmptyReportId,
    #[error("request id must not be empty")]
    EmptyRequestId,
    #[error("treasury id must not be empty")]
    InvalidTreasuryId,
    #[error("beneficiary must not be empty")]
    InvalidBeneficiary,
    #[error("outflow amount must be greater than zero")]
    ZeroOutflowAmount,
    #[error("outflow amount {amount} exceeds configured maximum {max_amount}")]
    AmountExceedsLimit { amount: u64, max_amount: u64 },
    #[error("justification must be at least 10 non-whitespace characters")]
    JustificationTooShort,
    #[error("execute_after must be greater than created_at")]
    InvalidExecutionWindow,
    #[error("outflow delay {delay_secs}s is below the minimum {min_delay_secs}s")]
    DelayBelowMinimum {
        delay_secs: u64,
        min_delay_secs: u64,
    },
    #[error("outflow delay {delay_secs}s exceeds the maximum {max_delay_secs}s")]
    DelayAboveMaximum {
        delay_secs: u64,
        max_delay_secs: u64,
    },
    #[error("timelock configuration is invalid: {0}")]
    InvalidTimeLockConfig(String),
    #[error("request `{request_id}` already exists")]
    DuplicateRequestId { request_id: String },
    #[error("too many active timelock requests: limit is {limit}")]
    TooManyPendingRequests { limit: usize },
    #[error("request `{request_id}` was not found")]
    UnknownRequest { request_id: String },
    #[error("request `{request_id}` is still time-locked until {unlock_at}")]
    RequestStillLocked { request_id: String, unlock_at: u64 },
    #[error("request `{request_id}` expired at {expired_at}")]
    RequestExpired { request_id: String, expired_at: u64 },
    #[error("request `{request_id}` was already executed at {executed_at}")]
    RequestAlreadyExecuted {
        request_id: String,
        executed_at: u64,
    },
    #[error("request `{request_id}` was already cancelled at {cancelled_at}")]
    RequestAlreadyCancelled {
        request_id: String,
        cancelled_at: u64,
    },
    #[error("cancellation reason must be at least 5 non-whitespace characters")]
    InvalidCancellationReason,
    #[error("timelock state integrity violation for `{request_id}`: {detail}")]
    StateIntegrityViolation { request_id: String, detail: String },
    #[error("request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("{operation} failed with HTTP {status}: {body}")]
    UnexpectedHttpStatus {
        operation: &'static str,
        status: StatusCode,
        body: String,
    },
}

pub struct AuditGuardClient {
    client: Client,
    api_url: Url,
}

pub struct SecureTreasuryOutflowTimeLock {
    config: TreasuryOutflowTimeLockConfig,
    requests: BTreeMap<String, ScheduledTreasuryOutflow>,
}

impl AuditGuardClient {
    /// Creates a new AuditGuardClient
    ///
    /// # Arguments
    ///
    /// * `api_url` - The base URL of the existing Audit-Guard API
    pub fn new(api_url: &str) -> Result<Self, AuditGuardError> {
        let api_url = api_url.trim();
        if api_url.is_empty() {
            return Err(AuditGuardError::EmptyApiUrl);
        }

        let parsed_url = Url::parse(api_url)
            .map_err(|error| AuditGuardError::InvalidApiUrl(error.to_string()))?;

        Ok(Self {
            client: Client::new(),
            api_url: parsed_url,
        })
    }

    fn build_endpoint(&self, path: &str) -> Result<Url, AuditGuardError> {
        self.api_url
            .join(path)
            .map_err(|error| AuditGuardError::InvalidEndpoint(error.to_string()))
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), AuditGuardError> {
        report.validate()?;
        let endpoint = self.build_endpoint("api/v1/audit/reports")?;

        let response = self
            .client
            .post(endpoint)
            .json(report)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(AuditGuardError::UnexpectedHttpStatus {
                operation: "submit audit report",
                status,
                body,
            })
        }
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, AuditGuardError> {
        let id = id.trim();
        if id.is_empty() {
            return Err(AuditGuardError::EmptyReportId);
        }

        let endpoint = self.build_endpoint(&format!("api/v1/audit/reports/{id}"))?;

        let response = self.client.get(endpoint)
            .send()
            .await?

            ;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuditGuardError::UnexpectedHttpStatus {
                operation: "fetch audit report",
                status,
                body,
            });
        }

        let report: AuditReport = response.json().await?;
        report.validate()?;

        Ok(report)
    }
}

impl SecureTreasuryOutflowTimeLock {
    pub fn new(config: TreasuryOutflowTimeLockConfig) -> Result<Self, AuditGuardError> {
        config.validate()?;
        Ok(Self {
            config,
            requests: BTreeMap::new(),
        })
    }

    pub fn schedule_outflow(
        &mut self,
        request: TreasuryOutflowRequest,
    ) -> Result<ScheduledTreasuryOutflow, AuditGuardError> {
        request.validate(&self.config)?;

        if self.requests.contains_key(&request.request_id) {
            return Err(AuditGuardError::DuplicateRequestId {
                request_id: request.request_id,
            });
        }

        if self.active_request_count() >= self.config.max_pending_requests {
            return Err(AuditGuardError::TooManyPendingRequests {
                limit: self.config.max_pending_requests,
            });
        }

        let scheduled = ScheduledTreasuryOutflow {
            expires_at: request.execute_after + self.config.grace_period_secs,
            request,
            status: TreasuryOutflowStatus::Pending,
            executed_at: None,
            cancelled_at: None,
            cancellation_reason: None,
        };

        self.requests.insert(
            scheduled.request.request_id.clone(),
            scheduled.clone(),
        );

        Ok(scheduled)
    }

    pub fn get_outflow(
        &self,
        request_id: &str,
    ) -> Result<&ScheduledTreasuryOutflow, AuditGuardError> {
        self.requests
            .get(request_id)
            .ok_or_else(|| AuditGuardError::UnknownRequest {
                request_id: request_id.to_string(),
            })
    }

    pub fn release_outflow(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> Result<ScheduledTreasuryOutflow, AuditGuardError> {
        let scheduled = self.get_mut_request(request_id)?;
        scheduled.apply_time_transition(now);

        match scheduled.status {
            TreasuryOutflowStatus::Pending => Err(AuditGuardError::RequestStillLocked {
                request_id: request_id.to_string(),
                unlock_at: scheduled.request.execute_after,
            }),
            TreasuryOutflowStatus::Ready => {
                scheduled.status = TreasuryOutflowStatus::Executed;
                scheduled.executed_at = Some(now);
                Ok(scheduled.clone())
            }
            TreasuryOutflowStatus::Executed => {
                Err(AuditGuardError::RequestAlreadyExecuted {
                    request_id: request_id.to_string(),
                    executed_at: scheduled.executed_at.unwrap_or(now),
                })
            }
            TreasuryOutflowStatus::Cancelled => {
                Err(AuditGuardError::RequestAlreadyCancelled {
                    request_id: request_id.to_string(),
                    cancelled_at: scheduled.cancelled_at.unwrap_or(now),
                })
            }
            TreasuryOutflowStatus::Expired => Err(AuditGuardError::RequestExpired {
                request_id: request_id.to_string(),
                expired_at: scheduled.expires_at,
            }),
        }
    }

    pub fn cancel_outflow(
        &mut self,
        request_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<ScheduledTreasuryOutflow, AuditGuardError> {
        if reason.trim().len() < 5 {
            return Err(AuditGuardError::InvalidCancellationReason);
        }

        let scheduled = self.get_mut_request(request_id)?;
        scheduled.apply_time_transition(now);

        match scheduled.status {
            TreasuryOutflowStatus::Executed => Err(AuditGuardError::RequestAlreadyExecuted {
                request_id: request_id.to_string(),
                executed_at: scheduled.executed_at.unwrap_or(now),
            }),
            TreasuryOutflowStatus::Cancelled => {
                Err(AuditGuardError::RequestAlreadyCancelled {
                    request_id: request_id.to_string(),
                    cancelled_at: scheduled.cancelled_at.unwrap_or(now),
                })
            }
            TreasuryOutflowStatus::Pending
            | TreasuryOutflowStatus::Ready
            | TreasuryOutflowStatus::Expired => {
                scheduled.status = TreasuryOutflowStatus::Cancelled;
                scheduled.cancelled_at = Some(now);
                scheduled.cancellation_reason = Some(reason.trim().to_string());
                Ok(scheduled.clone())
            }
        }
    }

    pub fn verify_state_integrity(
        &self,
        now: u64,
    ) -> Result<TimeLockVerificationReport, AuditGuardError> {
        let mut ready_requests = 0;
        let mut expired_requests = 0;

        for (request_id, scheduled) in &self.requests {
            scheduled.request.validate(&self.config)?;

            let expected_expiry = scheduled.request.execute_after + self.config.grace_period_secs;
            if scheduled.expires_at != expected_expiry {
                return Err(AuditGuardError::StateIntegrityViolation {
                    request_id: request_id.clone(),
                    detail: format!(
                        "expires_at {} does not match expected {}",
                        scheduled.expires_at, expected_expiry
                    ),
                });
            }

            match scheduled.status {
                TreasuryOutflowStatus::Pending => {
                    if scheduled.executed_at.is_some() || scheduled.cancelled_at.is_some() {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "pending request cannot have execution or cancellation timestamps"
                                .to_string(),
                        });
                    }

                    if now >= scheduled.request.execute_after {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "pending request should have transitioned out of pending state"
                                .to_string(),
                        });
                    }
                }
                TreasuryOutflowStatus::Ready => {
                    ready_requests += 1;
                    if scheduled.executed_at.is_some() || scheduled.cancelled_at.is_some() {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "ready request cannot have execution or cancellation timestamps"
                                .to_string(),
                        });
                    }

                    if now < scheduled.request.execute_after || now > scheduled.expires_at {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "ready request is outside the executable time window"
                                .to_string(),
                        });
                    }
                }
                TreasuryOutflowStatus::Executed => {
                    let executed_at = scheduled.executed_at.ok_or_else(|| {
                        AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "executed request is missing executed_at timestamp".to_string(),
                        }
                    })?;

                    if executed_at < scheduled.request.execute_after {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "request executed before unlock time".to_string(),
                        });
                    }

                    if scheduled.cancelled_at.is_some() || scheduled.cancellation_reason.is_some() {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "executed request cannot also be cancelled".to_string(),
                        });
                    }
                }
                TreasuryOutflowStatus::Cancelled => {
                    if scheduled.executed_at.is_some() {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "cancelled request cannot also be executed".to_string(),
                        });
                    }

                    if scheduled.cancelled_at.is_none()
                        || scheduled
                            .cancellation_reason
                            .as_ref()
                            .map(|reason| reason.trim().is_empty())
                            .unwrap_or(true)
                    {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "cancelled request must include timestamp and reason"
                                .to_string(),
                        });
                    }
                }
                TreasuryOutflowStatus::Expired => {
                    expired_requests += 1;
                    if scheduled.executed_at.is_some() || scheduled.cancelled_at.is_some() {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "expired request cannot have execution or cancellation timestamps"
                                .to_string(),
                        });
                    }

                    if now <= scheduled.expires_at {
                        return Err(AuditGuardError::StateIntegrityViolation {
                            request_id: request_id.clone(),
                            detail: "expired request has not yet reached its expiry boundary"
                                .to_string(),
                        });
                    }
                }
            }
        }

        Ok(TimeLockVerificationReport {
            checked_requests: self.requests.len(),
            ready_requests,
            expired_requests,
        })
    }

    fn active_request_count(&self) -> usize {
        self.requests
            .values()
            .filter(|scheduled| {
                !matches!(
                    scheduled.status,
                    TreasuryOutflowStatus::Executed | TreasuryOutflowStatus::Cancelled
                )
            })
            .count()
    }

    fn get_mut_request(
        &mut self,
        request_id: &str,
    ) -> Result<&mut ScheduledTreasuryOutflow, AuditGuardError> {
        self.requests
            .get_mut(request_id)
            .ok_or_else(|| AuditGuardError::UnknownRequest {
                request_id: request_id.to_string(),
            })
    }
}

impl ScheduledTreasuryOutflow {
    fn apply_time_transition(&mut self, now: u64) {
        if matches!(
            self.status,
            TreasuryOutflowStatus::Executed | TreasuryOutflowStatus::Cancelled
        ) {
            return;
        }

        self.status = if now > self.expires_at {
            TreasuryOutflowStatus::Expired
        } else if now >= self.request.execute_after {
            TreasuryOutflowStatus::Ready
        } else {
            TreasuryOutflowStatus::Pending
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn base_config() -> TreasuryOutflowTimeLockConfig {
        TreasuryOutflowTimeLockConfig {
            min_delay_secs: 60,
            max_delay_secs: 86_400,
            max_amount: 1_000_000,
            grace_period_secs: 300,
            max_pending_requests: 2,
        }
    }

    fn sample_request(request_id: &str, created_at: u64, execute_after: u64) -> TreasuryOutflowRequest {
        TreasuryOutflowRequest {
            request_id: request_id.to_string(),
            treasury_id: "treasury-main".to_string(),
            beneficiary: "GBENEFICIARY123".to_string(),
            amount: 500,
            created_at,
            execute_after,
            justification: "Monthly treasury rebalance".to_string(),
        }
    }

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
    fn audit_report_validation_rejects_inconsistent_state() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: true,
            violations: vec!["should not exist".to_string()],
        };

        assert!(matches!(
            report.validate(),
            Err(AuditGuardError::CompliantReportHasViolations)
        ));
    }

    #[test]
    fn audit_guard_client_rejects_invalid_api_url() {
        assert!(matches!(
            AuditGuardClient::new("   "),
            Err(AuditGuardError::EmptyApiUrl)
        ));
    }

    #[tokio::test]
    async fn submit_report_propagates_http_failure_details() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/audit/reports"))
            .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
            .mount(&server)
            .await;

        let client = AuditGuardClient::new(&server.uri()).expect("server URL should be valid");
        let report = AuditReport {
            policy_name: "timelock-check".to_string(),
            compliant: false,
            violations: vec!["delay mismatch".to_string()],
        };

        let error = client
            .submit_report(&report)
            .await
            .expect_err("HTTP failure should be propagated");

        match error {
            AuditGuardError::UnexpectedHttpStatus { status, body, .. } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert!(body.contains("service unavailable"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_report_rejects_invalid_payloads() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/audit/reports/report-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "policy_name": "timelock-check",
                    "compliant": false,
                    "violations": []
                })),
            )
            .mount(&server)
            .await;

        let client = AuditGuardClient::new(&server.uri()).expect("server URL should be valid");
        let error = client
            .get_report("report-1")
            .await
            .expect_err("invalid payload should fail validation");

        assert!(matches!(
            error,
            AuditGuardError::NonCompliantReportMissingViolations
        ));
    }

    #[test]
    fn timelock_rejects_short_delay_and_duplicate_ids() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");

        let too_early = sample_request("req-1", 100, 120);
        assert!(matches!(
            timelock.schedule_outflow(too_early),
            Err(AuditGuardError::DelayBelowMinimum { .. })
        ));

        let valid = sample_request("req-1", 100, 200);
        timelock
            .schedule_outflow(valid.clone())
            .expect("request should schedule");

        assert!(matches!(
            timelock.schedule_outflow(valid),
            Err(AuditGuardError::DuplicateRequestId { .. })
        ));
    }

    #[test]
    fn timelock_blocks_early_execution_and_executes_once_ready() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");
        timelock
            .schedule_outflow(sample_request("req-2", 100, 200))
            .expect("request should schedule");

        assert!(matches!(
            timelock.release_outflow("req-2", 150),
            Err(AuditGuardError::RequestStillLocked { .. })
        ));

        let executed = timelock
            .release_outflow("req-2", 220)
            .expect("request should execute once ready");
        assert_eq!(executed.status, TreasuryOutflowStatus::Executed);
        assert_eq!(executed.executed_at, Some(220));

        assert!(matches!(
            timelock.release_outflow("req-2", 221),
            Err(AuditGuardError::RequestAlreadyExecuted { .. })
        ));
    }

    #[test]
    fn timelock_expires_after_grace_period_and_allows_cancellation_cleanup() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");
        timelock
            .schedule_outflow(sample_request("req-3", 100, 200))
            .expect("request should schedule");

        assert!(matches!(
            timelock.release_outflow("req-3", 501),
            Err(AuditGuardError::RequestExpired { .. })
        ));

        let cancelled = timelock
            .cancel_outflow("req-3", "risk review", 502)
            .expect("expired request should still be cancellable for cleanup");
        assert_eq!(cancelled.status, TreasuryOutflowStatus::Cancelled);
        assert_eq!(cancelled.cancellation_reason.as_deref(), Some("risk review"));
    }

    #[test]
    fn timelock_enforces_pending_request_capacity() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");
        timelock
            .schedule_outflow(sample_request("req-4", 100, 200))
            .expect("first request should schedule");
        timelock
            .schedule_outflow(sample_request("req-5", 110, 210))
            .expect("second request should schedule");

        assert!(matches!(
            timelock.schedule_outflow(sample_request("req-6", 120, 220)),
            Err(AuditGuardError::TooManyPendingRequests { limit: 2 })
        ));
    }

    #[test]
    fn timelock_integrity_verification_detects_tampered_state() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");
        timelock
            .schedule_outflow(sample_request("req-7", 100, 200))
            .expect("request should schedule");

        let scheduled = timelock
            .requests
            .get_mut("req-7")
            .expect("request should exist for test mutation");
        scheduled.status = TreasuryOutflowStatus::Executed;
        scheduled.executed_at = Some(150);

        assert!(matches!(
            timelock.verify_state_integrity(220),
            Err(AuditGuardError::StateIntegrityViolation { .. })
        ));
    }

    #[test]
    fn timelock_integrity_verification_reports_ready_and_expired_counts() {
        let mut timelock =
            SecureTreasuryOutflowTimeLock::new(base_config()).expect("config should be valid");
        timelock
            .schedule_outflow(sample_request("req-8", 100, 400))
            .expect("request should schedule");
        timelock
            .schedule_outflow(sample_request("req-9", 110, 190))
            .expect("request should schedule");

        timelock
            .get_mut_request("req-8")
            .expect("request should exist")
            .apply_time_transition(500);
        timelock
            .get_mut_request("req-9")
            .expect("request should exist")
            .apply_time_transition(500);

        let report = timelock
            .verify_state_integrity(500)
            .expect("integrity report should succeed");
        assert_eq!(report.checked_requests, 2);
        assert_eq!(report.ready_requests, 1);
        assert_eq!(report.expired_requests, 1);
    }
}
