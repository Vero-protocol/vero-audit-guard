use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error as DeriveError;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerSnapshot {
    pub state: CircuitBreakerState,
    pub consecutive_failures: u32,
    pub last_reason: Option<String>,
}

#[derive(Debug, DeriveError, PartialEq, Eq)]
pub enum CircuitBreakerError {
    #[error("failure threshold must be greater than zero")]
    InvalidFailureThreshold,
    #[error("reset timeout must be greater than zero")]
    InvalidResetTimeout,
    #[error("circuit breaker reason must not be empty")]
    InvalidReason,
    #[error("protocol circuit is open; retry after {retry_after_ms}ms")]
    Open { retry_after_ms: u64 },
    #[error("protocol circuit is testing recovery")]
    ProbeInProgress,
    #[error("circuit breaker state is unavailable")]
    StateUnavailable,
}

struct CircuitBreakerInner {
    state: CircuitBreakerState,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    last_reason: Option<String>,
    probe_in_flight: bool,
}

pub struct ProtocolCircuitBreaker {
    failure_threshold: u32,
    reset_timeout: Duration,
    inner: Mutex<CircuitBreakerInner>,
}

pub type SharedProtocolCircuitBreaker = Arc<ProtocolCircuitBreaker>;

impl ProtocolCircuitBreaker {
    pub fn new(
        failure_threshold: u32,
        reset_timeout: Duration,
    ) -> Result<Self, CircuitBreakerError> {
        if failure_threshold == 0 {
            return Err(CircuitBreakerError::InvalidFailureThreshold);
        }
        if reset_timeout.is_zero() {
            return Err(CircuitBreakerError::InvalidResetTimeout);
        }

        Ok(Self {
            failure_threshold,
            reset_timeout,
            inner: Mutex::new(CircuitBreakerInner {
                state: CircuitBreakerState::Closed,
                consecutive_failures: 0,
                opened_at: None,
                last_reason: None,
                probe_in_flight: false,
            }),
        })
    }

    pub fn shared(
        failure_threshold: u32,
        reset_timeout: Duration,
    ) -> Result<SharedProtocolCircuitBreaker, CircuitBreakerError> {
        Ok(Arc::new(Self::new(failure_threshold, reset_timeout)?))
    }

    pub fn allow_request(&self) -> Result<(), CircuitBreakerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        if inner.state == CircuitBreakerState::Open {
            let elapsed = inner
                .opened_at
                .map(|opened| opened.elapsed())
                .unwrap_or_default();
            if elapsed < self.reset_timeout {
                return Err(CircuitBreakerError::Open {
                    retry_after_ms: (self.reset_timeout - elapsed).as_millis() as u64,
                });
            }
            inner.state = CircuitBreakerState::HalfOpen;
            inner.probe_in_flight = false;
        }

        if inner.state == CircuitBreakerState::HalfOpen {
            if inner.probe_in_flight {
                return Err(CircuitBreakerError::ProbeInProgress);
            }
            inner.probe_in_flight = true;
        }
        Ok(())
    }

    pub fn record_success(&self) -> Result<(), CircuitBreakerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        inner.state = CircuitBreakerState::Closed;
        inner.consecutive_failures = 0;
        inner.opened_at = None;
        inner.last_reason = None;
        inner.probe_in_flight = false;
        Ok(())
    }

    pub fn record_failure(&self, reason: &str) -> Result<(), CircuitBreakerError> {
        let reason = valid_reason(reason)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
        inner.last_reason = Some(reason);
        inner.probe_in_flight = false;
        if inner.state == CircuitBreakerState::HalfOpen
            || inner.consecutive_failures >= self.failure_threshold
        {
            inner.state = CircuitBreakerState::Open;
            inner.opened_at = Some(Instant::now());
        }
        Ok(())
    }

    pub fn trip(&self, reason: &str) -> Result<(), CircuitBreakerError> {
        let reason = valid_reason(reason)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        inner.state = CircuitBreakerState::Open;
        inner.consecutive_failures = self.failure_threshold;
        inner.opened_at = Some(Instant::now());
        inner.last_reason = Some(reason);
        inner.probe_in_flight = false;
        Ok(())
    }

    pub fn reset(&self) -> Result<(), CircuitBreakerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        inner.state = CircuitBreakerState::Closed;
        inner.consecutive_failures = 0;
        inner.opened_at = None;
        inner.last_reason = None;
        inner.probe_in_flight = false;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<CircuitBreakerSnapshot, CircuitBreakerError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| CircuitBreakerError::StateUnavailable)?;
        Ok(CircuitBreakerSnapshot {
            state: inner.state,
            consecutive_failures: inner.consecutive_failures,
            last_reason: inner.last_reason.clone(),
        })
    }
}

fn valid_reason(reason: &str) -> Result<String, CircuitBreakerError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(CircuitBreakerError::InvalidReason);
    }
    Ok(reason.to_string())
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
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        }
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);

        let response = self.client.post(&endpoint).json(report).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to submit report. Status: {}", response.status()).into())
        }
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, Box<dyn Error>> {
        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);

        let report: AuditReport = self.client.get(&endpoint).send().await?.json().await?;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
    fn circuit_opens_after_repeated_failures() {
        let breaker = ProtocolCircuitBreaker::new(2, Duration::from_secs(30)).unwrap();

        breaker.record_failure("first failure").unwrap();
        assert_eq!(
            breaker.snapshot().unwrap().state,
            CircuitBreakerState::Closed
        );
        breaker.record_failure("second failure").unwrap();

        assert_eq!(breaker.snapshot().unwrap().state, CircuitBreakerState::Open);
        assert!(matches!(
            breaker.allow_request(),
            Err(CircuitBreakerError::Open { .. })
        ));
    }

    #[test]
    fn half_open_allows_one_probe_and_recovers_on_success() {
        let breaker = ProtocolCircuitBreaker::new(1, Duration::from_millis(1)).unwrap();
        breaker.trip("manual stop").unwrap();
        std::thread::sleep(Duration::from_millis(2));

        breaker.allow_request().unwrap();
        assert_eq!(
            breaker.allow_request(),
            Err(CircuitBreakerError::ProbeInProgress)
        );
        breaker.record_success().unwrap();
        assert_eq!(
            breaker.snapshot().unwrap().state,
            CircuitBreakerState::Closed
        );
    }

    #[test]
    fn invalid_breaker_input_is_rejected() {
        assert!(matches!(
            ProtocolCircuitBreaker::new(0, Duration::from_secs(1)),
            Err(CircuitBreakerError::InvalidFailureThreshold)
        ));
        let breaker = ProtocolCircuitBreaker::new(1, Duration::from_secs(1)).unwrap();
        assert!(matches!(
            breaker.trip(" "),
            Err(CircuitBreakerError::InvalidReason)
        ));
    }
}
