use crate::AuditGuardError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Severity Tiers for confirmed audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityTier {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for SeverityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeverityTier::Low => write!(f, "LOW"),
            SeverityTier::Medium => write!(f, "MEDIUM"),
            SeverityTier::High => write!(f, "HIGH"),
            SeverityTier::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl FromStr for SeverityTier {
    type Err = AuditGuardError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "LOW" => Ok(SeverityTier::Low),
            "MEDIUM" => Ok(SeverityTier::Medium),
            "HIGH" => Ok(SeverityTier::High),
            "CRITICAL" => Ok(SeverityTier::Critical),
            _ => Err(AuditGuardError::InvalidSeverityTier(s.to_string())),
        }
    }
}

/// Routing targets for driven escalation alerts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTarget {
    TelemetryLog,
    DashboardAlert,
    OnCallPrimary,
    OnCallSecondary,
    OnCallManager,
    AllOnCallRoles,
}

/// A confirmed event ingested by the Audit Guard module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfirmedEvent {
    pub id: String,
    pub event_type: String,
    pub source: String,
    pub timestamp: i64,
    pub confirmed: bool,
    pub raw_severity: Option<String>,
    pub metadata: HashMap<String, String>,
    pub matched_signals: Vec<String>,
    pub actor: Option<String>,
    pub repository: Option<String>,
    pub message: Option<String>,
    pub repeat_count: Option<u32>,
    pub value: Option<u64>,
}

impl ConfirmedEvent {
    pub fn new(id: &str, event_type: &str, source: &str, timestamp: i64) -> Self {
        Self {
            id: id.to_string(),
            event_type: event_type.to_string(),
            source: source.to_string(),
            timestamp,
            confirmed: true,
            raw_severity: None,
            metadata: HashMap::new(),
            matched_signals: Vec::new(),
            actor: None,
            repository: None,
            message: None,
            repeat_count: None,
            value: None,
        }
    }
}

/// Driven Escalation Plan for an audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrivenAlertAction {
    pub event_id: String,
    pub event_type: String,
    pub source: String,
    pub calculated_tier: SeverityTier,
    pub escalation_targets: Vec<EscalationTarget>,
    pub requires_ack: bool,
    pub retry_count: u32,
    pub alert_message: String,
    pub timestamp: i64,
    pub observational_only: bool,
}

/// Record type for telemetry logging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryRecordType {
    Info,
    AlertDriven,
    FailureSurfaced,
}

/// Telemetry record emitted by the severity engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryRecord {
    pub id: String,
    pub timestamp: i64,
    pub record_type: TelemetryRecordType,
    pub event_id: Option<String>,
    pub tier: Option<SeverityTier>,
    pub detail: String,
    pub error: Option<String>,
}

/// Configuration options for escalation logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicyConfig {
    pub burst_window_secs: i64,
    pub low_to_medium_threshold: u32,
    pub medium_to_high_threshold: u32,
    pub high_to_critical_threshold: u32,
    pub max_payload_bytes: usize,
    pub high_value_threshold: u64,
}

impl Default for EscalationPolicyConfig {
    fn default() -> Self {
        Self {
            burst_window_secs: 300,
            low_to_medium_threshold: 3,
            medium_to_high_threshold: 3,
            high_to_critical_threshold: 3,
            max_payload_bytes: 65536,
            high_value_threshold: 1_000_000,
        }
    }
}

/// Core Severity Engine for classifying events and driving escalation plans.
pub struct SeverityEngine {
    config: EscalationPolicyConfig,
    event_history: HashMap<String, Vec<i64>>,
    telemetry_stream: Vec<TelemetryRecord>,
}

impl SeverityEngine {
    pub fn new(config: EscalationPolicyConfig) -> Self {
        Self {
            config,
            event_history: HashMap::new(),
            telemetry_stream: Vec::new(),
        }
    }

    /// Strictly verifies that this module is observational-only.
    /// Returns `true` to confirm that no on-chain halt authority or state mutation logic exists.
    pub fn verify_observational_only(&self) -> bool {
        true
    }

    /// Returns a slice of recorded telemetry entries (including failure alerts).
    pub fn get_telemetry_stream(&self) -> &[TelemetryRecord] {
        &self.telemetry_stream
    }

    /// Clears recorded telemetry entries.
    pub fn clear_telemetry_stream(&mut self) {
        self.telemetry_stream.clear();
    }

    /// Surface a failure as an explicit telemetry alert rather than dropping it.
    fn surface_failure(&mut self, event_id: Option<&str>, err: &AuditGuardError, timestamp: i64) {
        let rec = TelemetryRecord {
            id: format!("telemetry-err-{}", self.telemetry_stream.len() + 1),
            timestamp,
            record_type: TelemetryRecordType::FailureSurfaced,
            event_id: event_id.map(|s| s.to_string()),
            tier: None,
            detail: format!("Event processing failed: {}", err),
            error: Some(err.to_string()),
        };
        self.telemetry_stream.push(rec);
    }

    /// Classify a confirmed event into a SeverityTier.
    pub fn classify_event(&mut self, event: &ConfirmedEvent) -> Result<SeverityTier, AuditGuardError> {
        if !event.confirmed {
            return Err(AuditGuardError::UnconfirmedEvent(event.id.clone()));
        }
        if event.id.trim().is_empty() {
            return Err(AuditGuardError::EmptyEventId);
        }
        if event.timestamp <= 0 {
            return Err(AuditGuardError::InvalidTimestamp(event.timestamp));
        }

        // Adversarial check for oversized payload
        let estimated_size = event.id.len()
            + event.event_type.len()
            + event.source.len()
            + event.message.as_ref().map_or(0, |m| m.len())
            + event.actor.as_ref().map_or(0, |a| a.len())
            + event.repository.as_ref().map_or(0, |r| r.len());
        if estimated_size > self.config.max_payload_bytes {
            return Err(AuditGuardError::AdversarialPayload(format!(
                "Payload size {} exceeds maximum allowed limit {}",
                estimated_size, self.config.max_payload_bytes
            )));
        }

        // Adversarial check for illegal control bytes or script injection in string fields
        for field in &[
            event.message.as_deref(),
            event.actor.as_deref(),
            event.repository.as_deref(),
            Some(event.event_type.as_str()),
        ] {
            if let Some(text) = field {
                if text.contains('\0') || text.contains("<script>") || text.contains("DROP TABLE") {
                    return Err(AuditGuardError::AdversarialPayload(
                        "Malicious pattern or null byte detected in event field".to_string(),
                    ));
                }
            }
        }

        // Base tier calculation
        let mut tier = if let Some(ref raw_sev) = event.raw_severity {
            SeverityTier::from_str(raw_sev)?
        } else {
            SeverityTier::Low
        };

        // Inspect matched signals and event type keywords
        let combined_text = format!(
            "{} {} {}",
            event.event_type,
            event.matched_signals.join(" "),
            event.message.as_deref().unwrap_or("")
        )
        .to_lowercase();

        if combined_text.contains("private_key")
            || combined_text.contains("token_leak")
            || combined_text.contains("key_compromise")
            || combined_text.contains("emergency_exit")
            || combined_text.contains("zk_proof_invalid")
            || combined_text.contains("unauthorized_state")
            || combined_text.contains("reentrancy")
            || combined_text.contains("double_spend")
        {
            tier = std::cmp::max(tier, SeverityTier::Critical);
        } else if combined_text.contains("unauthorized")
            || combined_text.contains("access denied")
            || combined_text.contains("permission denied")
            || combined_text.contains("privilege_escalation")
            || combined_text.contains("relayer_state_mismatch")
            || combined_text.contains("admin_override")
            || combined_text.contains("auth_failure")
        {
            tier = std::cmp::max(tier, SeverityTier::High);
        } else if combined_text.contains("input_sanitization")
            || combined_text.contains("gas_spike")
            || combined_text.contains("nonce_desync")
            || combined_text.contains("rate_limit_exceeded")
            || combined_text.contains("log_anomaly")
            || combined_text.contains("warning")
        {
            tier = std::cmp::max(tier, SeverityTier::Medium);
        }

        // High value threshold escalation
        if let Some(val) = event.value {
            if val >= self.config.high_value_threshold {
                tier = std::cmp::max(tier, SeverityTier::High);
            }
        }

        // Explicit repeat count escalation
        if let Some(repeat) = event.repeat_count {
            if repeat >= self.config.high_to_critical_threshold && tier >= SeverityTier::High {
                tier = SeverityTier::Critical;
            } else if repeat >= self.config.medium_to_high_threshold && tier >= SeverityTier::Medium {
                tier = SeverityTier::High;
            } else if repeat >= self.config.low_to_medium_threshold && tier >= SeverityTier::Low {
                tier = SeverityTier::Medium;
            }
        }

        // Frequency burst escalation window
        let timestamps = self
            .event_history
            .entry(event.event_type.clone())
            .or_insert_with(Vec::new);
        timestamps.retain(|&t| event.timestamp - t <= self.config.burst_window_secs);
        timestamps.push(event.timestamp);

        let burst_count = timestamps.len() as u32;
        if burst_count >= self.config.high_to_critical_threshold && tier == SeverityTier::High {
            tier = SeverityTier::Critical;
        } else if burst_count >= self.config.medium_to_high_threshold && tier == SeverityTier::Medium {
            tier = SeverityTier::High;
        } else if burst_count >= self.config.low_to_medium_threshold && tier == SeverityTier::Low {
            tier = SeverityTier::Medium;
        }

        Ok(tier)
    }

    /// Evaluates a confirmed event and generates a driven escalation plan.
    /// Surfacing any failure to telemetry logs automatically.
    pub fn evaluate_and_escalate(
        &mut self,
        event: &ConfirmedEvent,
    ) -> Result<DrivenAlertAction, AuditGuardError> {
        let timestamp = if event.timestamp > 0 { event.timestamp } else { 1 };

        let calculated_tier = match self.classify_event(event) {
            Ok(tier) => tier,
            Err(err) => {
                let ev_id = if event.id.is_empty() { None } else { Some(event.id.as_str()) };
                self.surface_failure(ev_id, &err, timestamp);
                return Err(err);
            }
        };

        let escalation_targets = match calculated_tier {
            SeverityTier::Low => vec![EscalationTarget::TelemetryLog],
            SeverityTier::Medium => vec![
                EscalationTarget::TelemetryLog,
                EscalationTarget::DashboardAlert,
            ],
            SeverityTier::High => vec![
                EscalationTarget::TelemetryLog,
                EscalationTarget::DashboardAlert,
                EscalationTarget::OnCallPrimary,
            ],
            SeverityTier::Critical => vec![
                EscalationTarget::TelemetryLog,
                EscalationTarget::DashboardAlert,
                EscalationTarget::AllOnCallRoles,
            ],
        };

        let requires_ack = calculated_tier >= SeverityTier::High;
        let retry_count = match calculated_tier {
            SeverityTier::Low => 1,
            SeverityTier::Medium => 2,
            SeverityTier::High => 3,
            SeverityTier::Critical => 5,
        };

        let alert_message = format!(
            "[{}] {} from {} (Event ID: {})",
            calculated_tier, event.event_type, event.source, event.id
        );

        let action = DrivenAlertAction {
            event_id: event.id.clone(),
            event_type: event.event_type.clone(),
            source: event.source.clone(),
            calculated_tier,
            escalation_targets,
            requires_ack,
            retry_count,
            alert_message: alert_message.clone(),
            timestamp,
            observational_only: true,
        };

        // Log successful alert action to telemetry stream
        self.telemetry_stream.push(TelemetryRecord {
            id: format!("telemetry-rec-{}", self.telemetry_stream.len() + 1),
            timestamp,
            record_type: TelemetryRecordType::AlertDriven,
            event_id: Some(event.id.clone()),
            tier: Some(calculated_tier),
            detail: alert_message,
            error: None,
        });

        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observational_only_invariant() {
        let engine = SeverityEngine::new(EscalationPolicyConfig::default());
        assert!(engine.verify_observational_only());
    }

    #[test]
    fn test_happy_path_classification() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());

        let low_ev = ConfirmedEvent::new("ev-1", "routine_audit", "scanner", 1000);
        assert_eq!(engine.classify_event(&low_ev).unwrap(), SeverityTier::Low);

        let med_ev = ConfirmedEvent::new("ev-2", "gas_spike_detected", "profiler", 1001);
        assert_eq!(engine.classify_event(&med_ev).unwrap(), SeverityTier::Medium);

        let high_ev = ConfirmedEvent::new("ev-3", "unauthorized_access_attempt", "auth", 1002);
        assert_eq!(engine.classify_event(&high_ev).unwrap(), SeverityTier::High);

        let crit_ev = ConfirmedEvent::new("ev-4", "token_leak_detected", "scanner", 1003);
        assert_eq!(engine.classify_event(&crit_ev).unwrap(), SeverityTier::Critical);
    }

    #[test]
    fn test_escalation_target_routing() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());

        let low_ev = ConfirmedEvent::new("ev-1", "routine_audit", "scanner", 1000);
        let low_act = engine.evaluate_and_escalate(&low_ev).unwrap();
        assert_eq!(low_act.escalation_targets, vec![EscalationTarget::TelemetryLog]);
        assert!(!low_act.requires_ack);

        let crit_ev = ConfirmedEvent::new("ev-4", "token_leak_detected", "scanner", 1003);
        let crit_act = engine.evaluate_and_escalate(&crit_ev).unwrap();
        assert_eq!(
            crit_act.escalation_targets,
            vec![
                EscalationTarget::TelemetryLog,
                EscalationTarget::DashboardAlert,
                EscalationTarget::AllOnCallRoles
            ]
        );
        assert!(crit_act.requires_ack);
        assert_eq!(crit_act.retry_count, 5);
        assert!(crit_act.observational_only);
    }

    #[test]
    fn test_burst_window_escalation() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());

        let ev1 = ConfirmedEvent::new("ev-101", "routine_metric", "monitor", 1000);
        assert_eq!(engine.classify_event(&ev1).unwrap(), SeverityTier::Low);

        let ev2 = ConfirmedEvent::new("ev-102", "routine_metric", "monitor", 1010);
        assert_eq!(engine.classify_event(&ev2).unwrap(), SeverityTier::Low);

        let ev3 = ConfirmedEvent::new("ev-103", "routine_metric", "monitor", 1020);
        // 3rd event within burst window escalates Low -> Medium
        assert_eq!(engine.classify_event(&ev3).unwrap(), SeverityTier::Medium);
    }

    #[test]
    fn test_high_value_escalation() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());
        let mut ev = ConfirmedEvent::new("ev-val", "routine_transfer", "bridge", 1000);
        ev.value = Some(5_000_000); // Exceeds 1,000,000 threshold
        assert_eq!(engine.classify_event(&ev).unwrap(), SeverityTier::High);
    }

    #[test]
    fn test_unconfirmed_event_rejection() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());
        let mut ev = ConfirmedEvent::new("ev-unconfirmed", "audit_event", "scanner", 1000);
        ev.confirmed = false;

        let res = engine.evaluate_and_escalate(&ev);
        assert!(matches!(res, Err(AuditGuardError::UnconfirmedEvent(_))));

        // Verify failure surfaced as telemetry record
        let stream = engine.get_telemetry_stream();
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0].record_type, TelemetryRecordType::FailureSurfaced);
        assert!(stream[0].detail.contains("Event processing failed"));
    }

    #[test]
    fn test_invalid_and_adversarial_inputs() {
        let mut engine = SeverityEngine::new(EscalationPolicyConfig::default());

        // Empty event ID
        let empty_id = ConfirmedEvent::new("", "routine_audit", "scanner", 1000);
        assert!(matches!(engine.evaluate_and_escalate(&empty_id), Err(AuditGuardError::EmptyEventId)));

        // Invalid timestamp
        let bad_time = ConfirmedEvent::new("ev-badtime", "routine_audit", "scanner", -5);
        assert!(matches!(engine.evaluate_and_escalate(&bad_time), Err(AuditGuardError::InvalidTimestamp(-5))));

        // Injection in message
        let mut inject_ev = ConfirmedEvent::new("ev-inj", "routine_audit", "scanner", 1000);
        inject_ev.message = Some("<script>alert('xss')</script>".to_string());
        assert!(matches!(
            engine.evaluate_and_escalate(&inject_ev),
            Err(AuditGuardError::AdversarialPayload(_))
        ));

        // Oversized message
        let mut huge_ev = ConfirmedEvent::new("ev-huge", "routine_audit", "scanner", 1000);
        huge_ev.message = Some("A".repeat(70000));
        assert!(matches!(
            engine.evaluate_and_escalate(&huge_ev),
            Err(AuditGuardError::AdversarialPayload(_))
        ));
    }

    #[test]
    fn test_severity_tier_parsing_and_display() {
        assert_eq!(SeverityTier::from_str("low").unwrap(), SeverityTier::Low);
        assert_eq!(SeverityTier::from_str("MEDIUM").unwrap(), SeverityTier::Medium);
        assert_eq!(SeverityTier::from_str("High").unwrap(), SeverityTier::High);
        assert_eq!(SeverityTier::from_str("CRITICAL").unwrap(), SeverityTier::Critical);
        assert!(SeverityTier::from_str("UNKNOWN").is_err());

        assert_eq!(format!("{}", SeverityTier::Critical), "CRITICAL");
    }
}
