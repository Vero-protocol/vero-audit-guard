// drift_validator.rs

use serde::{Deserialize, Serialize};
use crate::drift_error::DriftError;

/// Represents a single drift telemetry event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    /// Unique identifier for the drift event.
    pub id: String,
    /// ISO‑8601 timestamp of when the drift was observed.
    pub timestamp: String,
    /// Measured drift value (e.g., nonce delta, balance delta, etc.).
    pub drift_value: u64,
    /// Optional additional payload – kept generic for future extensions.
    pub payload: Option<serde_json::Value>,
}

impl DriftEvent {
    /// Basic sanity checks on the event fields.
    fn validate_structure(&self) -> Result<(), DriftError> {
        if self.id.trim().is_empty() {
            return Err(DriftError::MalformedPayload("event id is empty".into()));
        }
        if DateTime::parse_from_rfc3339(&self.timestamp).is_err() {
            return Err(DriftError::MalformedPayload("invalid timestamp".into()));
        }
        Ok(())
    }
}

// Use chrono for timestamp parsing – it is already a dependency in the workspace.
use chrono::{DateTime, FixedOffset};

/// Configurable threshold for drift validation.
/// In a real implementation this would be loaded from a policy file (e.g., OPA),
/// but for now we expose a simple constant to illustrate the flow.
pub const MAX_DRIFT_THRESHOLD: u64 = 100;

/// Core validation function that checks a drift event against the policy threshold.
/// Returns `Ok(())` when the event is within limits, otherwise a `DriftError`.
pub fn validate_drift(event: &DriftEvent) -> Result<(), DriftError> {
    // First ensure the payload is well‑formed.
    event.validate_structure()?;

    // Compare the measured drift against the allowed maximum.
    if event.drift_value > MAX_DRIFT_THRESHOLD {
        return Err(DriftError::ThresholdExceeded(event.drift_value));
    }

    // If needed, additional policy look‑ups could be performed here.
    // For now we assume the static threshold is sufficient.
    Ok(())
}
