use crate::AuditGuardError;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
pub struct DriftEvent {
    pub detector_id: String,
    pub drift: i64,
    pub description: Option<String>,
    pub timestamp_ms: u64,
    pub source: Option<String>,
}

impl DriftEvent {
    pub fn validate(&self) -> Result<(), AuditGuardError> {
        if self.detector_id.trim().is_empty() {
            return Err(AuditGuardError::InvalidDriftPayload {
                reason: "detector_id is empty".to_string(),
            });
        }
        if self.timestamp_ms == 0 {
            return Err(AuditGuardError::InvalidDriftPayload {
                reason: "timestamp_ms must be positive".to_string(),
            });
        }
        Ok(())
    }
}

/// Returns a sink compatible with `TelemetryQueue::graceful_shutdown` that
/// accepts telemetry events and handles ones originating from
/// `"anomaly-detector"` by parsing them as `DriftEvent` and delegating to
/// the provided handler.
///
/// The returned sink maps any parsing/validation/handler errors into a
/// `String` so it can be used directly by `graceful_shutdown`.
pub fn make_drift_sink<F>(mut handler: F) -> impl FnMut(crate::telemetry_queue::TelemetryEvent) -> Result<(), String>
where
    F: FnMut(DriftEvent) -> Result<(), AuditGuardError>,
{
    move |event: crate::telemetry_queue::TelemetryEvent| {
        // Only process events from anomaly-detector
        if event.source != "anomaly-detector" {
            return Ok(());
        }

        // Parse payload as JSON into DriftEvent
        let parsed: DriftEvent = serde_json::from_str(&event.payload)
            .map_err(|e| format!("invalid drift payload: {}", e))?;

        parsed
            .validate()
            .map_err(|e| format!("drift validation failed: {}", e))?;

        handler(parsed).map_err(|e| format!("handler error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry_queue::{TelemetryEvent, TelemetryQueue, TelemetryQueueError};
    use std::time::Duration;

    #[test]
    fn drift_event_validate_rejects_empty_detector() {
        let d = DriftEvent {
            detector_id: "".to_string(),
            drift: 5,
            description: None,
            timestamp_ms: 1,
            source: None,
        };
        assert!(matches!(d.validate(), Err(AuditGuardError::InvalidDriftPayload{..})));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_handles_valid_drift_event() {
        let queue = TelemetryQueue::new();
        let payload = serde_json::json!({
            "detector_id": "det-1",
            "drift": 42,
            "description": "state drift detected",
            "timestamp_ms": 1620000000000u64
        })
        .to_string();

        queue.enqueue(TelemetryEvent::new("anomaly-detector", payload)).unwrap();

        let sink = make_drift_sink(|d: DriftEvent| {
            assert_eq!(d.detector_id, "det-1");
            Ok(())
        });

        let drained = queue
            .graceful_shutdown(sink, Duration::from_secs(1))
            .await
            .expect("drain should succeed");

        assert_eq!(drained, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_returns_sink_error_on_invalid_json() {
        let queue = TelemetryQueue::new();
        queue
            .enqueue(TelemetryEvent::new("anomaly-detector", "not-a-json".to_string()))
            .unwrap();

        let sink = make_drift_sink(|_d: DriftEvent| Ok(()));
        let result = queue
            .graceful_shutdown(sink, Duration::from_secs(1))
            .await;

        assert!(matches!(result, Err(TelemetryQueueError::SinkError(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_reports_validation_failure() {
        let queue = TelemetryQueue::new();
        let payload = serde_json::json!({
            "detector_id": "det-2",
            "drift": 1,
            "description": "",
            "timestamp_ms": 0
        })
        .to_string();

        queue.enqueue(TelemetryEvent::new("anomaly-detector", payload)).unwrap();

        let sink = make_drift_sink(|_d: DriftEvent| Ok(()));
        let result = queue
            .graceful_shutdown(sink, Duration::from_secs(1))
            .await;

        assert!(matches!(result, Err(TelemetryQueueError::SinkError(_))));
    }
}
