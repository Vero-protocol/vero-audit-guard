// drift_validator_test.rs

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(drift: u64, id: &str) -> DriftEvent {
        DriftEvent {
            id: id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            drift_value: drift,
            payload: None,
        }
    }

    #[test]
    fn test_valid_drift() {
        let event = make_event(50, "event1");
        assert!(validate_drift(&event).is_ok());
    }

    #[test]
    fn test_exceeds_threshold() {
        let event = make_event(150, "event2");
        match validate_drift(&event) {
            Err(DriftError::ThresholdExceeded(val)) => assert_eq!(val, 150),
            _ => panic!("Expected ThresholdExceeded error"),
        }
    }

    #[test]
    fn test_malformed_id() {
        let mut event = make_event(10, "");
        event.id = "".to_string();
        match validate_drift(&event) {
            Err(DriftError::MalformedPayload(msg)) => assert!(msg.contains("event id")),
            _ => panic!("Expected MalformedPayload error for empty id"),
        }
    }

    #[test]
    fn test_invalid_timestamp() {
        let mut event = make_event(10, "event3");
        event.timestamp = "invalid-timestamp".to_string();
        match validate_drift(&event) {
            Err(DriftError::MalformedPayload(msg)) => assert!(msg.contains("timestamp")),
            _ => panic!("Expected MalformedPayload error for invalid timestamp"),
        }
    }
}
