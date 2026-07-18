pub mod error;
pub mod metrics_server;
pub mod telemetry;

pub use error::TelemetryError;
pub use metrics_server::start_metrics_server;
pub use telemetry::{
    gather_metrics, init_telemetry, CONFIRMATION_RATE, QUEUE_DEPTH, RELOAD_STATUS, WRITE_LATENCY_MS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_initialization() {
        let _ = init_telemetry();

        // Verify metric updates
        QUEUE_DEPTH.set(10);
        assert_eq!(QUEUE_DEPTH.get(), 10);

        CONFIRMATION_RATE.inc_by(5);
        assert_eq!(CONFIRMATION_RATE.get(), 5);

        WRITE_LATENCY_MS.set(12.5);
        assert_eq!(WRITE_LATENCY_MS.get(), 12.5);

        RELOAD_STATUS.set(1);
        assert_eq!(RELOAD_STATUS.get(), 1);
    }

    #[test]
    fn test_metrics_export() {
        let _ = init_telemetry();
        QUEUE_DEPTH.set(42);
        let output = gather_metrics().expect("Failed to gather metrics");
        assert!(output.contains("queue_depth 42"));
    }

    #[test]
    fn test_adversarial_input_or_error_propagation() {
        let err = TelemetryError::InvalidInput("bad data".to_string());
        assert_eq!(format!("{}", err), "Invalid telemetry input: bad data");
    }
}
