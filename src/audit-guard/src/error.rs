use thiserror::Error;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("Failed to export metrics: {0}")]
    ExportError(String),

    #[error("Failed to bind metrics server to address: {0}")]
    ServerError(#[from] std::io::Error),

    #[error("Invalid telemetry input: {0}")]
    InvalidInput(String),

    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
}
