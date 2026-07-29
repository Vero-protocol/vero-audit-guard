// drift_error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DriftError {
    #[error("Drift exceeds configured threshold: {0}")]
    ThresholdExceeded(u64),

    #[error("Malformed drift payload: {0}")]
    MalformedPayload(String),

    #[error("Failed to load policy configuration: {0}")]
    PolicyLookupFailed(String),
}
