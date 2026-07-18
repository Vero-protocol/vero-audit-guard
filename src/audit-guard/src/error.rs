use thiserror::Error;

#[derive(Error, Debug)]
pub enum HealthError {
    #[error("Failed to bind health server to address: {0}")]
    ServerError(#[from] std::io::Error),

    #[error("Invalid health configuration: {0}")]
    ConfigError(String),
}
