pub mod error;
pub mod health;
pub mod server;

pub use error::HealthError;
pub use health::{is_ready, set_readiness};
pub use server::start_health_server;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_toggle() {
        // By default it should be ready
        assert!(is_ready());

        // Toggle to degraded
        set_readiness(false);
        assert!(!is_ready());

        // Toggle back to ready
        set_readiness(true);
        assert!(is_ready());
    }

    #[test]
    fn test_error_formatting() {
        let err = HealthError::ConfigError("missing port".to_string());
        assert_eq!(
            format!("{}", err),
            "Invalid health configuration: missing port"
        );
    }
}
