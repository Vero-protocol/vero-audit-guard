/// Security Configuration Module
/// Provides standardized security protocols and configuration management
/// All configuration follows Rust safety standards with no unsafe code

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Security severity levels aligned with incident response procedures
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// P3 - Low severity (24 hour SLA)
    Low = 0,
    /// P2 - Medium severity (4 hour SLA)
    Medium = 1,
    /// P1 - High severity (1 hour SLA)
    High = 2,
    /// P0 - Critical severity (15 minute SLA)
    Critical = 3,
}

impl SecuritySeverity {
    /// Get the response SLA for this severity level
    pub fn response_sla(&self) -> Duration {
        match self {
            SecuritySeverity::Low => Duration::from_secs(24 * 60 * 60), // 24 hours
            SecuritySeverity::Medium => Duration::from_secs(4 * 60 * 60), // 4 hours
            SecuritySeverity::High => Duration::from_secs(60 * 60),      // 1 hour
            SecuritySeverity::Critical => Duration::from_secs(15 * 60),  // 15 minutes
        }
    }

    /// Parse severity from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" | "p3" => Some(SecuritySeverity::Low),
            "medium" | "p2" => Some(SecuritySeverity::Medium),
            "high" | "p1" => Some(SecuritySeverity::High),
            "critical" | "p0" => Some(SecuritySeverity::Critical),
            _ => None,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SecuritySeverity::Low => "LOW",
            SecuritySeverity::Medium => "MEDIUM",
            SecuritySeverity::High => "HIGH",
            SecuritySeverity::Critical => "CRITICAL",
        }
    }
}

/// Security configuration for audit-guard operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Minimum severity level to block CI/CD pipeline
    pub block_threshold: SecuritySeverity,
    /// Enable automatic incident response
    pub auto_incident_response: bool,
    /// Authorized addresses for relayer operations
    pub authorized_addresses: HashSet<String>,
    /// Maximum allowed nonce spike
    pub nonce_spike_threshold: u64,
    /// Maximum failed transactions before alert
    pub failed_tx_threshold: u64,
    /// Enable on-chain audit trail anchoring
    pub enable_chain_anchoring: bool,
    /// Enable policy as code enforcement
    pub enforce_policies: bool,
    /// Maximum allowed file modifications in a single PR
    pub max_pr_files: usize,
    /// Maximum diff size (additions + deletions) in a single PR
    pub max_pr_diff: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            block_threshold: SecuritySeverity::Critical,
            auto_incident_response: true,
            authorized_addresses: HashSet::new(),
            nonce_spike_threshold: 50,
            failed_tx_threshold: 10,
            enable_chain_anchoring: true,
            enforce_policies: true,
            max_pr_files: 20,
            max_pr_diff: 1000,
        }
    }
}

impl SecurityConfig {
    /// Create a new security configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict security configuration for production
    pub fn strict() -> Self {
        Self {
            block_threshold: SecuritySeverity::High,
            auto_incident_response: true,
            authorized_addresses: HashSet::new(),
            nonce_spike_threshold: 25,
            failed_tx_threshold: 5,
            enable_chain_anchoring: true,
            enforce_policies: true,
            max_pr_files: 10,
            max_pr_diff: 500,
        }
    }

    /// Create a permissive configuration for development
    pub fn permissive() -> Self {
        Self {
            block_threshold: SecuritySeverity::Critical,
            auto_incident_response: false,
            authorized_addresses: HashSet::new(),
            nonce_spike_threshold: 100,
            failed_tx_threshold: 20,
            enable_chain_anchoring: false,
            enforce_policies: false,
            max_pr_files: 50,
            max_pr_diff: 5000,
        }
    }

    /// Add an authorized address
    pub fn add_authorized_address(&mut self, address: String) -> bool {
        self.authorized_addresses.insert(address)
    }

    /// Remove an authorized address
    pub fn remove_authorized_address(&mut self, address: &str) -> bool {
        self.authorized_addresses.remove(address)
    }

    /// Check if an address is authorized
    pub fn is_authorized(&self, address: &str) -> bool {
        self.authorized_addresses.contains(address)
    }

    /// Validate the configuration for internal consistency
    pub fn validate(&self) -> Result<(), String> {
        if self.nonce_spike_threshold == 0 {
            return Err("nonce_spike_threshold must be greater than 0".to_string());
        }
        if self.failed_tx_threshold == 0 {
            return Err("failed_tx_threshold must be greater than 0".to_string());
        }
        if self.max_pr_files == 0 {
            return Err("max_pr_files must be greater than 0".to_string());
        }
        if self.max_pr_diff == 0 {
            return Err("max_pr_diff must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Security finding from static analysis or runtime monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique identifier for this finding
    pub id: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Category of the finding
    pub category: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Location in code (file:line or component name)
    pub location: Option<String>,
    /// Recommended remediation
    pub remediation: Option<String>,
}

impl SecurityFinding {
    /// Create a new security finding
    pub fn new(
        id: String,
        severity: SecuritySeverity,
        category: String,
        title: String,
        description: String,
    ) -> Self {
        Self {
            id,
            severity,
            category,
            title,
            description,
            location: None,
            remediation: None,
        }
    }

    /// Add location information
    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    /// Add remediation guidance
    pub fn with_remediation(mut self, remediation: String) -> Self {
        self.remediation = Some(remediation);
        self
    }

    /// Check if this finding should block CI/CD
    pub fn should_block(&self, config: &SecurityConfig) -> bool {
        self.severity >= config.block_threshold
    }
}

/// Security event for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Event type (e.g., "FINDING_DETECTED", "INCIDENT_TRIGGERED")
    pub event_type: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Event details
    pub details: String,
    /// Related findings
    pub findings: Vec<SecurityFinding>,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        timestamp: u64,
        event_type: String,
        severity: SecuritySeverity,
        details: String,
    ) -> Self {
        Self {
            timestamp,
            event_type,
            severity,
            details,
            findings: Vec::new(),
        }
    }

    /// Add a finding to this event
    pub fn add_finding(mut self, finding: SecurityFinding) -> Self {
        self.findings.push(finding);
        self
    }

    /// Get the highest severity among all findings
    pub fn max_severity(&self) -> SecuritySeverity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(self.severity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
    }

    #[test]
    fn test_security_severity_from_str() {
        assert_eq!(
            SecuritySeverity::from_str("low"),
            Some(SecuritySeverity::Low)
        );
        assert_eq!(
            SecuritySeverity::from_str("CRITICAL"),
            Some(SecuritySeverity::Critical)
        );
        assert_eq!(
            SecuritySeverity::from_str("p1"),
            Some(SecuritySeverity::High)
        );
        assert_eq!(SecuritySeverity::from_str("invalid"), None);
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert_eq!(config.block_threshold, SecuritySeverity::Critical);
        assert!(config.auto_incident_response);
        assert!(config.enforce_policies);
    }

    #[test]
    fn test_security_config_strict() {
        let config = SecurityConfig::strict();
        assert_eq!(config.block_threshold, SecuritySeverity::High);
        assert_eq!(config.nonce_spike_threshold, 25);
        assert_eq!(config.max_pr_files, 10);
    }

    #[test]
    fn test_security_config_validation() {
        let mut config = SecurityConfig::default();
        assert!(config.validate().is_ok());

        config.nonce_spike_threshold = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_authorized_addresses() {
        let mut config = SecurityConfig::new();
        assert!(!config.is_authorized("GABC123"));

        config.add_authorized_address("GABC123".to_string());
        assert!(config.is_authorized("GABC123"));

        config.remove_authorized_address("GABC123");
        assert!(!config.is_authorized("GABC123"));
    }

    #[test]
    fn test_security_finding_creation() {
        let finding = SecurityFinding::new(
            "SEC-001".to_string(),
            SecuritySeverity::High,
            "vulnerability".to_string(),
            "SQL Injection".to_string(),
            "Unsafe query construction".to_string(),
        )
        .with_location("src/db.rs:42".to_string())
        .with_remediation("Use parameterized queries".to_string());

        assert_eq!(finding.severity, SecuritySeverity::High);
        assert!(finding.location.is_some());
        assert!(finding.remediation.is_some());
    }

    #[test]
    fn test_finding_should_block() {
        let config = SecurityConfig::default(); // blocks on CRITICAL
        let critical = SecurityFinding::new(
            "001".to_string(),
            SecuritySeverity::Critical,
            "test".to_string(),
            "test".to_string(),
            "test".to_string(),
        );
        let high = SecurityFinding::new(
            "002".to_string(),
            SecuritySeverity::High,
            "test".to_string(),
            "test".to_string(),
            "test".to_string(),
        );

        assert!(critical.should_block(&config));
        assert!(!high.should_block(&config));
    }

    #[test]
    fn test_security_event_max_severity() {
        let event = SecurityEvent::new(
            1234567890,
            "SCAN_COMPLETE".to_string(),
            SecuritySeverity::Low,
            "Scan completed".to_string(),
        )
        .add_finding(SecurityFinding::new(
            "001".to_string(),
            SecuritySeverity::Medium,
            "test".to_string(),
            "test".to_string(),
            "test".to_string(),
        ))
        .add_finding(SecurityFinding::new(
            "002".to_string(),
            SecuritySeverity::High,
            "test".to_string(),
            "test".to_string(),
            "test".to_string(),
        ));

        assert_eq!(event.max_severity(), SecuritySeverity::High);
    }
}
