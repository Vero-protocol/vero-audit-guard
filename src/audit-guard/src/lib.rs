//! Vero Audit Guard observational write-path library.
//!
//! The guard records and forwards observations; it has no on-chain halt or
//! enforcement authority.

mod write_path;

pub use write_path::{AuditTrailClient, ConfirmedAuditRecord, WritePathError};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn confirmed_record_is_serializable() {
        let record = ConfirmedAuditRecord {
            record_id: "test-policy-1".into(),
            observed_at: "2026-07-19T00:00:00Z".into(),
            evidence_hash: "0".repeat(64),
            payload: json!({ "policy": "test", "confirmed": true }),
        };
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(encoded.contains("test-policy-1"));
    }
}
