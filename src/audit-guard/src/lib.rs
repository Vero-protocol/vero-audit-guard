use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub policy_name: String,
    pub compliant: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeTransferResult {
    pub amount: u128,
    pub fee: u128,
    pub recipient_amount: u128,
    pub sender_balance_after: u128,
    pub fee_collector: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FeeOnTransferError {
    #[error("fee basis points must be between 0 and 10000")]
    InvalidFeeBps,
    #[error("fee collector must not be empty")]
    InvalidFeeCollector,
    #[error("transfer amount must be greater than zero")]
    InvalidAmount,
    #[error("sender balance is insufficient for the transfer")]
    InsufficientBalance,
    #[error("fee calculation overflowed")]
    ArithmeticOverflow,
}

pub struct ProtocolFeeOnTransfer {
    fee_bps: u16,
    fee_collector: String,
}

impl ProtocolFeeOnTransfer {
    pub fn new(fee_bps: u16, fee_collector: &str) -> Result<Self, FeeOnTransferError> {
        if fee_bps > 10_000 {
            return Err(FeeOnTransferError::InvalidFeeBps);
        }
        let fee_collector = fee_collector.trim();
        if fee_collector.is_empty() {
            return Err(FeeOnTransferError::InvalidFeeCollector);
        }

        Ok(Self {
            fee_bps,
            fee_collector: fee_collector.to_string(),
        })
    }

    pub fn calculate(
        &self,
        amount: u128,
        sender_balance: u128,
    ) -> Result<FeeTransferResult, FeeOnTransferError> {
        if amount == 0 {
            return Err(FeeOnTransferError::InvalidAmount);
        }
        if amount > sender_balance {
            return Err(FeeOnTransferError::InsufficientBalance);
        }

        let fee = amount
            .checked_mul(self.fee_bps as u128)
            .ok_or(FeeOnTransferError::ArithmeticOverflow)?
            / 10_000;

        Ok(FeeTransferResult {
            amount,
            fee,
            recipient_amount: amount - fee,
            sender_balance_after: sender_balance - amount,
            fee_collector: self.fee_collector.clone(),
        })
    }
}

pub struct AuditGuardClient {
    client: Client,
    api_url: String,
}

impl AuditGuardClient {
    /// Creates a new AuditGuardClient
    ///
    /// # Arguments
    ///
    /// * `api_url` - The base URL of the existing Audit-Guard API
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::new(),
            api_url: api_url.to_string(),
        }
    }

    /// Submits an audit report to the API
    /// This adheres to Rust safety standards by avoiding raw pointers,
    /// using safe abstractions, and properly propagating errors.
    pub async fn submit_report(&self, report: &AuditReport) -> Result<(), Box<dyn StdError>> {
        let endpoint = format!("{}/api/v1/audit/reports", self.api_url);

        let response = self.client.post(&endpoint).json(report).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to submit report. Status: {}", response.status()).into())
        }
    }

    /// Fetches a specific audit report
    pub async fn get_report(&self, id: &str) -> Result<AuditReport, Box<dyn StdError>> {
        let endpoint = format!("{}/api/v1/audit/reports/{}", self.api_url, id);

        let report: AuditReport = self.client.get(&endpoint).send().await?.json().await?;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_report_creation() {
        let report = AuditReport {
            policy_name: "test-policy".to_string(),
            compliant: true,
            violations: vec![],
        };
        assert_eq!(report.policy_name, "test-policy");
        assert!(report.compliant);
    }

    #[test]
    fn fee_transfer_preserves_amount_conservation() {
        let processor = ProtocolFeeOnTransfer::new(250, "treasury").unwrap();
        let result = processor.calculate(100_000, 250_000).unwrap();

        assert_eq!(result.fee, 2_500);
        assert_eq!(result.recipient_amount + result.fee, result.amount);
        assert_eq!(result.sender_balance_after, 150_000);
        assert_eq!(result.fee_collector, "treasury");
    }

    #[test]
    fn fee_transfer_rejects_invalid_state() {
        assert!(matches!(
            ProtocolFeeOnTransfer::new(10_001, "treasury"),
            Err(FeeOnTransferError::InvalidFeeBps)
        ));
        assert!(matches!(
            ProtocolFeeOnTransfer::new(250, " "),
            Err(FeeOnTransferError::InvalidFeeCollector)
        ));

        let processor = ProtocolFeeOnTransfer::new(250, "treasury").unwrap();
        assert_eq!(
            processor.calculate(0, 100),
            Err(FeeOnTransferError::InvalidAmount)
        );
        assert_eq!(
            processor.calculate(101, 100),
            Err(FeeOnTransferError::InsufficientBalance)
        );
    }

    #[test]
    fn fee_transfer_uses_zero_fee_without_rounding_amounts() {
        let processor = ProtocolFeeOnTransfer::new(0, "treasury").unwrap();
        let result = processor.calculate(1, 1).unwrap();

        assert_eq!(result.fee, 0);
        assert_eq!(result.recipient_amount, 1);
        assert_eq!(result.sender_balance_after, 0);
    }

    #[test]
    fn fee_transfer_rejects_arithmetic_overflow() {
        let processor = ProtocolFeeOnTransfer::new(10_000, "treasury").unwrap();
        assert_eq!(
            processor.calculate(u128::MAX, u128::MAX),
            Err(FeeOnTransferError::ArithmeticOverflow)
        );
    }
}
