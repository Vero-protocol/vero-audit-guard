use soroban_sdk::{contracttype, Address, BytesN, Map, Symbol, Val};

/// Canonical state snapshot committed to a ZK audit cycle.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateCommitment {
    pub sequence: u64,
    pub state_hash: BytesN<32>,
    pub ledger: u32,
    pub author: Address,
}

/// Proposal lifecycle states, stored as u32 bitmask-friendly variants.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProposalState {
    Pending = 0,
    Approved = 1,
    Executed = 2,
    Expired = 3,
    Cancelled = 4,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BreakerState {
    Closed = 0,
    Open = 1,
}

/// What action triggered a treasury snapshot.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TriggerKind {
    Deposit = 0,
    Withdrawal = 1,
    ProposalExecuted = 2,
    GovernanceUpdate = 3,
    Manual = 4,
    BurnSafe = 5,
    RecoveryExecuted = 6,
    Other = 7,
}

/// Compact treasury snapshot for audit history.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasurySnapshot {
    pub id: u64,
    pub total_balance: i128,
    pub account_count: u32,
    pub ledger: u32,
    pub timestamp_unix: u64,
    pub state_hash: BytesN<32>,
    pub trigger: TriggerKind,
    pub context: Map<Symbol, Val>,
}

/// Compact governance proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub action_hash: BytesN<32>,
    pub proposer: Address,
    pub approved_by: soroban_sdk::Vec<Address>,
    pub state: ProposalState,
}
