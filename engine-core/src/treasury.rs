use soroban_sdk::{contract, contractimpl, contracttype, panic_with_error, Address, Env, Map};
use crate::types::TreasuryError;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: u64,
    pub balances: Map<Address, i128>,
    pub timestamp: u64,
}

#[contract]
pub struct Treasury;

#[contractimpl]
impl Treasury {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, TreasuryError::InvalidBalance);
        }
    }

    pub fn take_snapshot(env: Env, snapshot_id: u64) -> u64 {
        let timestamp = env.ledger().timestamp();
        
        let snapshot = Snapshot {
            id: snapshot_id,
            balances: Map::new(&env),
            timestamp,
        };

        env.storage().persistent().set(&snapshot_id, &snapshot);
        snapshot_id
    }
}
