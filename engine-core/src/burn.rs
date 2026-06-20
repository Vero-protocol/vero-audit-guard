use soroban_sdk::{contract, contractimpl, panic_with_error, Address, Env};
use crate::types::BurnError;

#[contract]
pub struct BurnContract;

#[contractimpl]
impl BurnContract {
    pub fn execute_burn(env: Env, _to: Address, amount: i128) {
        if amount <= 0 {
            panic_with_error!(&env, BurnError::ZeroAddress);
        }
    }
}
