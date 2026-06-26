//! Defensive guards — reentrancy protection.
//!
//! Reentrancy guards prevent a function from being called again while it is
//! already executing. This is particularly important for functions that
//! perform external calls or complex state transitions.

use soroban_sdk::{contracterror, panic_with_error, symbol_short, Env, Symbol};

const KEY_GUARD: Symbol = symbol_short!("RE_GUARD");

#[contracterror]
#[derive(Copy, Clone)]
pub enum GuardError {
    ReentrancyDetected = 100,
}

/// Sets the reentrancy lock. Panics if already locked.
pub fn enter_reentrancy_guard(env: &Env) {
    if env.storage().temporary().has(&KEY_GUARD) {
        panic_with_error!(env, GuardError::ReentrancyDetected);
    }
    env.storage().temporary().set(&KEY_GUARD, &true);
}

/// Clears the reentrancy lock.
pub fn exit_reentrancy_guard(env: &Env) {
    env.storage().temporary().remove(&KEY_GUARD);
}

/// RAII guard for reentrancy protection.
pub struct ReentrancyGuard<'a> {
    env: &'a Env,
}

impl<'a> ReentrancyGuard<'a> {
    pub fn enter(env: &'a Env) -> Self {
        enter_reentrancy_guard(env);
        ReentrancyGuard { env }
    }
}

impl<'a> Drop for ReentrancyGuard<'a> {
    fn drop(&mut self) {
        exit_reentrancy_guard(self.env);
    }
}

/// Macro to wrap a function body with reentrancy protection.
#[macro_export]
macro_rules! non_reentrant {
    ($env:expr) => {
        let _guard = $crate::guards::ReentrancyGuard::enter($env);
    };
}
