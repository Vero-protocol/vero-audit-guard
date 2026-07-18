use lazy_static::lazy_static;
use std::sync::atomic::{AtomicBool, Ordering};

lazy_static! {
    /// Global readiness state. True means fully healthy (200 OK), False means degraded (503 Service Unavailable).
    pub static ref IS_READY: AtomicBool = AtomicBool::new(true);
}

/// Set the global readiness state.
pub fn set_readiness(ready: bool) {
    IS_READY.store(ready, Ordering::SeqCst);
}

/// Get the current readiness state.
pub fn is_ready() -> bool {
    IS_READY.load(Ordering::SeqCst)
}
