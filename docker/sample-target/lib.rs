//! Fixture Soroban-style module used by local Docker Compose so scanner-engine
//! has a clean target when `vero-core-contracts` is not mounted.

pub fn guarded_add(left: i64, right: i64) -> Option<i64> {
    left.checked_add(right)
}

pub fn guarded_transfer(amount: i64, available: i64) -> Result<i64, &'static str> {
    if amount < 0 {
        return Err("amount must be non-negative");
    }
    available.checked_sub(amount).ok_or("insufficient balance")
}
