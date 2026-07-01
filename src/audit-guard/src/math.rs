/// Math module with Soroban-compatible safe arithmetic operations
/// All operations are designed to prevent overflow, underflow, and division by zero
use std::ops::{Add, Sub, Mul, Div};

/// Safe addition that checks for overflow
/// Returns None if overflow would occur
pub fn safe_add<T>(a: T, b: T) -> Option<T>
where
    T: Add<Output = T> + PartialOrd + Copy + CheckedAdd,
{
    a.checked_add(b)
}

/// Safe subtraction that checks for underflow
/// Returns None if underflow would occur
pub fn safe_sub<T>(a: T, b: T) -> Option<T>
where
    T: Sub<Output = T> + PartialOrd + Copy + CheckedSub,
{
    a.checked_sub(b)
}

/// Safe multiplication that checks for overflow
/// Returns None if overflow would occur
pub fn safe_mul<T>(a: T, b: T) -> Option<T>
where
    T: Mul<Output = T> + PartialOrd + Copy + CheckedMul,
{
    a.checked_mul(b)
}

/// Safe division that checks for division by zero
/// Returns None if divisor is zero or overflow would occur
pub fn safe_div<T>(a: T, b: T) -> Option<T>
where
    T: Div<Output = T> + PartialOrd + Copy + CheckedDiv + Zero,
{
    if b.is_zero() {
        return None;
    }
    a.checked_div(b)
}

/// Safe modulo operation
/// Returns None if divisor is zero
pub fn safe_mod<T>(a: T, b: T) -> Option<T>
where
    T: Copy + CheckedRem + Zero,
{
    if b.is_zero() {
        return None;
    }
    a.checked_rem(b)
}

/// Safe exponentiation using repeated multiplication
/// Returns None if overflow would occur
pub fn safe_pow<T>(base: T, exp: u32) -> Option<T>
where
    T: Copy + CheckedMul + From<u8>,
{
    base.checked_pow(exp)
}

/// Compute percentage with overflow protection
/// Returns (value * percentage) / 100
pub fn safe_percentage<T>(value: T, percentage: T) -> Option<T>
where
    T: Copy + CheckedMul + CheckedDiv + From<u8>,
{
    let multiplied = value.checked_mul(percentage)?;
    multiplied.checked_div(T::from(100))
}

/// Scale a value by a ratio (numerator/denominator)
/// Returns (value * numerator) / denominator
pub fn safe_scale<T>(value: T, numerator: T, denominator: T) -> Option<T>
where
    T: Copy + CheckedMul + CheckedDiv + Zero,
{
    if denominator.is_zero() {
        return None;
    }
    let multiplied = value.checked_mul(numerator)?;
    multiplied.checked_div(denominator)
}

/// Calculate average of two numbers without overflow
/// Uses the formula: a + (b - a) / 2
pub fn safe_average<T>(a: T, b: T) -> Option<T>
where
    T: Copy + PartialOrd + CheckedSub + CheckedDiv + CheckedAdd + From<u8>,
{
    if a > b {
        let diff = a.checked_sub(b)?;
        let half_diff = diff.checked_div(T::from(2))?;
        b.checked_add(half_diff)
    } else {
        let diff = b.checked_sub(a)?;
        let half_diff = diff.checked_div(T::from(2))?;
        a.checked_add(half_diff)
    }
}

/// Compute absolute difference between two numbers
pub fn safe_abs_diff<T>(a: T, b: T) -> Option<T>
where
    T: Copy + PartialOrd + CheckedSub,
{
    if a >= b {
        a.checked_sub(b)
    } else {
        b.checked_sub(a)
    }
}

/// Multiply and add in one operation: (a * b) + c
/// Useful for fixed-point arithmetic
pub fn safe_mul_add<T>(a: T, b: T, c: T) -> Option<T>
where
    T: Copy + CheckedMul + CheckedAdd,
{
    let product = a.checked_mul(b)?;
    product.checked_add(c)
}

/// Compute compound interest: principal * (1 + rate)^periods
/// Rate should be provided as basis points (e.g., 500 = 5%)
pub fn safe_compound_interest(principal: u64, rate_bp: u64, periods: u32) -> Option<u64> {
    let base_bp = 10000u64;
    let rate_factor = base_bp.checked_add(rate_bp)?;
    
    let mut result = principal;
    for _ in 0..periods {
        result = safe_scale(result, rate_factor, base_bp)?;
    }
    Some(result)
}

// Trait definitions for checked arithmetic operations
pub trait CheckedAdd: Sized {
    fn checked_add(self, other: Self) -> Option<Self>;
}

pub trait CheckedSub: Sized {
    fn checked_sub(self, other: Self) -> Option<Self>;
}

pub trait CheckedMul: Sized {
    fn checked_mul(self, other: Self) -> Option<Self>;
}

pub trait CheckedDiv: Sized {
    fn checked_div(self, other: Self) -> Option<Self>;
}

pub trait CheckedRem: Sized {
    fn checked_rem(self, other: Self) -> Option<Self>;
}

pub trait CheckedPow: Sized {
    fn checked_pow(self, exp: u32) -> Option<Self>;
}

pub trait Zero {
    fn is_zero(&self) -> bool;
}

// Implement traits for common integer types
macro_rules! impl_checked_ops {
    ($($t:ty)*) => ($(
        impl CheckedAdd for $t {
            fn checked_add(self, other: Self) -> Option<Self> {
                <$t>::checked_add(self, other)
            }
        }

        impl CheckedSub for $t {
            fn checked_sub(self, other: Self) -> Option<Self> {
                <$t>::checked_sub(self, other)
            }
        }

        impl CheckedMul for $t {
            fn checked_mul(self, other: Self) -> Option<Self> {
                <$t>::checked_mul(self, other)
            }
        }

        impl CheckedDiv for $t {
            fn checked_div(self, other: Self) -> Option<Self> {
                <$t>::checked_div(self, other)
            }
        }

        impl CheckedRem for $t {
            fn checked_rem(self, other: Self) -> Option<Self> {
                <$t>::checked_rem(self, other)
            }
        }

        impl CheckedPow for $t {
            fn checked_pow(self, exp: u32) -> Option<Self> {
                <$t>::checked_pow(self, exp)
            }
        }

        impl Zero for $t {
            fn is_zero(&self) -> bool {
                *self == 0
            }
        }
    )*)
}

impl_checked_ops! { i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_add() {
        assert_eq!(safe_add(5u32, 10u32), Some(15u32));
        assert_eq!(safe_add(u32::MAX, 1u32), None);
        assert_eq!(safe_add(i32::MAX, 1i32), None);
    }

    #[test]
    fn test_safe_sub() {
        assert_eq!(safe_sub(10u32, 5u32), Some(5u32));
        assert_eq!(safe_sub(0u32, 1u32), None);
        assert_eq!(safe_sub(i32::MIN, 1i32), None);
    }

    #[test]
    fn test_safe_mul() {
        assert_eq!(safe_mul(5u32, 10u32), Some(50u32));
        assert_eq!(safe_mul(u32::MAX, 2u32), None);
        assert_eq!(safe_mul(i32::MAX, 2i32), None);
    }

    #[test]
    fn test_safe_div() {
        assert_eq!(safe_div(10u32, 2u32), Some(5u32));
        assert_eq!(safe_div(10u32, 0u32), None);
        assert_eq!(safe_div(i32::MIN, -1i32), None);
    }

    #[test]
    fn test_safe_mod() {
        assert_eq!(safe_mod(10u32, 3u32), Some(1u32));
        assert_eq!(safe_mod(10u32, 0u32), None);
    }

    #[test]
    fn test_safe_pow() {
        assert_eq!(safe_pow(2u32, 3), Some(8u32));
        assert_eq!(safe_pow(2u32, 31), Some(2147483648u32));
        assert_eq!(safe_pow(2u32, 32), None);
    }

    #[test]
    fn test_safe_percentage() {
        assert_eq!(safe_percentage(1000u32, 10u32), Some(100u32));
        assert_eq!(safe_percentage(u32::MAX, 200u32), None);
    }

    #[test]
    fn test_safe_scale() {
        assert_eq!(safe_scale(100u32, 3u32, 2u32), Some(150u32));
        assert_eq!(safe_scale(100u32, 3u32, 0u32), None);
        assert_eq!(safe_scale(u32::MAX, 2u32, 1u32), None);
    }

    #[test]
    fn test_safe_average() {
        assert_eq!(safe_average(10u32, 20u32), Some(15u32));
        assert_eq!(safe_average(20u32, 10u32), Some(15u32));
        assert_eq!(safe_average(u32::MAX, u32::MAX), Some(u32::MAX));
    }

    #[test]
    fn test_safe_abs_diff() {
        assert_eq!(safe_abs_diff(10u32, 5u32), Some(5u32));
        assert_eq!(safe_abs_diff(5u32, 10u32), Some(5u32));
        assert_eq!(safe_abs_diff(0u32, 0u32), Some(0u32));
    }

    #[test]
    fn test_safe_mul_add() {
        assert_eq!(safe_mul_add(5u32, 10u32, 3u32), Some(53u32));
        assert_eq!(safe_mul_add(u32::MAX, 2u32, 1u32), None);
    }

    #[test]
    fn test_safe_compound_interest() {
        // 1000 principal with 5% rate (500 bp) for 2 periods
        // 1000 * 1.05 * 1.05 = 1102.5 (integer division gives 1102)
        assert_eq!(safe_compound_interest(1000, 500, 2), Some(1102));
        assert_eq!(safe_compound_interest(u64::MAX, 10000, 2), None);
    }
}
