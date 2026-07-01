/// Integration tests for the math module
/// These tests verify edge cases and complex scenarios

use audit_guard::math::*;

#[test]
fn test_overflow_scenarios() {
    // Test u64::MAX + 1
    assert_eq!(safe_add(u64::MAX, 1u64), None);
    
    // Test u32::MAX * 2
    assert_eq!(safe_mul(u32::MAX, 2u32), None);
    
    // Test i64::MIN - 1
    assert_eq!(safe_sub(i64::MIN, 1i64), None);
    
    // Test u64::MAX * u64::MAX
    assert_eq!(safe_mul(u64::MAX, u64::MAX), None);
}

#[test]
fn test_underflow_scenarios() {
    // Test 0 - 1 for unsigned
    assert_eq!(safe_sub(0u32, 1u32), None);
    
    // Test i64::MIN - 1
    assert_eq!(safe_sub(i64::MIN, 1i64), None);
}

#[test]
fn test_division_edge_cases() {
    // Test division by zero
    assert_eq!(safe_div(100u32, 0u32), None);
    
    // Test i64::MIN / -1 (special overflow case)
    assert_eq!(safe_div(i64::MIN, -1i64), None);
    
    // Test normal division
    assert_eq!(safe_div(100u32, 10u32), Some(10u32));
}

#[test]
fn test_power_edge_cases() {
    // Test 0^0 (conventionally 1)
    assert_eq!(safe_pow(0u32, 0), Some(1u32));
    
    // Test 1^n (always 1)
    assert_eq!(safe_pow(1u32, 1000), Some(1u32));
    
    // Test 2^31 (fits in u32)
    assert_eq!(safe_pow(2u32, 31), Some(2147483648u32));
    
    // Test 2^32 (overflow)
    assert_eq!(safe_pow(2u32, 32), None);
}

#[test]
fn test_percentage_calculations() {
    // Test 10% of 1000
    assert_eq!(safe_percentage(1000u32, 10u32), Some(100u32));
    
    // Test 100% of 1000
    assert_eq!(safe_percentage(1000u32, 100u32), Some(1000u32));
    
    // Test 0% of 1000
    assert_eq!(safe_percentage(1000u32, 0u32), Some(0u32));
    
    // Test overflow scenario
    assert_eq!(safe_percentage(u64::MAX, 200u64), None);
}

#[test]
fn test_scaling_operations() {
    // Test 100 * 3/2 = 150
    assert_eq!(safe_scale(100u32, 3u32, 2u32), Some(150u32));
    
    // Test scaling by 1/1 (identity)
    assert_eq!(safe_scale(100u32, 1u32, 1u32), Some(100u32));
    
    // Test division by zero
    assert_eq!(safe_scale(100u32, 3u32, 0u32), None);
    
    // Test overflow
    assert_eq!(safe_scale(u64::MAX, 2u64, 1u64), None);
}

#[test]
fn test_average_calculations() {
    // Test average of equal values
    assert_eq!(safe_average(100u32, 100u32), Some(100u32));
    
    // Test average of 0 and 100
    assert_eq!(safe_average(0u32, 100u32), Some(50u32));
    
    // Test average with reversed order
    assert_eq!(safe_average(100u32, 0u32), Some(50u32));
    
    // Test average of MAX values
    assert_eq!(safe_average(u64::MAX, u64::MAX), Some(u64::MAX));
    
    // Test average of boundary values
    let result = safe_average(u64::MAX - 1, u64::MAX);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), u64::MAX - 1);
}

#[test]
fn test_abs_diff() {
    // Test normal difference
    assert_eq!(safe_abs_diff(100u32, 50u32), Some(50u32));
    
    // Test reversed order
    assert_eq!(safe_abs_diff(50u32, 100u32), Some(50u32));
    
    // Test zero difference
    assert_eq!(safe_abs_diff(100u32, 100u32), Some(0u32));
    
    // Test maximum difference
    assert_eq!(safe_abs_diff(u32::MAX, 0u32), Some(u32::MAX));
}

#[test]
fn test_mul_add_operations() {
    // Test (5 * 10) + 3 = 53
    assert_eq!(safe_mul_add(5u32, 10u32, 3u32), Some(53u32));
    
    // Test overflow in multiplication
    assert_eq!(safe_mul_add(u64::MAX, 2u64, 0u64), None);
    
    // Test overflow in addition
    assert_eq!(safe_mul_add(u64::MAX, 1u64, 1u64), None);
    
    // Test (0 * n) + c = c
    assert_eq!(safe_mul_add(0u32, 1000u32, 42u32), Some(42u32));
}

#[test]
fn test_modulo_operations() {
    // Test 10 % 3 = 1
    assert_eq!(safe_mod(10u32, 3u32), Some(1u32));
    
    // Test modulo by zero
    assert_eq!(safe_mod(10u32, 0u32), None);
    
    // Test modulo when dividend < divisor
    assert_eq!(safe_mod(5u32, 10u32), Some(5u32));
    
    // Test modulo by 1 (always 0)
    assert_eq!(safe_mod(100u32, 1u32), Some(0u32));
}

#[test]
fn test_compound_interest_calculations() {
    // Test 1000 at 5% for 0 periods = 1000
    assert_eq!(safe_compound_interest(1000, 500, 0), Some(1000));
    
    // Test 1000 at 0% for 10 periods = 1000
    assert_eq!(safe_compound_interest(1000, 0, 10), Some(1000));
    
    // Test 0 principal = 0
    assert_eq!(safe_compound_interest(0, 500, 10), Some(0));
    
    // Test realistic scenario: 1000 at 5% (500 bp) for 2 periods
    // 1000 * 1.05 * 1.05 = 1102.5 (integer division gives 1102)
    assert_eq!(safe_compound_interest(1000, 500, 2), Some(1102));
    
    // Test overflow scenario
    assert_eq!(safe_compound_interest(u64::MAX, 10000, 2), None);
}

#[test]
fn test_chained_operations() {
    // Test: (100 + 50) * 2 / 3
    let result = safe_add(100u32, 50u32)
        .and_then(|sum| safe_mul(sum, 2u32))
        .and_then(|product| safe_div(product, 3u32));
    assert_eq!(result, Some(100u32));
    
    // Test: average(100, 200) + 50
    let result = safe_average(100u32, 200u32)
        .and_then(|avg| safe_add(avg, 50u32));
    assert_eq!(result, Some(200u32));
    
    // Test: scale then percentage
    let result = safe_scale(1000u32, 3u32, 2u32)
        .and_then(|scaled| safe_percentage(scaled, 10u32));
    assert_eq!(result, Some(150u32));
}

#[test]
fn test_boundary_values() {
    // Test with u8::MAX
    assert_eq!(safe_add(u8::MAX, 0u8), Some(u8::MAX));
    assert_eq!(safe_add(u8::MAX, 1u8), None);
    
    // Test with u16::MAX
    assert_eq!(safe_mul(u16::MAX, 1u16), Some(u16::MAX));
    assert_eq!(safe_mul(u16::MAX, 2u16), None);
    
    // Test with i8::MIN
    assert_eq!(safe_sub(i8::MIN, 0i8), Some(i8::MIN));
    assert_eq!(safe_sub(i8::MIN, 1i8), None);
    
    // Test with i8::MAX
    assert_eq!(safe_add(i8::MAX, 0i8), Some(i8::MAX));
    assert_eq!(safe_add(i8::MAX, 1i8), None);
}

#[test]
fn test_type_generics() {
    // Verify operations work across different integer types
    
    // u8
    assert_eq!(safe_add(100u8, 50u8), Some(150u8));
    
    // u16
    assert_eq!(safe_mul(100u16, 2u16), Some(200u16));
    
    // u32
    assert_eq!(safe_div(1000u32, 10u32), Some(100u32));
    
    // u64
    assert_eq!(safe_sub(1000u64, 500u64), Some(500u64));
    
    // i32
    assert_eq!(safe_add(-100i32, 50i32), Some(-50i32));
    
    // i64
    assert_eq!(safe_mul(-10i64, 5i64), Some(-50i64));
}

#[test]
fn test_zero_identity() {
    // Addition identity
    assert_eq!(safe_add(100u32, 0u32), Some(100u32));
    assert_eq!(safe_add(0u32, 100u32), Some(100u32));
    
    // Multiplication by zero
    assert_eq!(safe_mul(100u32, 0u32), Some(0u32));
    assert_eq!(safe_mul(0u32, 100u32), Some(0u32));
    
    // Division of zero
    assert_eq!(safe_div(0u32, 100u32), Some(0u32));
}

#[test]
fn test_commutativity() {
    // Addition is commutative
    assert_eq!(safe_add(50u32, 100u32), safe_add(100u32, 50u32));
    
    // Multiplication is commutative
    assert_eq!(safe_mul(5u32, 20u32), safe_mul(20u32, 5u32));
}

#[test]
fn test_realistic_defi_scenarios() {
    // Scenario 1: Calculate 0.5% trading fee on 1,000,000 tokens
    let amount = 1_000_000u64;
    let fee_bp = 50u64; // 0.5% = 50 basis points
    let fee = safe_scale(amount, fee_bp, 10_000u64);
    assert_eq!(fee, Some(5_000u64));
    
    // Scenario 2: Calculate proportional share
    // User has 500 tokens out of 10,000 total, pool has 1,000,000 value
    let user_tokens = 500u64;
    let total_tokens = 10_000u64;
    let pool_value = 1_000_000u64;
    let user_share = safe_scale(pool_value, user_tokens, total_tokens);
    assert_eq!(user_share, Some(50_000u64));
    
    // Scenario 3: Calculate APY with compound interest
    // 10,000 principal at 12% APY (1200 bp) for 1 year (12 periods)
    let principal = 10_000u64;
    let monthly_rate_bp = 100u64; // ~1% per month
    let periods = 12u32;
    let final_amount = safe_compound_interest(principal, monthly_rate_bp, periods);
    assert!(final_amount.is_some());
    assert!(final_amount.unwrap() > principal);
}
