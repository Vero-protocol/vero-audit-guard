#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::*;

/// Comprehensive fuzzing target that tests combinations of operations
/// This helps discover edge cases in chained arithmetic operations
fuzz_target!(|data: (u32, u32, u32, u32)| {
    let (a, b, c, d) = data;
    
    // Test various operation combinations
    // These should never panic, regardless of input
    
    // Test: (a + b) * c
    if let Some(sum) = safe_add(a, b) {
        let _ = safe_mul(sum, c);
    }
    
    // Test: (a * b) / c
    if let Some(product) = safe_mul(a, b) {
        let _ = safe_div(product, c);
    }
    
    // Test: ((a + b) - c) + d
    if let Some(sum) = safe_add(a, b) {
        if let Some(diff) = safe_sub(sum, c) {
            let _ = safe_add(diff, d);
        }
    }
    
    // Test: (a * b) % c
    if let Some(product) = safe_mul(a, b) {
        let _ = safe_mod(product, c);
    }
    
    // Test: scale with intermediate operations
    if let Some(avg) = safe_average(a, b) {
        let _ = safe_scale(avg, c, d);
    }
    
    // Test: percentage of sum
    if let Some(sum) = safe_add(a, b) {
        let _ = safe_percentage(sum, c);
    }
    
    // Test: power then scale
    if let Some(power) = safe_pow(a, b % 10) {  // Limit exponent
        let _ = safe_scale(power, c, d);
    }
    
    // Test: mul_add chains
    if let Some(first) = safe_mul_add(a, b, c) {
        let _ = safe_mul_add(first, d, a);
    }
    
    // Test: abs_diff and average
    if let Some(diff) = safe_abs_diff(a, b) {
        let _ = safe_average(diff, c);
    }
    
    // Test: complex compound operation
    // (a + b) * c / d with safe operations
    let result = safe_add(a, b)
        .and_then(|sum| safe_mul(sum, c))
        .and_then(|product| safe_div(product, d));
    
    // Verify the result is consistent
    if let Some(final_value) = result {
        // Should be able to recreate this manually
        if b <= u32::MAX - a {
            let sum = a + b;
            if let Some(product) = sum.checked_mul(c) {
                if d != 0 {
                    if let Some(expected) = product.checked_div(d) {
                        assert_eq!(final_value, expected);
                    }
                }
            }
        }
    }
});
