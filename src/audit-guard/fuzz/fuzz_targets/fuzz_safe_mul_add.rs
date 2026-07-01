#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_mul_add;

fuzz_target!(|data: (u64, u64, u64)| {
    let (a, b, c) = data;
    
    // Test safe_mul_add never panics
    let result = safe_mul_add(a, b, c);
    
    // Verify correctness
    if let Some(mul_add_result) = result {
        // Manual calculation check
        if let Some(product) = a.checked_mul(b) {
            if let Some(expected) = product.checked_add(c) {
                assert_eq!(mul_add_result, expected);
            }
        }
        
        // If a or b is 0, result should equal c
        if a == 0 || b == 0 {
            assert_eq!(mul_add_result, c);
        }
    } else {
        // If None, overflow must have occurred
        let product = a.checked_mul(b);
        assert!(product.is_none() || product.unwrap().checked_add(c).is_none());
    }
});
