#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_scale;

fuzz_target!(|data: (u64, u64, u64)| {
    let (value, numerator, denominator) = data;
    
    // Test safe_scale never panics
    let result = safe_scale(value, numerator, denominator);
    
    // Verify correctness
    if let Some(scaled) = result {
        // Division by zero should never succeed
        assert_ne!(denominator, 0);
        
        // If value or numerator is 0, result should be 0
        if value == 0 || numerator == 0 {
            assert_eq!(scaled, 0);
        }
        
        // If numerator equals denominator, result should equal value
        if numerator == denominator {
            assert_eq!(scaled, value);
        }
        
        // Manual calculation check
        if let Some(multiplied) = value.checked_mul(numerator) {
            let expected = multiplied / denominator;
            assert_eq!(scaled, expected);
        }
    } else {
        // If None, either denominator is 0 or overflow occurred
        assert!(denominator == 0 || value.checked_mul(numerator).is_none());
    }
});
