#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_percentage;

fuzz_target!(|data: (u64, u64)| {
    let (value, percentage) = data;
    
    // Test safe_percentage never panics
    let result = safe_percentage(value, percentage);
    
    // Verify correctness
    if let Some(pct_value) = result {
        // Result should be <= value when percentage <= 100
        if percentage <= 100 {
            assert!(pct_value <= value);
        }
        
        // If value is 0, result should be 0
        if value == 0 {
            assert_eq!(pct_value, 0);
        }
        
        // Manual calculation check
        if let Some(multiplied) = value.checked_mul(percentage) {
            let expected = multiplied / 100;
            assert_eq!(pct_value, expected);
        }
    } else {
        // If None, overflow must have occurred in multiplication
        assert!(value.checked_mul(percentage).is_none());
    }
});
