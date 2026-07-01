#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_pow;

fuzz_target!(|data: (u32, u32)| {
    let (base, exp) = data;
    
    // Test safe_pow never panics
    let result = safe_pow(base, exp);
    
    // Verify correctness
    if let Some(power) = result {
        // Special cases
        if exp == 0 {
            assert_eq!(power, 1);
        } else if base == 0 {
            assert_eq!(power, 0);
        } else if base == 1 {
            assert_eq!(power, 1);
        }
        
        // Verify against checked_pow
        let expected = base.checked_pow(exp);
        assert_eq!(result, expected);
    } else {
        // If None, overflow must have occurred
        assert!(base.checked_pow(exp).is_none());
    }
});
