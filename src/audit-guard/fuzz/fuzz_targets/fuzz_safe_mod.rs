#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_mod;

fuzz_target!(|data: (u64, u64)| {
    let (a, b) = data;
    
    // Test safe_mod never panics
    let result = safe_mod(a, b);
    
    // Verify correctness
    if let Some(remainder) = result {
        // Modulo by zero should never succeed
        assert_ne!(b, 0);
        
        // Remainder should be less than divisor
        assert!(remainder < b);
        
        // Verify against checked_rem
        let expected = a.checked_rem(b);
        assert_eq!(result, expected);
    } else {
        // If None, b must be 0
        assert_eq!(b, 0);
    }
});
