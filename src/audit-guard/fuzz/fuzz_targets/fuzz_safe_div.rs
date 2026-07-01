#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_div;

fuzz_target!(|data: (i64, i64)| {
    let (a, b) = data;
    
    // Test safe_div never panics
    let result = safe_div(a, b);
    
    // Verify correctness
    if let Some(quotient) = result {
        // Division by zero should never succeed
        assert_ne!(b, 0);
        
        // The special case i64::MIN / -1 should be caught
        assert!(!(a == i64::MIN && b == -1));
        
        // Verify against checked_div
        let expected = a.checked_div(b);
        assert_eq!(result, expected);
    } else {
        // If None, either b is 0 or overflow occurred (i64::MIN / -1)
        assert!(b == 0 || a.checked_div(b).is_none());
    }
});
