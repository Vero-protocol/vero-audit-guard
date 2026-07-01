#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_sub;

fuzz_target!(|data: (u64, u64)| {
    let (a, b) = data;
    
    // Test safe_sub never panics
    let result = safe_sub(a, b);
    
    // Verify correctness
    if let Some(diff) = result {
        // The difference should be valid
        assert!(a >= b);
        assert!(diff <= a);
        
        // Manual underflow check
        let expected = a.checked_sub(b);
        assert_eq!(result, expected);
    } else {
        // If None, underflow must have occurred
        assert!(a.checked_sub(b).is_none());
    }
});
