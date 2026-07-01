#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_add;

fuzz_target!(|data: (u64, u64)| {
    let (a, b) = data;
    
    // Test safe_add never panics
    let result = safe_add(a, b);
    
    // Verify correctness when result is Some
    if let Some(sum) = result {
        // The sum should be valid
        assert!(sum >= a);
        assert!(sum >= b);
        
        // Manual overflow check
        let expected = a.checked_add(b);
        assert_eq!(result, expected);
    } else {
        // If None, overflow must have occurred
        assert!(a.checked_add(b).is_none());
    }
});
