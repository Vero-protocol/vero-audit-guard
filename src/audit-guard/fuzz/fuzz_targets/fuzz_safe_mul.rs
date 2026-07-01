#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_mul;

fuzz_target!(|data: (u64, u64)| {
    let (a, b) = data;
    
    // Test safe_mul never panics
    let result = safe_mul(a, b);
    
    // Verify correctness
    if let Some(product) = result {
        // If a or b is 0, product should be 0
        if a == 0 || b == 0 {
            assert_eq!(product, 0);
        } else {
            // Product should be at least as large as either factor
            assert!(product >= a);
            assert!(product >= b);
        }
        
        // Manual overflow check
        let expected = a.checked_mul(b);
        assert_eq!(result, expected);
    } else {
        // If None, overflow must have occurred
        assert!(a.checked_mul(b).is_none());
    }
});
