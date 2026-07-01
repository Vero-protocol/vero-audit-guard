#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_average;

fuzz_target!(|data: (u64, u64)| {
    let (a, b) = data;
    
    // Test safe_average never panics
    let result = safe_average(a, b);
    
    // Verify correctness
    if let Some(avg) = result {
        // Average should be between the two values
        if a <= b {
            assert!(a <= avg && avg <= b);
        } else {
            assert!(b <= avg && avg <= a);
        }
        
        // If both values are equal, average should equal them
        if a == b {
            assert_eq!(avg, a);
        }
        
        // Average should be close to the midpoint
        // We use saturating operations to avoid overflow in verification
        let sum_half = (a / 2).saturating_add(b / 2);
        let diff = if avg > sum_half {
            avg - sum_half
        } else {
            sum_half - avg
        };
        // Allow for rounding difference of at most 1
        assert!(diff <= 1);
    }
});
