#![no_main]

use libfuzzer_sys::fuzz_target;
use audit_guard::math::safe_compound_interest;

fuzz_target!(|data: (u64, u64, u32)| {
    let (principal, rate_bp, periods) = data;
    
    // Limit periods to reasonable range to avoid timeout
    let periods = periods % 100;
    
    // Test safe_compound_interest never panics
    let result = safe_compound_interest(principal, rate_bp, periods);
    
    // Verify correctness
    if let Some(final_amount) = result {
        // If periods is 0, result should equal principal
        if periods == 0 {
            assert_eq!(final_amount, principal);
        }
        
        // If principal is 0, result should be 0
        if principal == 0 {
            assert_eq!(final_amount, 0);
        }
        
        // If rate is 0 (0% interest), result should equal principal
        if rate_bp == 0 {
            assert_eq!(final_amount, principal);
        }
        
        // Result should be >= principal when rate >= 0
        assert!(final_amount >= principal);
    }
    // If None, overflow occurred during calculation
});
