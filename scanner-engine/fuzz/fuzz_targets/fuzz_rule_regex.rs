#![no_main]
use libfuzzer_sys::fuzz_target;
use vero_scanner_engine::{compile_rules, RULES};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let rules = compile_rules(RULES);
        // Each compiled regex must handle arbitrary input without panicking.
        for rule in &rules {
            let _ = rule.regex.is_match(line);
        }
    }
});
