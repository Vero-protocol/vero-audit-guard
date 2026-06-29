#![no_main]
use libfuzzer_sys::fuzz_target;
use vero_scanner_engine::{compile_rules, scan_content, RULES};

fuzz_target!(|data: &[u8]| {
    // Accept arbitrary bytes; non-UTF-8 input is silently ignored (same as real scan_file).
    if let Ok(content) = std::str::from_utf8(data) {
        let rules = compile_rules(RULES);
        // Must never panic on any valid UTF-8 input.
        let _findings = scan_content(content, "fuzz_input.rs", &rules);
    }
});
