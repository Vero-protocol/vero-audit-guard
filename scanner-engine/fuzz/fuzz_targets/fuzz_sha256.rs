#![no_main]
use libfuzzer_sys::fuzz_target;
use vero_scanner_engine::sha256_of;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // sha256_of must produce a valid 64-char lowercase hex string for any input.
        let hash = sha256_of(s);
        assert_eq!(hash.len(), 64, "SHA-256 hex digest must always be 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 output must be valid hex"
        );
    }
});
