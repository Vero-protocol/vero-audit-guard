# Fuzzing Suite for Audit Guard Math Module

This fuzzing suite provides comprehensive edge-case testing for all arithmetic operations in the `math.rs` module, adhering to Soroban integer safety standards.

## Overview

The fuzzing suite uses `cargo-fuzz` (powered by libFuzzer) to automatically generate and test millions of edge-case inputs for all arithmetic functions, helping to discover:

- Integer overflow vulnerabilities
- Integer underflow vulnerabilities
- Division by zero errors
- Edge cases in compound operations
- Unexpected behavior with boundary values

## Prerequisites

1. **Install Rust nightly** (required for cargo-fuzz):
   ```bash
   rustup install nightly
   ```

2. **Install cargo-fuzz**:
   ```bash
   cargo install cargo-fuzz
   ```

## Fuzz Targets

The suite includes the following fuzz targets:

### Individual Operation Targets

1. **fuzz_safe_add** - Tests safe addition with overflow detection
2. **fuzz_safe_sub** - Tests safe subtraction with underflow detection
3. **fuzz_safe_mul** - Tests safe multiplication with overflow detection
4. **fuzz_safe_div** - Tests safe division with zero-division and overflow checks
5. **fuzz_safe_mod** - Tests safe modulo operation
6. **fuzz_safe_pow** - Tests safe exponentiation
7. **fuzz_safe_percentage** - Tests percentage calculations
8. **fuzz_safe_scale** - Tests ratio-based scaling
9. **fuzz_safe_average** - Tests overflow-safe averaging
10. **fuzz_safe_mul_add** - Tests fused multiply-add operation

### Compound Operation Targets

11. **fuzz_compound_interest** - Tests compound interest calculations
12. **fuzz_all_operations** - Tests combinations of multiple operations

## Running the Fuzzing Suite

### Quick Start

Run all fuzz targets for 60 seconds each:

```bash
cd src/audit-guard
./run_all_fuzz.sh
```

### Running Individual Targets

Run a specific fuzz target indefinitely:

```bash
cargo +nightly fuzz run fuzz_safe_add
```

Run with a time limit (e.g., 120 seconds):

```bash
cargo +nightly fuzz run fuzz_safe_add -- -max_total_time=120
```

Run with a specific number of iterations:

```bash
cargo +nightly fuzz run fuzz_safe_add -- -runs=1000000
```

### Advanced Options

#### Parallel Execution

Run multiple workers in parallel:

```bash
cargo +nightly fuzz run fuzz_safe_add -- -workers=4
```

#### Custom Dictionary

Use a seed dictionary for more targeted fuzzing:

```bash
cargo +nightly fuzz run fuzz_safe_add -- -dict=fuzz_dictionary.txt
```

#### Coverage Information

Generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_safe_add
```

## Continuous Integration

The fuzzing suite is integrated into the CI/CD pipeline through the `.github/workflows/fuzzing.yml` workflow:

- Runs automatically on pull requests to the fuzzing branch
- Executes each fuzz target for 60 seconds
- Fails the build if any crashes or assertion failures are detected

## Interpreting Results

### Success

If fuzzing completes without finding issues:
```
#1234567 DONE   cov: 45 ft: 67 corp: 23/456b exec/s: 12345
```

### Crash Detected

If fuzzing finds a bug:
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
```

The crashing input will be saved in:
```
fuzz/artifacts/fuzz_target_name/crash-<hash>
```

### Reproducing Crashes

To reproduce a crash:

```bash
cargo +nightly fuzz run fuzz_safe_add fuzz/artifacts/fuzz_safe_add/crash-<hash>
```

## Soroban Integer Safety Standards

The math module and fuzzing suite adhere to Soroban's strict safety requirements:

### 1. No Panics
All arithmetic operations return `Option<T>` instead of panicking on overflow/underflow.

### 2. Checked Operations
All operations use Rust's checked arithmetic (`checked_add`, `checked_mul`, etc.).

### 3. Explicit Error Handling
Division by zero and other error conditions are explicitly handled.

### 4. Type Safety
Generic implementations ensure type-safe operations across all integer types.

### 5. Boundary Testing
Fuzz targets specifically test edge cases:
- Maximum and minimum values (`u64::MAX`, `i64::MIN`)
- Zero values
- One values
- Powers of two
- Adjacent to boundaries

## Coverage Goals

Target coverage metrics:
- **Line Coverage**: > 95%
- **Branch Coverage**: > 90%
- **Edge Case Coverage**: 100% of documented edge cases

## Best Practices

1. **Run fuzzing locally** before submitting PRs
2. **Add new fuzz targets** when adding new arithmetic operations
3. **Document edge cases** discovered through fuzzing
4. **Update tests** with interesting inputs found by fuzzing
5. **Run extended fuzzing** (24+ hours) before major releases

## Troubleshooting

### "error: no fuzz targets found"

Make sure you're in the correct directory:
```bash
cd src/audit-guard
```

### "nightly toolchain not installed"

Install the nightly toolchain:
```bash
rustup install nightly
```

### Out of Memory

Reduce memory usage with limits:
```bash
cargo +nightly fuzz run fuzz_safe_add -- -rss_limit_mb=2048
```

## Contributing

When adding new arithmetic functions to `math.rs`:

1. Create a new fuzz target in `fuzz/fuzz_targets/`
2. Add the target to `fuzz/Cargo.toml`
3. Update this README
4. Add the target to `run_all_fuzz.sh`
5. Run the new fuzz target for at least 1 hour locally

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Soroban documentation](https://soroban.stellar.org/)
- [Rust integer overflow handling](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
