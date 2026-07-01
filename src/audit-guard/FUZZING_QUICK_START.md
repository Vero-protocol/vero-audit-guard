# Fuzzing Quick Start Guide

Get started with the Audit Guard fuzzing suite in under 5 minutes.

## Prerequisites

```bash
# Install Rust nightly
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Run All Fuzz Tests

```bash
cd src/audit-guard
./run_all_fuzz.sh
```

This runs all 12 fuzz targets for 60 seconds each (~12 minutes total).

## Run Single Target

```bash
cd src/audit-guard
cargo +nightly fuzz run fuzz_safe_add -- -max_total_time=60
```

## View Fuzz Targets

All fuzz targets are in `fuzz/fuzz_targets/`:

- `fuzz_safe_add` - Addition
- `fuzz_safe_sub` - Subtraction
- `fuzz_safe_mul` - Multiplication
- `fuzz_safe_div` - Division
- `fuzz_safe_mod` - Modulo
- `fuzz_safe_pow` - Exponentiation
- `fuzz_safe_percentage` - Percentage calculation
- `fuzz_safe_scale` - Ratio scaling
- `fuzz_safe_average` - Average calculation
- `fuzz_safe_mul_add` - Multiply-add
- `fuzz_compound_interest` - Compound interest
- `fuzz_all_operations` - Combined operations

## Common Commands

### Run with multiple workers
```bash
cargo +nightly fuzz run fuzz_all_operations -- -workers=4
```

### Run indefinitely (until crash)
```bash
cargo +nightly fuzz run fuzz_safe_add
```

### Generate coverage report
```bash
cargo +nightly fuzz coverage fuzz_safe_add
```

### Reproduce a crash
```bash
cargo +nightly fuzz run fuzz_safe_add fuzz/artifacts/fuzz_safe_add/crash-<hash>
```

## Interpreting Results

### ✓ Success (No Issues Found)
```
#1234567 DONE   cov: 45 ft: 67 corp: 23/456b exec/s: 12345
```
All inputs handled safely!

### ✗ Crash Detected
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
```
Check `fuzz/artifacts/` for crash files.

## CI/CD Integration

Fuzzing runs automatically on:
- Pull requests to `main`
- Pushes to `feat/fuzzing-suite`
- Manual workflow dispatch

See `.github/workflows/fuzzing.yml`

## Testing Before PR

```bash
# Quick test (5 minutes)
cd src/audit-guard
./run_all_fuzz.sh 30

# Standard test (12 minutes) 
./run_all_fuzz.sh 60

# Extended test (1+ hour)
./run_all_fuzz.sh 300
```

## Need Help?

- Full documentation: `fuzz/README.md`
- Implementation guide: `FUZZING_IMPLEMENTATION.md`
- Issues: Check GitHub issues

## Soroban Safety Checklist

All operations in `math.rs` follow these rules:

- ✓ No panics on overflow/underflow
- ✓ No division by zero
- ✓ All operations return `Option<T>`
- ✓ No unsafe code
- ✓ Deterministic behavior

## Quick Troubleshooting

**Error: "cargo: command not found"**
- Install Rust: https://rustup.rs/

**Error: "no fuzz targets found"**
- Make sure you're in `src/audit-guard/` directory

**Error: "nightly toolchain not installed"**
- Run: `rustup install nightly`

**Fuzzing is slow**
- Use: `-- -workers=4` for parallel execution
- Use release builds automatically enabled

## What's Being Tested?

The fuzzing suite tests every arithmetic operation with:

1. **Boundary values**: MAX, MIN, 0, 1
2. **Overflow scenarios**: MAX + 1, MAX * 2
3. **Underflow scenarios**: 0 - 1, MIN - 1
4. **Division cases**: divide by 0, MIN / -1
5. **Random values**: Millions of random inputs
6. **Compound operations**: Chained calculations

## Success Metrics

- ✓ Zero crashes found
- ✓ 1,000,000+ executions per target
- ✓ All assertions pass
- ✓ No undefined behavior
- ✓ Deterministic results

Ready to start fuzzing! 🚀
