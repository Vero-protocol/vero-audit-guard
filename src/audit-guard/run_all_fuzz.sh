#!/bin/bash

# Comprehensive fuzzing script for all arithmetic operations
# Runs each fuzz target for a specified duration

set -e

FUZZ_TIME=${1:-60}  # Default: 60 seconds per target
PARALLEL_WORKERS=${2:-1}  # Default: 1 worker

echo "=========================================="
echo "Audit Guard Fuzzing Suite"
echo "=========================================="
echo "Time per target: ${FUZZ_TIME} seconds"
echo "Parallel workers: ${PARALLEL_WORKERS}"
echo "=========================================="
echo ""

# Array of all fuzz targets
TARGETS=(
    "fuzz_safe_add"
    "fuzz_safe_sub"
    "fuzz_safe_mul"
    "fuzz_safe_div"
    "fuzz_safe_mod"
    "fuzz_safe_pow"
    "fuzz_safe_percentage"
    "fuzz_safe_scale"
    "fuzz_safe_average"
    "fuzz_safe_mul_add"
    "fuzz_compound_interest"
    "fuzz_all_operations"
)

# Track results
PASSED=0
FAILED=0
FAILED_TARGETS=()

# Run each fuzz target
for target in "${TARGETS[@]}"; do
    echo "=========================================="
    echo "Running: $target"
    echo "=========================================="
    
    if cargo +nightly fuzz run "$target" -- \
        -max_total_time="$FUZZ_TIME" \
        -workers="$PARALLEL_WORKERS" \
        -print_final_stats=1; then
        echo "✓ $target completed successfully"
        ((PASSED++))
    else
        echo "✗ $target failed!"
        ((FAILED++))
        FAILED_TARGETS+=("$target")
    fi
    
    echo ""
done

# Print summary
echo "=========================================="
echo "Fuzzing Complete"
echo "=========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed targets:"
    for target in "${FAILED_TARGETS[@]}"; do
        echo "  - $target"
    done
    echo ""
    echo "To reproduce failures, run:"
    echo "  cargo +nightly fuzz run <target_name> <artifact_path>"
    exit 1
else
    echo ""
    echo "All fuzz targets passed! ✓"
    exit 0
fi
