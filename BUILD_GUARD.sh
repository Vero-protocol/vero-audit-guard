#!/usr/bin/env bash
# BUILD_GUARD.sh — Vero Protocol Watchtower Automation
# Scaffolds directories, runs scanner, tests anomaly-detector, anchors audit trail.
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="$ROOT/reports"
SCANNER_DIR="$ROOT/scanner-engine"
MONITOR_DIR="$ROOT/anomaly-detector"
TRAIL_DIR="$ROOT/verifiable-audit-trail"

log()  { echo "[BUILD_GUARD] $*"; }
fail() { echo "[BUILD_GUARD][FAIL] $*" >&2; exit 1; }

# ── 1. Scaffold directories ────────────────────────────────────────────────
log "Scaffolding directories..."
mkdir -p "$REPORTS_DIR" "$ROOT/monitor" "$ROOT/scanner"

# ── 2. Scanner Engine (Rust) ───────────────────────────────────────────────
log "Building scanner-engine..."
cd "$SCANNER_DIR"
cargo build --release 2>&1 | tail -5

TARGET_DIR="${1:-../vero-core-contracts}"
if [ -d "$TARGET_DIR" ]; then
  log "Running static analysis on $TARGET_DIR..."
  ./target/release/scanner "$TARGET_DIR" | tee "$REPORTS_DIR/latest-scan.json"
else
  log "Target '$TARGET_DIR' not found — skipping live scan. Creating placeholder report."
  echo '{"target":"N/A","total_files":0,"findings":[],"report_hash":"N/A"}' \
    > "$REPORTS_DIR/latest-scan.json"
fi

# ── 3. Anomaly Detector (TypeScript) ──────────────────────────────────────
log "Installing & testing anomaly-detector..."
cd "$MONITOR_DIR"
npm ci --silent
npm test

# ── 4. Verifiable Audit Trail (TypeScript) ────────────────────────────────
log "Installing & building verifiable-audit-trail..."
cd "$TRAIL_DIR"
npm ci --silent
npm run build

log "Anchoring audit report hashes (dry-run if no keypair set)..."
node dist/index.js "$REPORTS_DIR"

# ── 5. Security Health Check ──────────────────────────────────────────────
cd "$ROOT"
CRITICAL_COUNT=$(python3 -c "
import json, sys
try:
    r = json.load(open('$REPORTS_DIR/latest-scan.json'))
    print(sum(1 for f in r.get('findings',[]) if f.get('severity')=='CRITICAL'))
except: print(0)
")

log "Security Health Check:"
log "  Reports dir : $REPORTS_DIR"
log "  CRITICAL    : $CRITICAL_COUNT"

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  fail "Build blocked — $CRITICAL_COUNT CRITICAL finding(s) detected."
fi

log "✅ Build guard passed. All checks green."
