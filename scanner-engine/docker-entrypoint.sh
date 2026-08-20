#!/bin/sh
set -eu

TARGET="${1:-${SCAN_TARGET:-/target}}"
REPORTS_DIR="${REPORTS_DIR:-/app/reports}"

mkdir -p "$REPORTS_DIR"

if [ ! -d "$TARGET" ]; then
  echo "[scanner] Target '$TARGET' not found — writing placeholder report."
  printf '%s\n' '{"target":"N/A","total_files":0,"findings":[],"governance_findings":[],"report_hash":"N/A"}' \
    > "$REPORTS_DIR/latest-scan.json"
  exit 0
fi

echo "[scanner] Scanning $TARGET ..."
exec scanner "$TARGET"
