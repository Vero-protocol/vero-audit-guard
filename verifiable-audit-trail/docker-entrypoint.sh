#!/bin/sh
set -eu

REPORTS_DIR="${1:-${REPORTS_DIR:-/reports}}"
WAIT_SECONDS="${REPORT_WAIT_SECONDS:-60}"

i=0
while [ ! -f "$REPORTS_DIR/latest-scan.json" ]; do
  if [ "$i" -ge "$WAIT_SECONDS" ]; then
    echo "[audit-trail] Timed out waiting for $REPORTS_DIR/latest-scan.json" >&2
    exit 1
  fi
  echo "[audit-trail] Waiting for scan report ($i/${WAIT_SECONDS}s)..."
  i=$((i + 2))
  sleep 2
done

exec node dist/index.js "$REPORTS_DIR"
