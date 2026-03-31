#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURES_DIR="${1:-$ROOT_DIR/fixtures}"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
RUN_ROOT="$ROOT_DIR/target/fixture_circom_batch"
RUN_DIR="$RUN_ROOT/$TIMESTAMP"
LATEST_LINK="$RUN_ROOT/latest"
SUMMARY_LOG="$RUN_DIR/summary.log"

mkdir -p "$RUN_DIR"
rm -f "$LATEST_LINK"
ln -s "$RUN_DIR" "$LATEST_LINK"

cd "$ROOT_DIR"

mapfile -t CIRCOM_FILES < <(find "$FIXTURES_DIR" -maxdepth 1 -type f -name '*.circom' | sort)

if [ "${#CIRCOM_FILES[@]}" -eq 0 ]; then
  echo "No .circom files found under $FIXTURES_DIR" | tee "$SUMMARY_LOG"
  exit 1
fi

echo "Batch started at $(date)" | tee "$SUMMARY_LOG"
echo "Root: $ROOT_DIR" | tee -a "$SUMMARY_LOG"
echo "Fixtures: $FIXTURES_DIR" | tee -a "$SUMMARY_LOG"
echo "Run dir: $RUN_DIR" | tee -a "$SUMMARY_LOG"
echo "Total circuits: ${#CIRCOM_FILES[@]}" | tee -a "$SUMMARY_LOG"
echo | tee -a "$SUMMARY_LOG"

SUCCESS_COUNT=0
FAIL_COUNT=0

for circom_file in "${CIRCOM_FILES[@]}"; do
  stem="$(basename "$circom_file" .circom)"
  log_file="$RUN_DIR/${stem}.log"

  {
    echo "============================================================"
    echo "[$(date)] START $circom_file"
    echo "Log file: $log_file"
    echo "Command: cargo run --quiet -- circom $circom_file"
    echo "============================================================"
  } | tee -a "$SUMMARY_LOG" | tee "$log_file" >/dev/null

  if cargo run --quiet -- circom "$circom_file" >>"$log_file" 2>&1; then
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    echo "[$(date)] OK   $circom_file" | tee -a "$SUMMARY_LOG"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[$(date)] FAIL $circom_file (see $log_file)" | tee -a "$SUMMARY_LOG"
  fi

  echo | tee -a "$SUMMARY_LOG"
done

echo "Batch finished at $(date)" | tee -a "$SUMMARY_LOG"
echo "Success: $SUCCESS_COUNT" | tee -a "$SUMMARY_LOG"
echo "Failed:  $FAIL_COUNT" | tee -a "$SUMMARY_LOG"

if [ "$FAIL_COUNT" -ne 0 ]; then
  exit 1
fi

