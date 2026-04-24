#!/usr/bin/env bash
# Watch findings/*/crashes/ for new crash files and run triage-one.sh on each.
# Designed to run forever inside a tmux window. Re-runs are cheap thanks to
# triage-one's dedup-by-hash logic. Ctrl-C to stop.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
SEEN_DB="$TARGET_DIR/logs/triage-seen.txt"
LOG="$TARGET_DIR/logs/triage.log"
POLL_INTERVAL="${POLL_INTERVAL:-30}"

mkdir -p "$(dirname "$SEEN_DB")"
touch "$SEEN_DB"

echo "[triage-loop] starting; poll=${POLL_INTERVAL}s; seen=$(wc -l < "$SEEN_DB") entries" | tee -a "$LOG"

while true; do
  new=0
  while IFS= read -r -d '' crash; do
    # Unique key = fuzzer subdir name + crash filename (both stable per AFL++).
    fuzzer="$(basename "$(dirname "$(dirname "$crash")")")"
    key="$fuzzer/$(basename "$crash")"
    if grep -qxF "$key" "$SEEN_DB"; then
      continue
    fi
    echo "[triage-loop] $(date -Iseconds) new: $key" | tee -a "$LOG"
    if bash "$SCRIPT_DIR/triage-one.sh" "$crash" "$fuzzer" >> "$LOG" 2>&1; then
      echo "$key" >> "$SEEN_DB"
      new=$((new + 1))
    else
      echo "[triage-loop] triage-one failed for $key; will retry next poll" | tee -a "$LOG"
    fi
  done < <(find "$TARGET_DIR/findings" -path '*/crashes/id:*' -type f -print0 2>/dev/null)

  if (( new > 0 )); then
    echo "[triage-loop] $(date -Iseconds) processed $new new crashes" | tee -a "$LOG"
  fi
  sleep "$POLL_INTERVAL"
done
