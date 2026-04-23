#!/usr/bin/env bash
# Idempotent watchdog: for every ~/fuzzing/targets/*/scripts/start-fuzz.sh,
# re-invoke it. start-fuzz is pgrep-guarded per role, so roles that are
# already running cost ~20 ms of pgrep and exit immediately. Only dead
# roles (OOM-killed, crashed) actually get relaunched.
#
# This is the gap closer for a fuzzer worker dying while its parent systemd
# service has already exited (Type=oneshot + RemainAfterExit=true, which won't
# restart on per-worker OOM).
set -uo pipefail

TARGETS_DIR="${TARGETS_DIR:-$HOME/fuzzing/targets}"
LOG="${LOG:-$HOME/fuzzing/logs/watchdog.log}"
mkdir -p "$(dirname "$LOG")"

echo "[watchdog] $(date -Iseconds) tick" >> "$LOG"

for sf in "$TARGETS_DIR"/*/scripts/start-fuzz.sh; do
  [[ -x "$sf" ]] || continue
  target="$(basename "$(dirname "$(dirname "$sf")")")"
  # Run non-fatal: a failing restart for one target shouldn't prevent the next.
  if out="$(bash "$sf" 2>&1)"; then
    # Only log if the script actually did something (launched a role).
    if grep -q '\[+\] launched' <<< "$out"; then
      echo "[watchdog] $(date -Iseconds) $target: relaunched role(s)" >> "$LOG"
      echo "$out" | grep -E '^\[[+=]\]' | sed 's/^/  /' >> "$LOG"
    fi
  else
    echo "[watchdog] $(date -Iseconds) $target: start-fuzz.sh failed (exit $?)" >> "$LOG"
    echo "$out" | tail -10 | sed 's/^/  /' >> "$LOG"
  fi
done
