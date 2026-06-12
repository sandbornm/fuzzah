#!/usr/bin/env bash
# Bounded one-shot crash triage before a digest email.
#
# This is deliberately not a long-running loop. The live target triage loops
# still own normal crash processing; this script just drains a small backlog so
# a six-hour email reflects recent, deduped crash state.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_ON_HOST="$SHARED_DIR/run-on-fuzz-host.sh"
SELF_PATH="$SCRIPT_DIR/$(basename "$0")"

if [[ "$(uname -s)" != "Linux" || ! -d "$HOME/fuzzing" ]]; then
  exec "$RUN_ON_HOST" "bash $(printf '%q' "$SELF_PATH")"
fi

TARGETS_DIR="${TARGETS_DIR:-$HOME/fuzzing/targets}"
LOG_DIR="${LOG_DIR:-$HOME/fuzzing/logs}"
LOG="$LOG_DIR/crash-digest-triage.log"
LOCK_DIR="$LOG_DIR/crash-digest-triage.lock"
MAX_PER_TARGET="${FUZZ_DIGEST_MAX_TRIAGE_PER_TARGET:-25}"
MAX_TOTAL="${FUZZ_DIGEST_MAX_TRIAGE_TOTAL:-75}"
TRIAGE_TIMEOUT="${FUZZ_DIGEST_TRIAGE_TIMEOUT:-90}"

mkdir -p "$LOG_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "[triage-drain] already running; lock=$LOCK_DIR"
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

log() {
  printf '[triage-drain] %s %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG"
}

run_triage() {
  local triage="$1" crash="$2" fuzzer="$3"
  if command -v ionice >/dev/null 2>&1; then
    nice -n 15 ionice -c3 timeout "$TRIAGE_TIMEOUT" bash "$triage" "$crash" "$fuzzer"
  else
    nice -n 15 timeout "$TRIAGE_TIMEOUT" bash "$triage" "$crash" "$fuzzer"
  fi
}

[[ -d "$TARGETS_DIR" ]] || { log "no targets dir: $TARGETS_DIR"; exit 0; }

total=0
log "start max_per_target=$MAX_PER_TARGET max_total=$MAX_TOTAL timeout=${TRIAGE_TIMEOUT}s"

for tdir in "$TARGETS_DIR"/*; do
  [[ -d "$tdir" ]] || continue
  target="$(basename "$tdir")"
  triage="$tdir/scripts/triage-one.sh"
  [[ -x "$triage" ]] || { log "$target: no executable scripts/triage-one.sh; skip"; continue; }
  [[ -d "$tdir/findings" ]] || { log "$target: no findings dir; skip"; continue; }

  seen="$tdir/logs/triage-seen.txt"
  mkdir -p "$tdir/logs"
  touch "$seen"

  processed=0
  while IFS= read -r -d '' crash; do
    (( total >= MAX_TOTAL )) && break
    (( processed >= MAX_PER_TARGET )) && break
    fuzzer="$(basename "$(dirname "$(dirname "$crash")")")"
    key="$fuzzer/$(basename "$crash")"
    if grep -qxF "$key" "$seen"; then
      continue
    fi

    log "$target: triage $key"
    if run_triage "$triage" "$crash" "$fuzzer" >> "$LOG" 2>&1; then
      echo "$key" >> "$seen"
      processed=$((processed + 1))
      total=$((total + 1))
    else
      rc=$?
      log "$target: triage failed rc=$rc key=$key; will retry later"
    fi
  done < <(find "$tdir/findings" -path '*/crashes/id:*' -type f -print0 2>/dev/null | sort -z)

  log "$target: processed=$processed"
  (( total >= MAX_TOTAL )) && break
done

log "done total=$total"
