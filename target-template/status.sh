#!/usr/bin/env bash
# One-shot snapshot of the fuzz rig for this target.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
TARGET_NAME="$(basename "$TARGET_DIR")"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"
FIND="$TARGET_DIR/findings"
TRIAGE="$TARGET_DIR/crashes-triaged"

echo "=== ${TARGET_NAME}-fuzz status @ $(date +'%Y-%m-%d %H:%M:%S') ==="
echo

# Fuzzer processes. Scope pgrep to this target's dir so other targets don't inflate counts.
n_fuzz=$(pgrep -fc "afl-fuzz.*targets/${TARGET_NAME}" 2>/dev/null || echo 0)
n_triage=$(pgrep -fc "targets/${TARGET_NAME}.*triage-loop" 2>/dev/null || echo 0)
echo "processes:  afl-fuzz=$n_fuzz  triage-loop=$n_triage"

# afl-whatsup summary.
if [[ -d "$FIND" && -n "$(ls -A "$FIND" 2>/dev/null)" ]]; then
  if [[ -x "$AFL_DIR/afl-whatsup" ]]; then
    echo
    "$AFL_DIR/afl-whatsup" -s "$FIND" 2>/dev/null | sed -n '1,30p'
  fi
fi

# Disk.
echo
echo "disk:"
df -h "$TARGET_DIR" | tail -1

# Crash summary.
if [[ -d "$TRIAGE" ]]; then
  n_unique=$(find "$TRIAGE" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
  echo
  echo "triaged unique crashes: $n_unique"
  if (( n_unique > 0 )); then
    echo "most recent 5:"
    # shellcheck disable=SC2012  # ls -t for mtime sort; find has no portable -mtime sort
    ls -1t "$TRIAGE"/*/meta.json 2>/dev/null | head -5 | while read -r m; do
      h=$(basename "$(dirname "$m")")
      top=$(jq -r '.top_frame // "?"' "$m" 2>/dev/null || echo '?')
      seen=$(jq -r '.first_seen // "?"' "$m" 2>/dev/null || echo '?')
      printf '  %s  %s  %s\n' "$h" "$seen" "$top"
    done
  fi
fi

raw=$(find "$FIND" -path '*/crashes/id:*' -type f 2>/dev/null | wc -l)
echo
echo "raw crashes found (pre-dedup): $raw"

echo
echo "review:  cat $TRIAGE/INDEX.md"
echo "log:     tail -f $TARGET_DIR/logs/triage.log"
