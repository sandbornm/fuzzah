#!/usr/bin/env bash
# Graceful shutdown of fuzz processes. Sends SIGINT to afl-fuzz (it persists
# state on SIGINT) and the triage loop, then kills the tmux windows.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
TARGET_NAME="$(basename "$TARGET_DIR")"
SESSION="${SESSION:-${TARGET_NAME}-fuzz}"

# Scope kills to fuzzers whose cmdline references this target dir, so stopping
# one target never touches another (e.g. stopping target-A doesn't kill
# target-B's workers).
PATTERN="targets/${TARGET_NAME}"

echo "[=] sending SIGINT to afl-fuzz (scoped: $PATTERN)"
pkill -INT -f "afl-fuzz.*$PATTERN"            || echo "    no afl-fuzz running for ${TARGET_NAME}"
pkill -INT -f "triage-loop.*targets/${TARGET_NAME}" || echo "    no triage-loop running for ${TARGET_NAME}"

# Give afl-fuzz up to 10s to flush state.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  pgrep -f "afl-fuzz.*$PATTERN" >/dev/null || break
  sleep 1
done

if pgrep -f "afl-fuzz.*$PATTERN" >/dev/null; then
  echo "[!] ${TARGET_NAME} afl-fuzz still running after 10s; sending SIGTERM"
  pkill -TERM -f "afl-fuzz.*$PATTERN" || true
fi

# Kill the tmux windows (session remains empty).
for w in primary asan explore triage status; do
  tmux kill-window -t "${SESSION}:${w}" 2>/dev/null && echo "[=] killed window $w" || true
done

echo
echo "=== shutdown complete ==="
echo "findings preserved at: $TARGET_DIR/findings"
echo "resume with:           bash $SCRIPT_DIR/start-fuzz.sh"
