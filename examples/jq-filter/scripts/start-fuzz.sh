#!/usr/bin/env bash
# Launch the fuzz pipeline for this target. Creates/ensures a tmux session
# with windows:
#   primary   — master fuzzer on fast build + cmplog companion
#   asan      — secondary on ASAN+UBSAN build
#   explore   — secondary on fast build with the 'explore' power schedule
#   triage    — auto-triage loop
#   status    — periodic status snapshot
#
# Idempotent: reruns skip windows that already have a live afl-fuzz/triage
# process (scoped per target, so other targets' fuzzers don't confuse us).
# Safe to run from systemd and from the shared watchdog timer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
TARGET_NAME="$(basename "$TARGET_DIR")"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"
SESSION="${SESSION:-${TARGET_NAME}-fuzz}"

# ══════════════════════════════════════════════════════════════════════════
# EDIT PER TARGET — these are the only lines that need to change:
# ══════════════════════════════════════════════════════════════════════════
# Relative path from the build dir to the fuzz-target binary.
# Examples:  "mytool"  /  "utils/mybin"  /  "bin/myparser"  /  "src/decode"
HARNESS_SUBPATH="jq"

# Args passed to the harness, after `afl-fuzz -- <binary>`. Use @@ as the
# placeholder for the mutated input file. Any trailing args can redirect or
# suppress output. Examples:
#   "@@ /dev/null"          (binary takes input, writes rendered output to second arg)
#   "@@ -o /dev/null"       (output flag)
#   "-"                     (stdin-only target — no @@)
HARNESS_ARGS="-n -f @@ >/dev/null"

# Dict file (optional). Prefer a target-local dictionary in scripts/ so the
# target setup is self-contained; fall back to AFL++'s shared dictionaries.
SCRIPT_DICT="$SCRIPT_DIR/${TARGET_NAME}.dict"
AFL_DICT="$AFL_DIR/dictionaries/${TARGET_NAME}.dict"
if [[ -z "${DICT:-}" ]]; then
  if [[ -f "$SCRIPT_DICT" ]]; then
    DICT="$SCRIPT_DICT"
  else
    DICT="$AFL_DICT"
  fi
fi
# ══════════════════════════════════════════════════════════════════════════

# Process-match patterns used in pgrep scoping (so this target's kills don't
# touch other targets on the same host).
TARGET_TAG="targets/${TARGET_NAME}"

FAST_BIN="$TARGET_DIR/build-afl/${HARNESS_SUBPATH}"
ASAN_BIN="$TARGET_DIR/build-afl-asan/${HARNESS_SUBPATH}"
CMPLOG_BIN="$TARGET_DIR/build-afl-cmplog/${HARNESS_SUBPATH}"
CORPUS="$TARGET_DIR/seeds/corpus.min"
FIND="$TARGET_DIR/findings"

for f in "$FAST_BIN" "$ASAN_BIN" "$CMPLOG_BIN"; do
  [[ -x "$f" ]] || { echo "[!] missing $f — build first"; exit 1; }
done
[[ -d "$CORPUS" && "$(ls -A "$CORPUS")" ]] || { echo "[!] empty corpus at $CORPUS — run min-corpus.sh"; exit 1; }

mkdir -p "$FIND" "$TARGET_DIR/logs"

COMMON_ENV="AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 AFL_IMPORT_FIRST=1"
# -m is per-role below: fast build gets 1024 MiB, ASAN stays unbounded.
# Pathological inputs can balloon target children past the host's RAM; 1 GB
# cap on fast children prevents global OOM. ASAN needs -m none because its
# shadow memory pre-allocates TiBs of virtual address space.
COMMON_FLAGS=""
[[ -f "$DICT" ]] && COMMON_FLAGS="$COMMON_FLAGS -x $DICT"

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux new-session -d -s "$SESSION" -n idle
fi

is_role_running() {
  case "$1" in
    primary|asan|explore) pgrep -f "afl-fuzz.*-[MS] $1 .*$TARGET_TAG" >/dev/null ;;
    triage)               pgrep -f "$TARGET_TAG.*triage-loop\\.sh"   >/dev/null ;;
    status)               tmux list-windows -t "$SESSION" -F '#{window_name}' 2>/dev/null \
                          | grep -qx status ;;
    *)                    return 1 ;;
  esac
}

ensure_window() {
  local name="$1" cmd="$2"
  if is_role_running "$name"; then
    echo "[=] $name already running, skipping"
    return 0
  fi
  tmux kill-window -t "${SESSION}:${name}" 2>/dev/null || true
  tmux new-window -t "$SESSION" -n "$name"
  tmux send-keys -t "${SESSION}:${name}" "$cmd" Enter

  # For AFL fuzzer roles, poll fuzzer_stats to confirm the process actually
  # survived startup. send-keys only queues keystrokes; it doesn't wait for
  # the spawned process to come up, let alone stay up. This is the fix for
  # the 2026-04-23 "optimistic launched" outage — see
  # reports/2026-04-23-poppler-watchdog-cgroup-kill.md.
  case "$name" in
    primary|asan|explore)
      local stats="$FIND/$name/fuzzer_stats"
      # Role-specific deadline: asan+explore include a leading sleep in their
      # tmux command strings (5s and 10s respectively). Budget for that plus
      # ASAN shadow-memory setup time on a memory-pressured VM.
      local budget
      case "$name" in
        asan)    budget=45 ;;
        explore) budget=40 ;;
        *)       budget=30 ;;
      esac
      local deadline=$((SECONDS + budget))
      local pid=""
      while (( SECONDS < deadline )); do
        if [[ -s "$stats" ]] && grep -q '^fuzzer_pid' "$stats" 2>/dev/null; then
          pid="$(awk '/^fuzzer_pid/ {print $3; exit}' "$stats")"
          if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "[+] launched $name (pid $pid)"
            return 0
          fi
        fi
        sleep 1
      done
      echo "[!] $name failed to survive launch — fuzzer_stats never showed a live pid within ${budget}s"
      return 1
      ;;
    *)
      echo "[+] launched $name"
      return 0
      ;;
  esac
}

# Master (primary) — fast build, cmplog companion, 1 GB memlimit.
ensure_window primary "\
$COMMON_ENV \
$AFL_DIR/afl-fuzz -M primary -i $CORPUS -o $FIND \
  -c $CMPLOG_BIN -l 2AT \
  -t 3000 -m 1024 $COMMON_FLAGS \
  -- $FAST_BIN $HARNESS_ARGS"

# ASAN secondary — -m none mandatory for ASAN shadow memory.
ensure_window asan "\
sleep 5 && \
$COMMON_ENV \
$AFL_DIR/afl-fuzz -S asan -i $CORPUS -o $FIND \
  -t 5000 -m none $COMMON_FLAGS \
  -- $ASAN_BIN $HARNESS_ARGS"

# Explore secondary — broader schedule, 1 GB memlimit (fast build).
ensure_window explore "\
sleep 10 && \
$COMMON_ENV \
$AFL_DIR/afl-fuzz -S explore -p explore -i $CORPUS -o $FIND \
  -t 3000 -m 1024 $COMMON_FLAGS \
  -- $FAST_BIN $HARNESS_ARGS"

# Triage loop.
ensure_window triage "TARGET_DIR=$TARGET_DIR bash $SCRIPT_DIR/triage-loop.sh"

# Status refresh — convenience tail; not strictly needed.
ensure_window status "while true; do clear; bash $SCRIPT_DIR/status.sh; sleep 60; done"

echo
echo "=== tmux session '$SESSION' windows ==="
tmux list-windows -t "$SESSION"
echo
echo "Attach with:  tmux attach -t $SESSION"
echo "Stop:         bash $SCRIPT_DIR/stop-fuzz.sh"
