#!/usr/bin/env bash
# Triage a single AFL crash file. Dedupes by ASAN stack hash and archives
# unique crashes to crashes-triaged/<hash>/. Re-running on an already-triaged
# crash is a cheap no-op (counter bump).
#
# Target-agnostic: derives $TARGET_DIR from the script's filesystem location.
# Reads HARNESS_SUBPATH and HARNESS_ARGS from the target's start-fuzz.sh so
# reproduction commands match what the fuzzer is using.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
TARGET_NAME="$(basename "$TARGET_DIR")"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"

# Pull HARNESS_SUBPATH and HARNESS_ARGS out of start-fuzz.sh. Graceful fallback
# if missing: use the build-dir's top-level executable.
HARNESS_SUBPATH="$(grep -oE '^HARNESS_SUBPATH=[^ ]+' "$SCRIPT_DIR/start-fuzz.sh" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '"')"
HARNESS_ARGS_RAW="$(grep -oE '^HARNESS_ARGS=.*' "$SCRIPT_DIR/start-fuzz.sh" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')"
: "${HARNESS_SUBPATH:=${TARGET_NAME}}"
: "${HARNESS_ARGS_RAW:=@@}"

ASAN_BIN="$TARGET_DIR/build-afl-asan/${HARNESS_SUBPATH}"
FAST_BIN="$TARGET_DIR/build-afl/${HARNESS_SUBPATH}"
TRIAGE_DIR="$TARGET_DIR/crashes-triaged"
INDEX="$TRIAGE_DIR/INDEX.md"

CRASH_PATH="${1:-}"
FUZZER_NAME="${2:-unknown}"

[[ -n "$CRASH_PATH" && -f "$CRASH_PATH" ]] || { echo "usage: $0 <crash-file> [fuzzer-name]" >&2; exit 2; }
[[ -x "$ASAN_BIN" ]] || { echo "[!] missing $ASAN_BIN (build-afl-asan not built?)" >&2; exit 1; }

mkdir -p "$TRIAGE_DIR"
[[ -f "$INDEX" ]] || cat > "$INDEX" <<EOF
# ${TARGET_NAME} fuzz — triaged unique crashes

| hash | first seen | fuzzer | hit count | top frame |
|------|-----------|--------|-----------|-----------|
EOF

# Optional: run afl-tmin to minimize. Bounded to 2 min; fall back to original.
# NOTE: -m 1024 matches the fuzzer's fast-build cap to avoid runaway children.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MIN_PATH="$WORK/min.bin"
if command -v "$AFL_DIR/afl-tmin" >/dev/null && [[ -x "$FAST_BIN" ]]; then
  # Expand HARNESS_ARGS_RAW with @@ replaced — afl-tmin uses its own @@ substitution.
  # shellcheck disable=SC2086
  timeout 120 "$AFL_DIR/afl-tmin" -i "$CRASH_PATH" -o "$MIN_PATH" -t 5000 -m 1024 -- "$FAST_BIN" $HARNESS_ARGS_RAW >/dev/null 2>&1 || true
fi
[[ -s "$MIN_PATH" ]] || cp "$CRASH_PATH" "$MIN_PATH"

# Replace @@ in the harness args with the minimized path for reproduction.
REPRO_ARGS="${HARNESS_ARGS_RAW//@@/$MIN_PATH}"

# Reproduce under ASAN; capture stderr + exit code.
ASAN_LOG="$WORK/asan.txt"
ASAN_RC=0
# shellcheck disable=SC2086
timeout 30 env \
  ASAN_OPTIONS="abort_on_error=0:symbolize=1:detect_leaks=0:halt_on_error=0:print_stacktrace=1" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  "$ASAN_BIN" $REPRO_ARGS > /dev/null 2> "$ASAN_LOG" || ASAN_RC=$?

# Preferred: ASAN/UBSan frame list.
FRAMES="$(grep -oE '#[0-9]+ 0x[0-9a-f]+ in [^ ]+' "$ASAN_LOG" \
  | awk '!/__asan|__ubsan|__sanitizer|libc_start/' \
  | head -5 || true)"

# Fallback: gdb bt for silent SIGSEGV / SIGABRT crashes.
GDB_LOG="$WORK/gdb.txt"
if [[ -z "$FRAMES" ]] && command -v gdb >/dev/null; then
  # shellcheck disable=SC2086
  timeout 30 env \
      ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1" \
      gdb -batch -nx -q \
    -ex "set confirm off" \
    -ex "set pagination off" \
    -ex "set environment ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1" \
    -ex "run" \
    -ex "bt 20" \
    -ex "quit" \
    --args "$ASAN_BIN" $REPRO_ARGS > "$GDB_LOG" 2>&1 || true
  FRAMES="$(grep -oE '^#[0-9]+ +(0x[0-9a-f]+ +)?in +[^ (]+' "$GDB_LOG" \
    | awk '!/__asan|__ubsan|__sanitizer|libc_start|raise|abort|__pthread_kill/' \
    | head -5 || true)"
fi

# Memlimit-kill detection: when ASAN+GDB both produce no frames AND the ASAN
# run timed out (exit 124) or was killed by OOM (exit 137), this is an
# artifact of the `-m` cap, not a memory-safety bug. Tag distinctly so the
# operator can auto-ignore it (see .status write below).
if [[ -z "$FRAMES" ]] && { (( ASAN_RC == 124 )) || (( ASAN_RC == 137 )); }; then
  FRAMES="memlimit-kill rc=$ASAN_RC $(head -c 64 "$MIN_PATH" | sha256sum | cut -c1-16)"
fi

# Last-resort fingerprint: signal + file head hash.
if [[ -z "$FRAMES" ]]; then
  sig="$(awk "/signal SIG/{print \$NF; exit}" "$GDB_LOG" 2>/dev/null)"
  [[ -z "$sig" ]] && sig="unknown-sig"
  FRAMES="no-frames $sig $(head -c 64 "$MIN_PATH" | sha256sum | cut -c1-16)"
fi
HASH="$(printf '%s' "$FRAMES" | md5sum | cut -c1-12)"
TOP_FRAME="$(echo "$FRAMES" | head -1 | sed -E 's/^#[0-9]+ +(0x[0-9a-f]+ +)?in +//')"

DEST="$TRIAGE_DIR/$HASH"
if [[ -d "$DEST" ]]; then
  # Known crash — bump counter.
  META="$DEST/meta.json"
  if [[ -f "$META" ]] && command -v jq >/dev/null; then
    tmp="$(mktemp)"
    jq --arg fuzzer "$FUZZER_NAME" --arg ts "$(date -Iseconds)" '
      .hit_count += 1 |
      .last_seen = $ts |
      .fuzzers[$fuzzer] = ((.fuzzers[$fuzzer] // 0) + 1)
    ' "$META" > "$tmp" && mv "$tmp" "$META"
  fi
  exit 0
fi

# New crash — archive it.
mkdir -p "$DEST"
cp "$MIN_PATH"   "$DEST/poc.bin"
cp "$CRASH_PATH" "$DEST/poc.original.bin"
{
  echo "=== ASAN output ==="
  cat "$ASAN_LOG"
  if [[ -f "$GDB_LOG" ]]; then
    echo
    echo "=== GDB backtrace (fallback) ==="
    cat "$GDB_LOG"
  fi
} > "$DEST/trace.txt"

TS="$(date -Iseconds)"
cat > "$DEST/meta.json" <<EOF
{
  "hash": "$HASH",
  "first_seen": "$TS",
  "last_seen": "$TS",
  "hit_count": 1,
  "top_frame": $(printf '%s' "$TOP_FRAME" | jq -Rs . 2>/dev/null || echo '""'),
  "fuzzers": {"$FUZZER_NAME": 1},
  "poc_size": $(stat -c %s "$DEST/poc.bin"),
  "poc_original_size": $(stat -c %s "$DEST/poc.original.bin")
}
EOF

# Auto-ignore memlimit-kill artifacts: noise, not bugs. Keep entry for dedup.
if [[ "$TOP_FRAME" == memlimit-kill* ]]; then
  echo ignore > "$DEST/.status"
fi

# shellcheck disable=SC2016  # printf format in single quotes is correct; %s are format specs not vars
printf '| `%s` | %s | %s | 1 | `%s` |\n' "$HASH" "$TS" "$FUZZER_NAME" "$TOP_FRAME" >> "$INDEX"

echo "[+] new crash $HASH ($TOP_FRAME)"
