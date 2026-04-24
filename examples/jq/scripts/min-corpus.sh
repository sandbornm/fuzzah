#!/usr/bin/env bash
# Minimize seeds/corpus against the AFL-instrumented fast build so each kept
# file contributes unique edge coverage. Writes to seeds/corpus.min.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"

# Pull HARNESS_SUBPATH + HARNESS_ARGS out of start-fuzz.sh so cmin runs the
# harness the same way the fuzzer will.
HARNESS_SUBPATH="$(grep -oE '^HARNESS_SUBPATH=[^ ]+' "$SCRIPT_DIR/start-fuzz.sh" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '"')"
HARNESS_ARGS_RAW="$(grep -oE '^HARNESS_ARGS=.*' "$SCRIPT_DIR/start-fuzz.sh" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')"
: "${HARNESS_SUBPATH:=$(basename "$TARGET_DIR")}"
: "${HARNESS_ARGS_RAW:=@@}"

IN="$TARGET_DIR/seeds/corpus"
OUT="$TARGET_DIR/seeds/corpus.min"
BIN="$TARGET_DIR/build-afl/${HARNESS_SUBPATH}"

[[ -x "$BIN"               ]] || { echo "[!] missing $BIN — build-afl-fast.sh first"; exit 1; }
[[ -x "$AFL_DIR/afl-cmin"   ]] || { echo "[!] missing afl-cmin — check AFL++ install"; exit 1; }
[[ -d "$IN" && "$(ls -A "$IN")" ]] || { echo "[!] no input corpus at $IN — run filter-seeds.sh first"; exit 1; }

rm -rf "$OUT"

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

echo "[=] input: $(find "$IN" -type f | wc -l) files, $(du -sh "$IN" | cut -f1)"
echo "[=] running afl-cmin …"
# shellcheck disable=SC2086
"$AFL_DIR/afl-cmin" \
  -i "$IN" \
  -o "$OUT" \
  -t 5000 \
  -m 1024 \
  -- "$BIN" $HARNESS_ARGS_RAW

echo
echo "=== corpus.min ==="
echo "kept: $(find "$OUT" -type f | wc -l) files"
echo "size: $(du -sh "$OUT" | cut -f1)"
echo
echo "size distribution (bytes):"
find "$OUT" -type f -printf '%s\n' | sort -n | awk '
  { a[NR]=$1; sum+=$1 }
  END {
    if (NR==0) { print "  (empty)"; exit }
    printf "  min:  %d\n",  a[1]
    printf "  p50:  %d\n",  a[int(NR*0.50)+1]
    printf "  p90:  %d\n",  a[int(NR*0.90)+1]
    printf "  max:  %d\n",  a[NR]
    printf "  total:%d\n",  sum
  }'
