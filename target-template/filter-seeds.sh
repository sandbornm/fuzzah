#!/usr/bin/env bash
# Build seeds/corpus/ from seeds/raw/ by:
#   1. keeping only files <= MAX_BYTES
#   2. accepting only files whose first bytes match one of VALID_MAGIC_HEX
#   3. deduping by SHA-256
# Names files <sha256-prefix>.<ext> so the target's extension sniffing works.
#
# EDIT THIS PER TARGET: set VALID_MAGIC_HEX and VALID_EXTENSIONS for the input
# format(s) your harness accepts. Leave VALID_MAGIC_HEX=() to disable magic
# checking (accept anything of valid size).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
MAX_BYTES="${MAX_BYTES:-204800}"   # 200 KiB

# ── EDIT PER TARGET ─────────────────────────────────────────────────────────
# First N bytes of a valid input, lowercase hex, no separators. Any match wins.
# Examples:
#   PDF: VALID_MAGIC_HEX=("25504446")                   # "%PDF"
#   IVF: VALID_MAGIC_HEX=("444b4946")                   # "DKIF"
#   WebM/Matroska: VALID_MAGIC_HEX=("1a45dfa3")
#   PNG: VALID_MAGIC_HEX=("89504e470d0a1a0a")
# Combine for multi-format harnesses (e.g. IVF + WebM):
#   VALID_MAGIC_HEX=("444b4946" "1a45dfa3")
VALID_MAGIC_HEX=("REPLACE_WITH_MAGIC_HEX")

# File extensions to accept into raw/ and emit into corpus/. Lowercase.
VALID_EXTENSIONS=("bin")

# Default extension on the emitted file if the source had something unexpected.
DEFAULT_EXT="${VALID_EXTENSIONS[0]}"
# ────────────────────────────────────────────────────────────────────────────

RAW="$TARGET_DIR/seeds/raw"
CORPUS="$TARGET_DIR/seeds/corpus"

[[ -d "$RAW" ]] || { echo "[!] $RAW missing — run fetch-seeds.sh first"; exit 1; }

mkdir -p "$CORPUS"

# Wipe out corpus/ files of our tracked extensions before repopulating.
for ext in "${VALID_EXTENSIONS[@]}"; do
  find "$CORPUS" -maxdepth 1 -type f -name "*.${ext}" -delete
done

declare -A SEEN
kept=0; skipped_size=0; skipped_magic=0; skipped_dup=0

is_valid_magic() {
  local f="$1" hex
  # Read enough bytes to cover the longest magic in the list (max 16 bytes).
  hex="$(xxd -p -l 16 "$f" 2>/dev/null | head -1 | tr -d ' \n')"
  # If the magic list is empty or the placeholder, accept everything.
  if (( ${#VALID_MAGIC_HEX[@]} == 0 )) || [[ "${VALID_MAGIC_HEX[0]}" == "REPLACE_WITH_MAGIC_HEX" ]]; then
    return 0
  fi
  for m in "${VALID_MAGIC_HEX[@]}"; do
    if [[ "$hex" == "$m"* ]]; then
      return 0
    fi
  done
  return 1
}

# Build -iname arg string for find: "-iname '*.ext1' -o -iname '*.ext2' ..."
find_exts=()
for ext in "${VALID_EXTENSIONS[@]}"; do
  find_exts+=(-o -iname "*.${ext}")
done
# Drop the leading -o.
if (( ${#find_exts[@]} > 0 )); then
  unset 'find_exts[0]'
  find_exts=('(' "${find_exts[@]}" ')')
fi

while IFS= read -r -d '' f; do
  size=$(stat -c %s "$f")
  if (( size == 0 )) || (( size > MAX_BYTES )); then
    skipped_size=$((skipped_size + 1))
    continue
  fi
  if ! is_valid_magic "$f"; then
    skipped_magic=$((skipped_magic + 1))
    continue
  fi
  hash=$(sha256sum "$f" | cut -d' ' -f1)
  if [[ -n "${SEEN[$hash]:-}" ]]; then
    skipped_dup=$((skipped_dup + 1))
    continue
  fi
  SEEN[$hash]=1
  ext="${f##*.}"
  ext="${ext,,}"
  # If the source extension isn't in our whitelist, use the default.
  want_ext="$DEFAULT_EXT"
  for e in "${VALID_EXTENSIONS[@]}"; do
    if [[ "$ext" == "$e" ]]; then
      want_ext="$ext"
      break
    fi
  done
  cp "$f" "$CORPUS/${hash:0:16}.$want_ext"
  kept=$((kept + 1))
done < <(find "$RAW" -type f "${find_exts[@]}" -print0)

echo
echo "=== corpus build ==="
echo "kept:                      $kept"
echo "skipped (size):            $skipped_size"
echo "skipped (bad magic):       $skipped_magic"
echo "skipped (dup):             $skipped_dup"
echo
echo "corpus size: $(du -sh "$CORPUS" 2>/dev/null | cut -f1) across $(find "$CORPUS" -type f | wc -l) files"
echo
echo "size distribution (bytes):"
find "$CORPUS" -type f -printf '%s\n' | sort -n | awk '
  { a[NR]=$1; sum+=$1 }
  END {
    if (NR==0) { print "  (empty)"; exit }
    printf "  min:    %d\n",  a[1]
    printf "  p50:    %d\n",  a[int(NR*0.50)+1]
    printf "  p90:    %d\n",  a[int(NR*0.90)+1]
    printf "  max:    %d\n",  a[NR]
    printf "  mean:   %d\n",  sum/NR
    printf "  total:  %d\n",  sum
  }'
