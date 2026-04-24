#!/usr/bin/env bash
# Build the target with AFL++ CMPLOG instrumentation. Used via the -c flag of
# the primary afl-fuzz — NOT a standalone fuzz target. CMPLOG helps guess
# magic bytes and comparison operands (very useful for parsers with many
# branch-on-constant conditions).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"

SRC="$TARGET_DIR/src"
BUILD="$TARGET_DIR/build-afl-cmplog"
CC_BIN="$AFL_DIR/afl-clang-fast"
CXX_BIN="$AFL_DIR/afl-clang-fast++"

[[ -d "$SRC/.git" ]] || { echo "[!] $SRC missing — run build-afl-fast.sh first"; exit 1; }
[[ -x "$CC_BIN"   ]] || { echo "[!] missing $CC_BIN"; exit 1; }

if [[ "${FRESH:-0}" == "1" ]]; then
  rm -rf "$BUILD"
fi
mkdir -p "$BUILD"
cd "$BUILD"

export CC="$CC_BIN"
export CXX="$CXX_BIN"
export AFL_LLVM_CMPLOG=1
export AFL_QUIET=1

# ── EDIT PER TARGET ─────────────────────────────────────────────────────────
# Same configure/build block as build-afl-fast.sh (no sanitizers, no debug).

"$SRC/configure" \
  --disable-shared --enable-static \
  --with-oniguruma=builtin
make -j"${MAKE_J:-$(nproc)}"

[[ -x "$BUILD/jq" ]] || { echo "[!] expected binary at $BUILD/jq" >&2; exit 2; }
"$BUILD/jq" -n '.' >/dev/null
