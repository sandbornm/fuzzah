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

# ── Option A: autoconf / configure-style ───────────────────────────────────
# "$SRC/configure" \
#   --disable-shared --enable-static \
#   --disable-docs --disable-install-docs
# make -j"${MAKE_J:-$(nproc)}"

# ── Option B: cmake-style ──────────────────────────────────────────────────
# cmake -S "$SRC" -B "$BUILD" \
#   -DCMAKE_BUILD_TYPE=Release \
#   -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
#   -DBUILD_SHARED_LIBS=OFF
# cmake --build "$BUILD" -j"${MAKE_J:-$(nproc)}"

# ── Option C: meson-style ──────────────────────────────────────────────────
# meson setup "$BUILD" "$SRC" \
#   --buildtype=release \
#   -Ddefault_library=static
# meson compile -C "$BUILD" -j "${MAKE_J:-$(nproc)}"

echo "[!] build-afl-cmplog.sh: uncomment the block for your build system." >&2
exit 10
