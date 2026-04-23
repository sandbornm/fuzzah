#!/usr/bin/env bash
# Build the target with AFL++ instrumentation (fast variant — no sanitizers).
# Produces $TARGET_DIR/build-afl/<harness> where <harness> is whatever the
# target's build system emits for the fuzz entry point.
#
# EDIT PER TARGET: the `configure`/`cmake`/`meson` invocation below.
# Everything else is generic.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"

SRC="$TARGET_DIR/src"
BUILD="$TARGET_DIR/build-afl"
CC_BIN="$AFL_DIR/afl-clang-fast"
CXX_BIN="$AFL_DIR/afl-clang-fast++"

[[ -x "$CC_BIN"  ]] || { echo "[!] missing $CC_BIN — build AFL++ first"; exit 1; }
[[ -x "$CXX_BIN" ]] || { echo "[!] missing $CXX_BIN — build AFL++ first"; exit 1; }

# ── EDIT PER TARGET ─────────────────────────────────────────────────────────
# 1. Clone the target's upstream source the first time.
#    (Replace with your repo URL. If the target is vendored in-tree, skip this
#    block and symlink the source to $SRC manually.)
SRC_GIT_URL="${SRC_GIT_URL:-REPLACE_WITH_UPSTREAM_GIT_URL}"
if [[ ! -d "$SRC/.git" ]]; then
  if [[ "$SRC_GIT_URL" == "REPLACE_WITH_UPSTREAM_GIT_URL" ]]; then
    echo "[!] SRC_GIT_URL not set (edit this script or export it). $SRC missing." >&2
    exit 2
  fi
  echo "[+] cloning $SRC_GIT_URL -> $SRC (depth 1)"
  git clone --depth 1 "$SRC_GIT_URL" "$SRC"
else
  echo "[=] reusing existing $SRC (HEAD: $(git -C "$SRC" rev-parse --short HEAD))"
fi

# 2. Optional wipe for a clean rebuild.
if [[ "${FRESH:-0}" == "1" ]]; then
  echo "[-] removing $BUILD (FRESH=1)"
  rm -rf "$BUILD"
fi
mkdir -p "$BUILD"
cd "$BUILD"

# 3. AFL-clang as the compiler. AFL_QUIET=1 silences per-file build noise.
export CC="$CC_BIN"
export CXX="$CXX_BIN"
export AFL_QUIET=1

# 4. Configure + build. Pick the right block for your target's build system.
#    (Comment out the others.)

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

echo "[!] build-afl-fast.sh: uncomment the block for your build system and" >&2
echo "    customize the flags. No build ran." >&2
exit 10

# ── sanity check (runs after your build block above) ───────────────────────
# Adjust HARNESS_SUBPATH to match the binary your build emits. The following
# template line is fine if $HARNESS_SUBPATH is already exported.
# [[ -x "$BUILD/${HARNESS_SUBPATH:-mytool}" ]] || { echo "[!] expected binary at $BUILD/${HARNESS_SUBPATH:-mytool}" >&2; exit 2; }
# echo
# echo "=== build artefact ==="
# ls -la "$BUILD/${HARNESS_SUBPATH:-mytool}"
