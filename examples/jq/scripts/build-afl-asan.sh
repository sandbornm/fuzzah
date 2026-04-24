#!/usr/bin/env bash
# Build the target with AFL++ + ASAN + UBSAN instrumentation.
# Output at $TARGET_DIR/build-afl-asan/. Source reused from $TARGET_DIR/src/
# (cloned by build-afl-fast.sh; run that first).
#
# Must produce a binary at the same relative subpath as the fast build
# (see HARNESS_SUBPATH in start-fuzz.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
AFL_DIR="${AFL_DIR:-$HOME/fuzzing/tools/AFLplusplus}"

SRC="$TARGET_DIR/src"
BUILD="$TARGET_DIR/build-afl-asan"
CC_BIN="$AFL_DIR/afl-clang-fast"
CXX_BIN="$AFL_DIR/afl-clang-fast++"

[[ -x "$CC_BIN"   ]] || { echo "[!] missing $CC_BIN"; exit 1; }

SRC_GIT_URL="${SRC_GIT_URL:-https://github.com/jqlang/jq.git}"
SRC_GIT_REF="${SRC_GIT_REF:-jq-1.8.1}"

if [[ ! -d "$SRC/.git" ]]; then
  echo "[+] cloning $SRC_GIT_URL@$SRC_GIT_REF -> $SRC"
  git clone --depth 1 --branch "$SRC_GIT_REF" "$SRC_GIT_URL" "$SRC"
else
  echo "[=] refreshing $SRC to $SRC_GIT_REF"
  git -C "$SRC" fetch --depth 1 origin "refs/tags/$SRC_GIT_REF:refs/tags/$SRC_GIT_REF"
  git -C "$SRC" checkout -q "$SRC_GIT_REF"
fi
git -C "$SRC" submodule update --init --depth 1
(
  cd "$SRC"
  autoreconf -fi
)

if [[ "${FRESH:-0}" == "1" ]]; then
  rm -rf "$BUILD"
fi
mkdir -p "$BUILD"
cd "$BUILD"

export CC="$CC_BIN"
export CXX="$CXX_BIN"
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1
export AFL_QUIET=1
export CFLAGS="${CFLAGS:-} -g -O1 -fno-omit-frame-pointer"
export CXXFLAGS="${CXXFLAGS:-} -g -O1 -fno-omit-frame-pointer"

# ── EDIT PER TARGET ─────────────────────────────────────────────────────────
# Mirror the same configure/cmake/meson block you used in build-afl-fast.sh,
# but add --enable-debug (or equivalent), and pass --extra-cflags if the
# build system needs explicit flag plumbing.

"$SRC/configure" \
  --disable-shared --enable-static \
  --with-oniguruma=builtin
make -j"${MAKE_J:-$(nproc)}"

[[ -x "$BUILD/jq" ]] || { echo "[!] expected binary at $BUILD/jq" >&2; exit 2; }
printf '{"ok":true}\n' | "$BUILD/jq" -e . >/dev/null
