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

"$SRC/configure" \
  --disable-shared --enable-static \
  --with-oniguruma=builtin
make -j"${MAKE_J:-$(nproc)}"

[[ -x "$BUILD/jq" ]] || { echo "[!] expected binary at $BUILD/jq" >&2; exit 2; }
"$BUILD/jq" -n '.' >/dev/null
echo
echo "=== build artefact ==="
ls -la "$BUILD/jq"
