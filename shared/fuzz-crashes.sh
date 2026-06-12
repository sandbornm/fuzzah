#!/usr/bin/env bash
# Print one target's triaged crash index through the fuzz-host execution shim.
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUN_ON_FUZZ_HOST="$SCRIPT_DIR/run-on-fuzz-host.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") <target>
EOF
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="$1"
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "[!] invalid target name: $TARGET (allowed: alnum, dot, dash, underscore)" >&2
  exit 2
}

bash "$RUN_ON_FUZZ_HOST" "cat \"\$HOME/fuzzing/targets/$TARGET/crashes-triaged/INDEX.md\""
