#!/usr/bin/env bash
# Sync a host-side <target>-setup/ tree into $HOME/fuzzing/targets/<target>/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=shared/fuzzah-paths.sh
source "$SCRIPT_DIR/fuzzah-paths.sh"
RUN_ON_FUZZ_HOST="$SCRIPT_DIR/run-on-fuzz-host.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") <target>

Pushes:
  <control-root>/<target>-setup/SETUP.md
  <control-root>/<target>-setup/scripts/*

into:
  \$HOME/fuzzing/targets/<target>/
EOF
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="$1"
# Validate target name — interpolated into a remote shell via run-on-fuzz-host.sh.
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "[!] invalid target name: $TARGET (allowed: alnum, dot, dash, underscore)" >&2
  exit 2
}
SETUP_ROOT="$(fuzzah_setup_root "$TARGET")"

[[ -d "$SETUP_ROOT/scripts" ]] || { echo "[!] missing $SETUP_ROOT/scripts — run scaffold-target.sh first" >&2; exit 1; }
[[ -f "$SETUP_ROOT/SETUP.md" ]] || { echo "[!] missing $SETUP_ROOT/SETUP.md — run scaffold-target.sh first" >&2; exit 1; }

tar -C "$SETUP_ROOT" -cf - SETUP.md scripts \
  | bash "$RUN_ON_FUZZ_HOST" "dst=\"\$HOME/fuzzing/targets/$TARGET\"; mkdir -p \"\$dst\"; tar -xf - -C \"\$dst\""

echo "[+] synced $TARGET -> \$HOME/fuzzing/targets/$TARGET"
