#!/usr/bin/env bash
# Sync a target setup, build it, minimize corpus, and start the service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ON_FUZZ_HOST="$SCRIPT_DIR/run-on-fuzz-host.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") <target>

Runs:
  1. sync-target.sh
  2. harden + seed prep + 3 builds + cmin
  3. systemd enable/start
EOF
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="$1"
# Validate target name — it is interpolated into remote shell commands below.
# Restricting to a safe charset prevents arbitrary command execution on the
# fuzz host if a caller passes an unusual target string.
[[ "$TARGET" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "[!] invalid target name: $TARGET (allowed: alnum, dot, dash, underscore)" >&2
  exit 2
}

bash "$SCRIPT_DIR/sync-target.sh" "$TARGET"

bash "$RUN_ON_FUZZ_HOST" "
  cd \"\$HOME/fuzzing/targets/$TARGET/scripts\" &&
  bash harden.sh &&
  bash fetch-seeds.sh &&
  bash filter-seeds.sh &&
  bash build-afl-fast.sh &&
  bash build-afl-asan.sh &&
  bash build-afl-cmplog.sh &&
  bash min-corpus.sh
"

bash "$RUN_ON_FUZZ_HOST" "
  cp \"\$HOME/fuzzing/targets/$TARGET/scripts/$TARGET-fuzz.service\" \"\$HOME/.config/systemd/user/\" &&
  systemctl --user daemon-reload &&
  systemctl --user enable --now \"$TARGET-fuzz.service\"
"

echo
echo "[+] bootstrap complete for $TARGET"
echo "    next: bash \"$SCRIPT_DIR/run-on-fuzz-host.sh\" 'bash \"\$HOME/fuzzing/targets/$TARGET/scripts/status.sh\"'"
