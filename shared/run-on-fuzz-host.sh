#!/usr/bin/env bash
# Run a shell snippet on the fuzz host.
#
# Modes:
#   - direct: already on the Linux fuzz host / VM
#   - orb:    on macOS or another host with Orb available
#
# Detection rules:
#   1. FUZZAH_HOST_MODE=direct|orb overrides autodetect
#   2. Linux + $HOME/fuzzing present => direct
#   3. otherwise, if `orb` is on PATH => orb
#   4. otherwise fail with a clear error
#
# The command is always executed via `bash -lc` on the target side so that
# $HOME and ~ expand on the fuzz host, not on the caller's machine.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<'EOF'
usage: run-on-fuzz-host.sh [--sudo] <shell-snippet>

examples:
  run-on-fuzz-host.sh 'bash "$HOME/fuzzing/targets/poppler/scripts/status.sh"'
  run-on-fuzz-host.sh 'cat "$HOME/fuzzing/targets/libvpx/crashes-triaged/INDEX.md"'
  run-on-fuzz-host.sh --sudo 'dmesg -T | tail -50'

env:
  FUZZAH_HOST_MODE=direct|orb   force execution mode
  ORB_VM=<name>                 orb VM name when in orb mode (default: fuzzer)
EOF
}

orb_debug_hint() {
  echo "[!] Orb command failed. For host-side diagnostics run:" >&2
  echo "    bash \"$SCRIPT_DIR/orb-debug.sh\"" >&2
  echo "[!] If OrbStack is wedged, fully quit and relaunch the app, then retry." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

USE_SUDO=0
if [[ "${1:-}" == "--sudo" ]]; then
  USE_SUDO=1
  shift
fi

[[ $# -ge 1 ]] || { usage >&2; exit 2; }
CMD="$1"

MODE="${FUZZAH_HOST_MODE:-auto}"
UNAME_S="$(uname -s)"

is_direct_host() {
  [[ "$UNAME_S" == "Linux" && -d "$HOME/fuzzing" ]]
}

resolve_mode() {
  case "$MODE" in
    direct|orb)
      printf '%s\n' "$MODE"
      return 0
      ;;
    auto)
      if is_direct_host; then
        printf 'direct\n'
        return 0
      fi
      if command -v orb >/dev/null 2>&1; then
        printf 'orb\n'
        return 0
      fi
      echo "[!] no fuzz host detected locally (\$HOME/fuzzing missing) and 'orb' is not on PATH" >&2
      exit 2
      ;;
    *)
      echo "[!] invalid FUZZAH_HOST_MODE='$MODE' (expected auto|direct|orb)" >&2
      exit 2
      ;;
  esac
}

MODE="$(resolve_mode)"

if [[ "$MODE" == "direct" ]]; then
  if (( USE_SUDO )); then
    exec sudo bash -lc "$CMD"
  else
    exec bash -lc "$CMD"
  fi
fi

ORB_VM="${ORB_VM:-fuzzer}"
if ! command -v orb >/dev/null 2>&1; then
  echo "[!] FUZZAH_HOST_MODE=orb but 'orb' is not on PATH" >&2
  exit 2
fi

run_orb() {
  local rc=0
  if (( USE_SUDO )); then
    orb -m "$ORB_VM" sudo bash -lc "$CMD" || rc=$?
  else
    orb -m "$ORB_VM" bash -lc "$CMD" || rc=$?
  fi
  if (( rc != 0 )); then
    if command -v orbctl >/dev/null 2>&1; then
      orb_status="$(orbctl status 2>/dev/null || true)"
      [[ -n "$orb_status" ]] && echo "[!] orbctl status: $orb_status" >&2
    fi
    orb_debug_hint
  fi
  exit "$rc"
}

if (( USE_SUDO )); then
  run_orb
else
  run_orb
fi
