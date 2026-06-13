#!/usr/bin/env bash
# run-on-target.sh — route a shell snippet to the right execution context for a
# given fuzz target, based on the target's engine.
#
# Some targets are fuzzed by AFL++ inside the Linux VM (reached via orb / the
# run-on-fuzz-host.sh wrapper). Others are fuzzed by Jackalope/TinyInst on the
# macOS host itself (local fs, no orb). A fuzzilli target also lives in the VM
# (it's proxied like afl), just with a different stats schema. This wrapper hides
# that split so callers can say "run X on target T" and not care where T lives.
#
# Usage:
#   run-on-target.sh <target> <shell-snippet>
#
# Engine resolution (first match wins):
#   1. $FUZZAH_ENGINE_<target>   env override (target sanitized: non-alnum -> _)
#   2. ~/fuzzing-mac/targets/<target>/engine   (file, first token)
#   3. "afl"                     default
#
# Routing:
#   jackalope                  -> run locally via `bash -lc`
#   afl / fuzzilli / anything  -> delegate to shared/run-on-fuzz-host.sh (the VM)
#
# Env:
#   FUZZAH_DRYRUN=1  print `route=local|vm engine=<e>` and exit (do not execute).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ON_FUZZ_HOST="$SCRIPT_DIR/run-on-fuzz-host.sh"
HOST_TARGETS_ROOT="${FUZZAH_HOST_TARGETS_ROOT:-$HOME/fuzzing-mac/targets}"

usage() {
  cat <<'EOF'
usage: run-on-target.sh <target> <shell-snippet>

examples:
  run-on-target.sh imageio 'bash "$HOME/fuzzing-mac/targets/imageio/scripts/emit-stats.sh"'
  run-on-target.sh poppler 'bash "$HOME/fuzzing/targets/poppler/scripts/status.sh"'

env:
  FUZZAH_ENGINE_<target>=jackalope|afl|fuzzilli   force engine for <target>
  FUZZAH_HOST_TARGETS_ROOT=<dir>         host-target root (default ~/fuzzing-mac/targets)
  FUZZAH_DRYRUN=1                        print route+engine, do not execute
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; exit 0; fi
[[ $# -ge 2 ]] || { usage >&2; exit 2; }

TARGET="$1"; shift
CMD="$1"

# 1. env override — sanitize the target name into a valid shell var component.
san="$(printf '%s' "$TARGET" | sed 's/[^A-Za-z0-9]/_/g')"
env_var="FUZZAH_ENGINE_${san}"
engine="${!env_var:-}"

# 2. engine file on the macOS host
if [[ -z "$engine" ]]; then
  ef="$HOST_TARGETS_ROOT/$TARGET/engine"
  if [[ -r "$ef" ]]; then
    engine="$(tr -d '[:space:]' < "$ef" 2>/dev/null | head -c 64)"
  fi
fi

# 3. default
engine="${engine:-afl}"

case "$engine" in
  jackalope)    route="local" ;;
  afl|fuzzilli) route="vm" ;;   # both VM-located; fuzzilli just has a different stats schema
  *)            route="vm" ;;
esac

if [[ "${FUZZAH_DRYRUN:-0}" == "1" ]]; then
  printf 'route=%s engine=%s\n' "$route" "$engine"
  exit 0
fi

if [[ "$route" == "local" ]]; then
  exec bash -lc "$CMD"
else
  exec "$RUN_ON_FUZZ_HOST" "$CMD"
fi
