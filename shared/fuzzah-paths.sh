#!/usr/bin/env bash
# Shared path helpers for the fuzzah kit.
#
# Layouts supported:
#   1. standalone repo:
#        /path/to/fuzzah
#   2. nested control plane (like this workspace):
#        /path/to/fuzzig/fuzzah
#        /path/to/fuzzig/<target>-setup
#
# Override detection with:
#   FUZZAH_CONTROL_ROOT=/path/to/control-plane
set -euo pipefail

FUZZAH_SHARED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZAH_REPO_ROOT="$(cd "$FUZZAH_SHARED_DIR/.." && pwd)"
FUZZAH_TEMPLATE_ROOT="$FUZZAH_REPO_ROOT/target-template"

detect_control_root() {
  if [[ -n "${FUZZAH_CONTROL_ROOT:-}" ]]; then
    printf '%s\n' "$FUZZAH_CONTROL_ROOT"
    return 0
  fi

  local parent
  parent="$(cd "$FUZZAH_REPO_ROOT/.." && pwd)"

  if [[ -f "$parent/AGENTS.md" || -f "$parent/CLAUDE.md" || -d "$parent/.agents" || -d "$parent/.claude" ]]; then
    printf '%s\n' "$parent"
    return 0
  fi

  printf '%s\n' "$FUZZAH_REPO_ROOT"
}

FUZZAH_CONTROL_ROOT="$(detect_control_root)"

fuzzah_setup_root() {
  local target="$1"
  printf '%s/%s-setup\n' "$FUZZAH_CONTROL_ROOT" "$target"
}

fuzzah_scripts_dir() {
  local target="$1"
  printf '%s/scripts\n' "$(fuzzah_setup_root "$target")"
}
