#!/usr/bin/env bash
# verify-setup.sh — acceptance-test harness for the fuzzah toolkit.
#
# Usage:
#   bash shared/verify-setup.sh [--skip-live]
#
# Flags:
#   --skip-live   suppress VM-dependent checks (useful in CI)
#
# Exit codes:
#   0 — all assertions passed
#   1 — one or more assertions failed
#
# Intentionally NOT set -e: a failing assertion must not abort the rest.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=fuzzah-paths.sh
source "$SCRIPT_DIR/fuzzah-paths.sh"
set +e  # fuzzah-paths.sh uses set -euo pipefail; re-disable errexit so assertions accumulate

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------
SKIP_LIVE=0
for arg in "$@"; do
  case "$arg" in
    --skip-live) SKIP_LIVE=1 ;;
    -h|--help)
      printf 'usage: %s [--skip-live]\n' "$(basename "$0")"
      exit 0
      ;;
    *)
      printf '[!] unknown flag: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$(( PASS_COUNT + 1 ))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  printf '[FAIL] %s\n' "$1"
}

skip() {
  printf '[SKIP] %s\n' "$1"
}

# ---------------------------------------------------------------------------
# 1. Static structure — required files exist
# ---------------------------------------------------------------------------
printf '\n-- Static structure --\n'

required_files=(
  "$FUZZAH_REPO_ROOT/README.md"
  "$FUZZAH_REPO_ROOT/AGENTS.md"
  "$FUZZAH_REPO_ROOT/CLAUDE.md"
  "$FUZZAH_REPO_ROOT/.claude/settings.json"
  "$FUZZAH_TEMPLATE_ROOT/start-fuzz.sh"
  "$FUZZAH_TEMPLATE_ROOT/TARGET-fuzz.service"
  "$FUZZAH_SHARED_DIR/run-on-fuzz-host.sh"
  "$FUZZAH_SHARED_DIR/check-in.sh"
  "$FUZZAH_SHARED_DIR/rig-check.sh"
  "$FUZZAH_SHARED_DIR/scaffold-target.sh"
  "$FUZZAH_SHARED_DIR/bootstrap-target.sh"
  "$FUZZAH_SHARED_DIR/fuzz-watchdog.sh"
  "$FUZZAH_SHARED_DIR/fuzz-watchdog.service"
  "$FUZZAH_REPO_ROOT/examples/README.md"
  "$FUZZAH_REPO_ROOT/examples/jq/SETUP.md"
  "$FUZZAH_REPO_ROOT/examples/jq-filter/SETUP.md"
)

for f in "${required_files[@]}"; do
  if [[ -f "$f" ]]; then
    pass "exists: ${f#"$FUZZAH_REPO_ROOT/"}"
  else
    fail "missing: ${f#"$FUZZAH_REPO_ROOT/"}"
  fi
done

# ---------------------------------------------------------------------------
# 2. Executable bit — every *.sh under shared/ and target-template/
# ---------------------------------------------------------------------------
printf '\n-- Executable bit --\n'

while IFS= read -r -d '' script; do
  if [[ -x "$script" ]]; then
    pass "executable: ${script#"$FUZZAH_REPO_ROOT/"}"
  else
    fail "not executable: ${script#"$FUZZAH_REPO_ROOT/"}"
  fi
done < <(find "$FUZZAH_SHARED_DIR" "$FUZZAH_TEMPLATE_ROOT" -name '*.sh' -print0 | sort -z)

# ---------------------------------------------------------------------------
# 3. Shellcheck — every *.sh in shared/ and target-template/
# ---------------------------------------------------------------------------
printf '\n-- Shellcheck --\n'

if ! command -v shellcheck >/dev/null 2>&1; then
  skip "shellcheck not installed"
else
  while IFS= read -r -d '' script; do
    sc_out=""
    if sc_out="$(shellcheck -e SC1091 "$script" 2>&1)"; then
      pass "shellcheck: ${script#"$FUZZAH_REPO_ROOT/"}"
    else
      fail "shellcheck: ${script#"$FUZZAH_REPO_ROOT/"}"
      printf '%s\n' "$sc_out" | sed 's/^/    /'
    fi
  done < <(find "$FUZZAH_SHARED_DIR" "$FUZZAH_TEMPLATE_ROOT" -name '*.sh' -print0 | sort -z)
fi

# ---------------------------------------------------------------------------
# 4. Systemd unit hygiene — KillMode=process present in both units
# ---------------------------------------------------------------------------
printf '\n-- Systemd unit hygiene --\n'

unit_files=(
  "$FUZZAH_SHARED_DIR/fuzz-watchdog.service"
  "$FUZZAH_TEMPLATE_ROOT/TARGET-fuzz.service"
)

for unit in "${unit_files[@]}"; do
  label="${unit#"$FUZZAH_REPO_ROOT/"}"
  if [[ ! -f "$unit" ]]; then
    fail "KillMode=process in $label (file missing)"
  elif grep -q '^KillMode=process' "$unit"; then
    pass "KillMode=process in $label"
  else
    fail "KillMode=process missing in $label"
  fi
done

# ---------------------------------------------------------------------------
# 5. Live round-trip (skipped when --skip-live)
# ---------------------------------------------------------------------------
printf '\n-- Live round-trip --\n'

if (( SKIP_LIVE )); then
  skip "run-on-fuzz-host round-trip (LIVE_OK) — suppressed by --skip-live"
  skip "fuzzing/targets listing — suppressed by --skip-live"
else
  # 5a. echo LIVE_OK
  live_out=""
  if live_out="$(bash "$FUZZAH_SHARED_DIR/run-on-fuzz-host.sh" 'echo LIVE_OK' 2>&1)" \
      && printf '%s\n' "$live_out" | grep -q 'LIVE_OK'; then
    pass "run-on-fuzz-host round-trip (LIVE_OK)"
  else
    fail "run-on-fuzz-host round-trip (LIVE_OK) — output: $live_out"
  fi

  # 5b. ls ~/fuzzing/targets must produce non-empty output
  targets_out=""
  if targets_out="$(bash "$FUZZAH_SHARED_DIR/run-on-fuzz-host.sh" \
      'ls ~/fuzzing/targets 2>/dev/null' 2>&1)" \
      && [[ -n "$targets_out" ]]; then
    pass "fuzzing/targets listing non-empty"
  else
    fail "fuzzing/targets listing empty or command failed"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'
if (( FAIL_COUNT == 0 )); then
  printf '== ALL PASS ==\n'
  exit 0
else
  printf '== %d FAILURE(S) ==\n' "$FAIL_COUNT"
  exit 1
fi
