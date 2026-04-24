#!/usr/bin/env bash
# orb-debug.sh — best-effort diagnostics for OrbStack-backed fuzz hosts.
#
# Use this on macOS when Orb-backed commands fail unexpectedly. It focuses on:
#   • control-plane state (`orbctl`)
#   • helper health (`vmgr` RSS / uptime)
#   • recent vmgr log markers
#   • the persisted raw data image path (where findings live)
#
# This script is intentionally read-only.
set -uo pipefail

UNAME_S="$(uname -s)"
ORB_VM="${ORB_VM:-fuzzer}"
TS="$(date +'%Y-%m-%d %H:%M:%S %Z')"

if [[ "$UNAME_S" != "Darwin" ]]; then
  echo "[!] orb-debug is intended for macOS hosts with OrbStack" >&2
  exit 2
fi

if ! command -v orb >/dev/null 2>&1; then
  echo "[!] 'orb' not found on PATH" >&2
  exit 2
fi

if ! command -v orbctl >/dev/null 2>&1; then
  echo "[!] 'orbctl' not found on PATH" >&2
  exit 2
fi

GROUP_ROOT="$HOME/Library/Group Containers"
ORB_GROUP_DIR=""
if [[ -d "$GROUP_ROOT" ]]; then
  ORB_GROUP_DIR="$(find "$GROUP_ROOT" -maxdepth 1 -type d -name '*.dev.orbstack' 2>/dev/null | head -1)"
fi

DATA_IMG=""
if [[ -n "$ORB_GROUP_DIR" && -f "$ORB_GROUP_DIR/data/data.img.raw" ]]; then
  DATA_IMG="$ORB_GROUP_DIR/data/data.img.raw"
fi

VMGR_LOG="$HOME/.orbstack/log/vmgr.log"

echo "=== Orb debug @ $TS (vm=$ORB_VM) ==="
echo

orb_version="$(orbctl version 2>/dev/null | paste -sd ' ' - || true)"
orb_status="$(orbctl status 2>/dev/null | tr -d '\r' || true)"

echo "OrbStack:"
echo "  version: ${orb_version:-unavailable}"
echo "  status:  ${orb_status:-unavailable}"

# shellcheck disable=SC2009  # pgrep cannot filter by full command substring here
if ps_out="$(ps ax -o pid=,etime=,rss=,command= 2>/dev/null | grep 'OrbStack Helper vmgr' | grep -v grep | head -1)"; then
  if [[ -n "$ps_out" ]]; then
    echo "  vmgr:    $ps_out"
  else
    echo "  vmgr:    not running"
  fi
else
  echo "  vmgr:    unavailable (ps failed)"
fi

if [[ -f "$HOME/.orbstack/run/.update-pending" ]]; then
  echo "  update:  pending (~/.orbstack/run/.update-pending present)"
fi

echo
echo "Data image:"
if [[ -n "$DATA_IMG" ]]; then
  if stat_out="$(stat -f '%N %z bytes %Sm' "$DATA_IMG" 2>/dev/null)"; then
    echo "  $stat_out"
  else
    echo "  $DATA_IMG"
  fi
else
  echo "  not found under $GROUP_ROOT"
fi

echo
echo "Recent vmgr markers:"
if [[ -f "$VMGR_LOG" ]]; then
  markers="$(rg -n \
    'startup phase|container=fuzzer|container started|failed to add forward|proxy dialer did not pass back a connection|mm_receive_fd|Unknown Rosetta version|host-unix forward|update available' \
    "$VMGR_LOG" 2>/dev/null | tail -30)"
  if [[ -n "$markers" ]]; then
    # shellcheck disable=SC2001  # sed prefix-indent; ${var//...} can't do multiline prepend
    echo "$markers" | sed 's/^/  /'
  else
    echo "  (no matching markers)"
  fi
else
  echo "  vmgr log missing at $VMGR_LOG"
fi

echo
echo "Workarounds:"
echo "  1. If vmgr RSS is very large or orbctl says Stopped while vmgr is alive, fully quit and relaunch OrbStack."
echo "  2. If you see 'proxy dialer did not pass back a connection' or 'mm_receive_fd', restart OrbStack; if it persists, reboot macOS."
echo "  3. Findings normally survive control-plane failures because they live in the raw data image shown above."
echo "  4. After recovery, verify with:"
echo "     orb -m $ORB_VM ls -lah ~/fuzzing/targets/poppler/findings"
echo "     orb -m $ORB_VM ls -lah ~/fuzzing/targets/libvpx/findings"

echo
echo "=== end orb-debug ==="
