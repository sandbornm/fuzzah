#!/usr/bin/env bash
# rig-check.sh — system-domain health snapshot for the fuzz rig.
#
# Reports VM-side state that check-in.sh doesn't cover:
#   • VM memory & swap pressure
#   • Disk free
#   • systemd service + watchdog timer state
#   • fuzzer worker count per target (auto-discovered from ~/fuzzing/targets/*)
#   • OOM-kill events in dmesg (last N lines)
#   • Watchdog respawn rate (last 1h)
#   • Spurious SIGSEGV / unmapped kill events
#
# Portability: runs on a Mac host (proxies commands through `orb -m fuzzer`),
# on a Linux host with orb installed (same path), or directly inside the
# fuzzer VM (no proxy). Detection is automatic.
set -uo pipefail

# ── environment detection ───────────────────────────────────────────────────

UNAME_S="$(uname -s)"
IN_VM=0
# The in-VM layout convention: $HOME/fuzzing/targets/ exists.
if [[ "$UNAME_S" == "Linux" && -d "$HOME/fuzzing/targets" ]]; then
  IN_VM=1
fi

if (( IN_VM )); then
  HOST_TAG="vm-direct"
  vm()      { "$@"; }
  vm_sudo() { sudo "$@"; }
else
  HOST_TAG="host-via-orb"
  if ! command -v orb >/dev/null 2>&1; then
    echo "[!] neither inside the VM (no \$HOME/fuzzing/targets) nor able to find" >&2
    echo "    'orb' on PATH. Set ORB_VM to the VM name if you're on a host."     >&2
    exit 2
  fi
  ORB_VM="${ORB_VM:-fuzzer}"
  vm()      { orb -m "$ORB_VM" "$@"; }
  vm_sudo() { orb -m "$ORB_VM" sudo "$@"; }
fi

TS="$(date +'%Y-%m-%d %H:%M:%S %Z')"
echo "=== Rig health @ $TS  (host=$UNAME_S, mode=$HOST_TAG) ==="

# ── host-side preflight (only meaningful when not inside the VM) ────────────

if ! (( IN_VM )); then
  if orb list 2>/dev/null | awk -v v="${ORB_VM:-fuzzer}" '$1==v {found=1} END {exit !found}'; then
    vm_state="$(orb list 2>/dev/null | awk -v v="${ORB_VM:-fuzzer}" '$1==v {print $2}')"
    echo "VM:           orb machine \"${ORB_VM:-fuzzer}\" state=${vm_state:-unknown}"
  else
    echo "[!] orb machine \"${ORB_VM:-fuzzer}\" not found — rest of checks will fail" >&2
    exit 3
  fi
fi

# ── memory + swap ───────────────────────────────────────────────────────────

free_out="$(vm free -m 2>/dev/null | awk 'NR==2 {printf "total=%d used=%d free=%d available=%d", $2, $3, $4, $NF}')"
swap_out="$(vm free -m 2>/dev/null | awk 'NR==3 {printf "swap_total=%d swap_used=%d", $2, $3}')"
echo "Memory (MiB): $free_out  $swap_out"

avail="$(echo "$free_out" | grep -oE 'available=[0-9]+' | cut -d= -f2)"
if [[ -n "$avail" && "$avail" -lt 512 ]]; then
  echo "  [!] available memory < 512 MiB — VM is under pressure"
fi

# ── disk ────────────────────────────────────────────────────────────────────

disk_line="$(vm df -BG /home 2>/dev/null | awk 'NR==2 {printf "%s used=%s avail=%s (%s)", $1, $3, $4, $5}')"
echo "Disk (/home): $disk_line"
avail_gb="$(vm df -BG /home 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
if [[ -n "$avail_gb" && "$avail_gb" -lt 5 ]]; then
  echo "  [!] disk free < 5 GB — clean findings/ archives or extend VM storage"
fi

# ── discover targets from the filesystem ────────────────────────────────────

# Pick up any target dir the user has created. Names are derived from the
# directory listing (no hardcoded target list), so this script is target-
# agnostic — drop a new target in $HOME/fuzzing/targets/<name>/ and it works.
targets=()
while IFS= read -r t; do
  [[ -n "$t" ]] && targets+=("$t")
done < <(vm bash -c 'ls -1 $HOME/fuzzing/targets 2>/dev/null' | tr -d '\r')

# ── systemd unit state (derived from target names) ──────────────────────────

echo "Systemd:"
for t in "${targets[@]}"; do
  unit="${t}-fuzz.service"
  active="$(vm systemctl --user is-active "$unit" 2>/dev/null)"
  enabled="$(vm systemctl --user is-enabled "$unit" 2>/dev/null)"
  since="$(vm systemctl --user show "$unit" -p ActiveEnterTimestamp --value 2>/dev/null)"
  printf "  %-26s  active=%-8s  enabled=%-9s  since=%s\n" "$unit" "${active:-?}" "${enabled:-?}" "${since:-?}"
  if [[ "$active" != "active" ]]; then
    echo "  [!] $unit is not active"
  fi
done

# Shared watchdog (one unit for all targets).
unit="fuzz-watchdog.timer"
active="$(vm systemctl --user is-active "$unit" 2>/dev/null)"
enabled="$(vm systemctl --user is-enabled "$unit" 2>/dev/null)"
printf "  %-26s  active=%-8s  enabled=%-9s\n" "$unit" "${active:-?}" "${enabled:-?}"

# Watchdog timer next/last fire (best-effort; format varies by systemctl version).
wd_next="$(vm systemctl --user list-timers fuzz-watchdog.timer --no-pager 2>/dev/null | sed -n '2p')"
[[ -n "$wd_next" ]] && echo "  watchdog:  $wd_next"

# ── fuzzer worker count + uptime per target ────────────────────────────────

echo "Workers:"
for t in "${targets[@]}"; do
  pids="$(vm pgrep -f "[a]fl-fuzz.*targets/$t" 2>/dev/null)"
  n="$(echo "$pids" | grep -c '^[0-9]')"
  printf "  %-12s %d/3 alive" "$t" "$n"
  if [[ "$n" -lt 3 ]]; then
    printf "   [!] below expected"
  fi
  echo
  if [[ "$n" -gt 0 ]]; then
    for p in $pids; do
      args="$(vm ps -o args= -p "$p" 2>/dev/null)"
      role="$(echo "$args" | grep -oE -- '-[MS] [a-z]+' | awk '{print $2}')"
      m="$(echo "$args"   | grep -oE -- '-m [^ ]+' | head -1)"
      etime="$(vm ps -o etime= -p "$p" 2>/dev/null | tr -d ' ')"
      printf "    %-10s pid=%-8s etime=%-12s %s\n" "${role:-?}" "$p" "${etime:-?}" "${m:-?}"
    done
  fi
done

# ── OOM events in the dmesg ring (last 20 lines matching any target harness) ─

echo "OOM last (dmesg ring):"
# Build a grep pattern from the target names. A harness binary is usually
# named the same as the target, but targets can set HARNESS_NAME differently
# in their start-fuzz.sh; we match by target name in the kernel's command
# line for the OOM'd process, which is a reasonable proxy.
if (( ${#targets[@]} > 0 )); then
  pat="$(printf '%s|' "${targets[@]}" | sed 's/|$//')"
  oom_lines="$(vm_sudo dmesg -T 2>/dev/null | grep -iE 'killed process' | grep -iE "($pat)" | tail -10)"
else
  oom_lines="$(vm_sudo dmesg -T 2>/dev/null | grep -iE 'killed process' | tail -10)"
fi
oom_count="$(echo "$oom_lines" | awk 'NF' | wc -l)"
if [[ "$oom_count" -eq 0 ]]; then
  echo "  (none detected)"
else
  echo "$oom_lines" | sed 's/^/  /'
  if [[ "$oom_count" -ge 5 ]]; then
    echo "  [!] $oom_count OOM kills in dmesg ring — check whether -m caps are missing on any fuzzer / afl-tmin invocation"
  fi
fi

# ── watchdog respawn activity (last 1h) ─────────────────────────────────────

wd_log="$HOME/fuzzing/logs/watchdog.log"
if vm test -f "$wd_log" 2>/dev/null; then
  cutoff="$(date -d '1 hour ago' -Iseconds 2>/dev/null || date -v-1H -Iseconds 2>/dev/null)"
  respawns="$(vm awk -v cut="$cutoff" '$2 > cut && /relaunched role/ {n++} END {print n+0}' "$wd_log" 2>/dev/null)"
  echo "Watchdog respawns last 1h: ${respawns:-0}"
  if [[ -n "$respawns" && "$respawns" -gt 10 ]]; then
    echo "  [!] high respawn rate — investigate flap loop"
  fi
else
  echo "Watchdog respawns last 1h: (log file absent)"
fi

# ── spurious SIGSEGV: kernel saw a segv that wasn't a fuzzer child ─────────

# A real fuzzer-child crash is expected. Anything else (segv in afl-fuzz
# itself, the triage loop, a random VM daemon) is worth surfacing.
if (( ${#targets[@]} > 0 )); then
  pat="$(printf '%s|' "${targets[@]}" | sed 's/|$//')"
  spurious="$(vm_sudo dmesg -T 2>/dev/null | grep -iE 'segfault|general protection' | grep -viE "($pat)" | tail -5)"
else
  spurious="$(vm_sudo dmesg -T 2>/dev/null | grep -iE 'segfault|general protection' | tail -5)"
fi
if [[ -n "$spurious" ]]; then
  echo "Spurious kernel signals:"
  echo "$spurious" | sed 's/^/  /'
else
  echo "Spurious kernel signals: none"
fi

echo "=== end rig-check ==="
