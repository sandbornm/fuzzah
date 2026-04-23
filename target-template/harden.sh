#!/usr/bin/env bash
# One-time host hardening for the fuzz host/VM:
#   - install required CLI tools (jq, gdb, nftables, tmux)
#   - set kernel.core_pattern to "core"   (AFL++ requirement)
#   - set cpufreq governor to "performance" (if sysfs writable)
#   - optional: apply nftables egress block (pass --block-egress)
#
# Idempotent. Safe to rerun after reboots or host restarts.
#
# Target-agnostic: derives $TARGET_DIR from the script's filesystem location
# ($HOME/fuzzing/targets/<target>/scripts/ → $HOME/fuzzing/targets/<target>/).
set -euo pipefail

BLOCK_EGRESS=0
for arg in "$@"; do
  case "$arg" in
    --block-egress) BLOCK_EGRESS=1 ;;
    --unblock-egress) BLOCK_EGRESS=-1 ;;
    -h|--help)
      cat <<EOF
usage: $0 [--block-egress] [--unblock-egress]
  --block-egress      apply nftables rules that drop outbound except loopback
  --unblock-egress    flush the fuzz nftables table
EOF
      exit 0
      ;;
    *) echo "[!] unknown arg: $arg" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
mkdir -p "$TARGET_DIR/logs" "$TARGET_DIR/findings" "$TARGET_DIR/crashes-triaged"

echo "[=] ensuring apt packages"
MISSING=()
for pkg in jq gdb nftables tmux; do
  dpkg -s "$pkg" >/dev/null 2>&1 || MISSING+=("$pkg")
done
if (( ${#MISSING[@]} > 0 )); then
  echo "    installing: ${MISSING[*]}"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}" >/dev/null
fi

echo "[=] core_pattern"
current_cp="$(cat /proc/sys/kernel/core_pattern)"
if [[ "$current_cp" != "core" ]]; then
  echo "core" | sudo tee /proc/sys/kernel/core_pattern >/dev/null
  echo "    was '$current_cp', now 'core'"
else
  echo "    already 'core'"
fi

echo "[=] cpufreq governor"
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [[ -w "$g" ]] || { echo "    $g not writable, skipping"; break; }
  cur="$(cat "$g")"
  if [[ "$cur" != "performance" ]]; then
    echo "performance" | sudo tee "$g" >/dev/null 2>&1 || true
  fi
done
echo "    set where writable (orb VMs often block this — AFL_SKIP_CPUFREQ=1 is set anyway)"

if (( BLOCK_EGRESS == 1 )); then
  echo "[=] applying nftables egress block (fuzz_egress table)"
  sudo nft -f - <<'EOF'
table inet fuzz_egress
delete table inet fuzz_egress
table inet fuzz_egress {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    udp dport 53 accept
  }
}
EOF
  echo "    applied. To undo: $0 --unblock-egress"
elif (( BLOCK_EGRESS == -1 )); then
  echo "[=] flushing nftables fuzz_egress table"
  sudo nft delete table inet fuzz_egress 2>/dev/null || echo "    (table not present)"
else
  echo "[=] egress block NOT applied (pass --block-egress to enable before a run)"
fi

echo
echo "=== harden done ==="
mem_gb=$(awk '/MemTotal/ { printf "%.1fG", $2/1024/1024 }' /proc/meminfo)
afl_status=MISSING
[[ -x "$HOME/fuzzing/tools/AFLplusplus/afl-fuzz" ]] && afl_status=present
echo "Host:  $(nproc) cores, ${mem_gb} RAM"
echo "AFL++: $afl_status  (install into \$HOME/fuzzing/tools/AFLplusplus if MISSING)"
