#!/usr/bin/env bash
# shellcheck disable=SC2016
# Bootstrap a fresh macOS + OrbStack host for the fuzzah AFL++ lane.
#
# This sets up the shared fuzz host runtime only:
#   - OrbStack VM named fuzzer by default
#   - Ubuntu 24.04 by default
#   - ~/fuzzing/{tools,targets,logs}
#   - ~/fuzzing/tools/AFLplusplus
#   - ~/fuzzig-shared/{check-in,rig-check,fuzz-watchdog}.sh
#   - user systemd fuzz-watchdog.timer
#
# Target-specific setup remains separate: scaffold/sync/bootstrap each target
# after this script passes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VM_NAME="${ORB_VM:-fuzzer}"
DISTRO="${FUZZAH_ORB_DISTRO:-ubuntu:24.04}"
CPUS="${FUZZAH_ORB_CPUS:-10}"
MEMORY="${FUZZAH_ORB_MEMORY:-8G}"
DISK="${FUZZAH_ORB_DISK:-256G}"
VM_USER="${FUZZAH_ORB_USER:-${USER:-fuzzer}}"
BOOTSTRAP_ROOT="${FUZZAH_BOOTSTRAP_ROOT:-$HOME/fuzzig}"
REPO_URL="${FUZZAH_REPO_URL:-https://github.com/sandbornm/fuzzah.git}"
SKIP_CREATE=0
SKIP_AFL=0

if [[ ! -f "$REPO_ROOT/shared/check-in.sh" || ! -f "$REPO_ROOT/shared/fuzz-watchdog.sh" ]]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "[!] standalone bootstrap needs git to clone fuzzah" >&2
    exit 1
  fi
  clone_dir="$BOOTSTRAP_ROOT/fuzzah"
  mkdir -p "$BOOTSTRAP_ROOT"
  if [[ -d "$clone_dir/.git" ]]; then
    echo "[*] using existing fuzzah checkout: $clone_dir"
    git -C "$clone_dir" pull --ff-only || true
  else
    echo "[*] cloning fuzzah into $clone_dir"
    git clone "$REPO_URL" "$clone_dir"
  fi
  exec bash "$clone_dir/shared/setup-macos-orb.sh" "$@"
fi

usage() {
  cat <<EOF
usage: bash shared/setup-macos-orb.sh [options]

Bootstraps the base fuzzah runtime on a macOS host with OrbStack.

Options:
  --vm-name NAME     OrbStack machine name (default: $VM_NAME)
  --distro DISTRO    OrbStack distro image (default: $DISTRO)
  --cpus N           VM CPU limit (default: $CPUS)
  --memory SIZE      VM memory limit, e.g. 8G (default: $MEMORY)
  --disk SIZE        VM disk limit, e.g. 256G (default: $DISK)
  --user USER        Linux user inside the VM (default: $VM_USER)
  --skip-create      Do not create the VM; require it to already be reachable
  --skip-afl         Skip AFL++ clone/build, still install shared scripts
  -h, --help         Show this help

Environment overrides:
  ORB_VM, FUZZAH_ORB_DISTRO, FUZZAH_ORB_CPUS, FUZZAH_ORB_MEMORY,
  FUZZAH_ORB_DISK, FUZZAH_ORB_USER, FUZZAH_BOOTSTRAP_ROOT, FUZZAH_REPO_URL

Standalone use:
  curl -fsSL https://raw.githubusercontent.com/sandbornm/fuzzah/main/shared/setup-macos-orb.sh \\
    -o /tmp/setup-macos-orb.sh
  bash /tmp/setup-macos-orb.sh

After this passes, add targets with:
  bash shared/scaffold-target.sh <target>
  bash shared/bootstrap-target.sh <target>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm-name) VM_NAME="${2:?missing value for --vm-name}"; shift 2 ;;
    --distro) DISTRO="${2:?missing value for --distro}"; shift 2 ;;
    --cpus) CPUS="${2:?missing value for --cpus}"; shift 2 ;;
    --memory) MEMORY="${2:?missing value for --memory}"; shift 2 ;;
    --disk) DISK="${2:?missing value for --disk}"; shift 2 ;;
    --user) VM_USER="${2:?missing value for --user}"; shift 2 ;;
    --skip-create) SKIP_CREATE=1; shift ;;
    --skip-afl) SKIP_AFL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[!] unknown flag: $1" >&2; usage >&2; exit 2 ;;
  esac
done

step() {
  printf '\n==> %s\n' "$1"
}

die() {
  printf '[!] %s\n' "$1" >&2
  exit 1
}

sh_quote() {
  printf "'%s'" "${1//\'/\'\"\'\"\'}"
}

vm() {
  orb -m "$VM_NAME" bash -lc "$1"
}

wait_for_vm() {
  local tries="${1:-30}"
  local i
  for ((i = 1; i <= tries; i++)); do
    if vm 'true' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

require_macos_orb() {
  [[ "$(uname -s)" == "Darwin" ]] || die "setup-macos-orb.sh must run on macOS"
  command -v orb >/dev/null 2>&1 || die "missing orb CLI; install OrbStack first"
}

create_or_reuse_vm() {
  if wait_for_vm 1; then
    echo "[+] reusing reachable OrbStack VM: $VM_NAME"
    return 0
  fi

  if (( SKIP_CREATE )); then
    die "VM '$VM_NAME' is not reachable and --skip-create was set"
  fi

  echo "[*] creating OrbStack VM '$VM_NAME' ($DISTRO, cpus=$CPUS, memory=$MEMORY, disk=$DISK, user=$VM_USER)"
  local out rc
  set +e
  out="$(orb create --cpus "$CPUS" --memory "$MEMORY" --disk "$DISK" --user "$VM_USER" "$DISTRO" "$VM_NAME" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    printf '%s\n' "$out" >&2
    if printf '%s\n' "$out" | grep -Eiq 'already exists|exists|duplicate'; then
      die "VM '$VM_NAME' appears to exist but is not reachable. Fully quit/relaunch OrbStack, then rerun with --skip-create."
    fi
    die "orb create failed"
  fi

  wait_for_vm 60 || die "created VM '$VM_NAME' but it did not become reachable"
}

install_base_packages() {
  local packages=(
    build-essential
    clang
    llvm
    lld
    cmake
    ninja-build
    git
    python3
    python3-dev
    python3-venv
    automake
    autoconf
    libtool
    pkg-config
    libglib2.0-dev
    bison
    flex
    gdb
    jq
    nftables
    tmux
    curl
    wget
    ca-certificates
    xz-utils
    unzip
    zip
    rsync
    file
    xxd
  )
  local quoted=""
  local pkg
  for pkg in "${packages[@]}"; do
    quoted+=" $(printf '%q' "$pkg")"
  done
  vm "sudo env DEBIAN_FRONTEND=noninteractive apt-get update && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y$quoted"
}

prepare_runtime_dirs() {
  vm 'mkdir -p "$HOME/fuzzing/tools" "$HOME/fuzzing/targets" "$HOME/fuzzing/logs" "$HOME/fuzzig-shared" "$HOME/.config/systemd/user"'
}

install_aflpp() {
  (( SKIP_AFL )) && { echo "[*] skipping AFL++ build by request"; return 0; }
  vm 'set -euo pipefail
mkdir -p "$HOME/fuzzing/tools"
if [[ ! -d "$HOME/fuzzing/tools/AFLplusplus/.git" ]]; then
  git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git "$HOME/fuzzing/tools/AFLplusplus"
fi
if [[ ! -x "$HOME/fuzzing/tools/AFLplusplus/afl-fuzz" ]]; then
  make -C "$HOME/fuzzing/tools/AFLplusplus" distrib -j"$(nproc)"
else
  echo "[+] AFL++ already built"
fi'
}

install_shared_scripts() {
  local repo_q
  repo_q="$(sh_quote "$REPO_ROOT")"
  vm "set -euo pipefail
mkdir -p \"\$HOME/fuzzig-shared\" \"\$HOME/.config/systemd/user\" \"\$HOME/fuzzing/logs\" \"\$HOME/fuzzing/targets\"
cp $repo_q/shared/check-in.sh \"\$HOME/fuzzig-shared/\"
cp $repo_q/shared/rig-check.sh \"\$HOME/fuzzig-shared/\"
cp $repo_q/shared/fuzz-watchdog.sh \"\$HOME/fuzzig-shared/\"
chmod +x \"\$HOME/fuzzig-shared/\"*.sh
cp $repo_q/shared/fuzz-watchdog.service \"\$HOME/.config/systemd/user/\"
cp $repo_q/shared/fuzz-watchdog.timer \"\$HOME/.config/systemd/user/\"
sudo loginctl enable-linger \"\$USER\" >/dev/null 2>&1 || true
systemctl --user daemon-reload
systemctl --user enable --now fuzz-watchdog.timer"
}

smoke_test() {
  if (( SKIP_AFL )); then
    vm 'set -euo pipefail
echo "VM: $(hostname)"
cat /etc/os-release | sed -n "1,3p"
test -d "$HOME/fuzzing/targets"
test -x "$HOME/fuzzig-shared/check-in.sh"
systemctl --user is-active fuzz-watchdog.timer
echo LIVE_OK'
  else
    vm 'set -euo pipefail
echo "VM: $(hostname)"
cat /etc/os-release | sed -n "1,3p"
test -d "$HOME/fuzzing/targets"
test -x "$HOME/fuzzing/tools/AFLplusplus/afl-fuzz"
test -x "$HOME/fuzzig-shared/check-in.sh"
systemctl --user is-active fuzz-watchdog.timer
echo LIVE_OK'
  fi
  bash "$REPO_ROOT/shared/verify-setup.sh" --skip-live
}

main() {
  require_macos_orb
  echo "fuzzah repo: $REPO_ROOT"
  echo "control root: ${FUZZAH_CONTROL_ROOT:-$(cd "$REPO_ROOT/.." && pwd)}"

  step "1/6 create or reuse OrbStack VM"
  create_or_reuse_vm

  step "2/6 install base Ubuntu packages"
  install_base_packages

  step "3/6 create runtime directories"
  prepare_runtime_dirs

  step "4/6 clone/build AFL++"
  install_aflpp

  step "5/6 install shared scripts and watchdog"
  install_shared_scripts

  step "6/6 smoke test"
  smoke_test

  cat <<EOF

== setup complete ==

Next:
  bash shared/rig-check.sh
  bash shared/scaffold-target.sh <target>
  bash shared/bootstrap-target.sh <target>

For dashboard/email on this Mac:
  bash shared/crash-digest/install-macos.sh --dry-run
  bash shared/crash-digest/install-macos.sh --tailscale-serve
EOF
}

main "$@"
