#!/usr/bin/env bash
# Create or refresh a host-side editable target setup dir from target-template/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=shared/fuzzah-paths.sh
source "$SCRIPT_DIR/fuzzah-paths.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") [--force] <target>

Scaffolds:
  $(basename "$0") jq

env:
  FUZZAH_CONTROL_ROOT=/path/to/control-plane
EOF
}

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
  shift
fi

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="$1"
SETUP_ROOT="$(fuzzah_setup_root "$TARGET")"
SCRIPTS_DIR="$(fuzzah_scripts_dir "$TARGET")"

mkdir -p "$SETUP_ROOT" "$SCRIPTS_DIR"

copy_if_needed() {
  local src="$1" dst="$2"
  if [[ -e "$dst" && "$FORCE" != "1" ]]; then
    echo "[=] keep $dst"
    return 0
  fi
  cp "$src" "$dst"
  echo "[+] wrote $dst"
}

for src in "$FUZZAH_TEMPLATE_ROOT"/*.sh; do
  copy_if_needed "$src" "$SCRIPTS_DIR/$(basename "$src")"
done

shopt -s nullglob
for src in "$FUZZAH_TEMPLATE_ROOT"/*.dict; do
  copy_if_needed "$src" "$SCRIPTS_DIR/$(basename "$src")"
done
shopt -u nullglob

if [[ -f "$FUZZAH_TEMPLATE_ROOT/apt-packages.txt" ]]; then
  copy_if_needed "$FUZZAH_TEMPLATE_ROOT/apt-packages.txt" "$SCRIPTS_DIR/apt-packages.txt"
fi

SERVICE_TMP="$SCRIPTS_DIR/TARGET-fuzz.service"
copy_if_needed "$FUZZAH_TEMPLATE_ROOT/TARGET-fuzz.service" "$SERVICE_TMP"
TARGET_SERVICE="$SCRIPTS_DIR/${TARGET}-fuzz.service"
if [[ ! -e "$TARGET_SERVICE" || "$FORCE" == "1" ]]; then
  mv "$SERVICE_TMP" "$TARGET_SERVICE"
  sed -i.bak "s/<TARGET>/$TARGET/g" "$TARGET_SERVICE"
  rm -f "${TARGET_SERVICE}.bak"
  echo "[+] prepared $TARGET_SERVICE"
fi
rm -f "$SERVICE_TMP"

SETUP_DOC="$SETUP_ROOT/SETUP.md"
if [[ ! -e "$SETUP_DOC" || "$FORCE" == "1" ]]; then
  cp "$FUZZAH_TEMPLATE_ROOT/SETUP.md" "$SETUP_DOC"
  sed -i.bak \
    -e "s/<TARGET>/$TARGET/g" \
    -e "s/<target>/$TARGET/g" \
    "$SETUP_DOC"
  rm -f "${SETUP_DOC}.bak"
  echo "[+] wrote $SETUP_DOC"
else
  echo "[=] keep $SETUP_DOC"
fi

echo
echo "Control root: $FUZZAH_CONTROL_ROOT"
echo "Setup root:   $SETUP_ROOT"
