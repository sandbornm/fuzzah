#!/usr/bin/env bash
# inspect-target.sh — summarize a target setup and flag obvious placeholders.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=shared/fuzzah-paths.sh
source "$SCRIPT_DIR/fuzzah-paths.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") <target>

Examples:
  $(basename "$0") jq
  $(basename "$0") jq-filter
EOF
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
TARGET="$1"
SETUP_ROOT="$(fuzzah_setup_root "$TARGET")"
SCRIPTS_DIR="$(fuzzah_scripts_dir "$TARGET")"

[[ -d "$SETUP_ROOT" ]] || { echo "[!] missing setup root: $SETUP_ROOT" >&2; exit 1; }
[[ -d "$SCRIPTS_DIR" ]] || { echo "[!] missing scripts dir: $SCRIPTS_DIR" >&2; exit 1; }

strip_assignment() {
  local file="$1" key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      sub(/^[[:space:]]+/, "", $2)
      sub(/^"/, "", $2)
      sub(/"$/, "", $2)
      print $2
      exit
    }
  ' "$file"
}

normalize_value() {
  local value="$1"
  if [[ "$value" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.*)\}$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  printf '%s\n' "$value"
}

list_array_entries() {
  local file="$1" name="$2"
  awk -v name="$name" '
    function flush_quotes(line) {
      while (match(line, /"[^"]+"/)) {
        s = substr(line, RSTART + 1, RLENGTH - 2)
        print s
        line = substr(line, RSTART + RLENGTH)
      }
    }
    $0 ~ ("^" name "=\\(") {
      in_array=1
      line=$0
      sub("^" name "=\\(", "", line)
      if (line ~ /\)[[:space:]]*$/) {
        sub(/\)[[:space:]]*$/, "", line)
        flush_quotes(line)
        exit
      }
      flush_quotes(line)
      next
    }
    in_array {
      line=$0
      if (line ~ /\)[[:space:]]*$/) {
        sub(/\)[[:space:]]*$/, "", line)
        flush_quotes(line)
        exit
      }
      flush_quotes(line)
    }
  ' "$file"
}

array_length() {
  local name="$1"
  local len=0
  if ! declare -p "$name" >/dev/null 2>&1; then
    printf '0\n'
    return 0
  fi
  eval "len=\${#$name[@]}"
  printf '%s\n' "$len"
}

print_array() {
  local prefix="$1" name="$2"
  local len i item
  len="$(array_length "$name")"
  if (( len == 0 )); then
    echo "  $prefix: (none)"
    return 0
  fi
  echo "  $prefix:"
  for ((i = 0; i < len; i++)); do
    eval "item=\${$name[$i]}"
    echo "    - $item"
  done
}

read_into_array() {
  local __name="$1"
  shift
  local __out
  local __line
  eval "$__name=()"
  __out="$("$@" || true)"
  while IFS= read -r __line; do
    [[ -n "$__line" ]] || continue
    eval "$__name+=(\"\$__line\")"
  done <<< "$__out"
}

START_SH="$SCRIPTS_DIR/start-fuzz.sh"
FETCH_SH="$SCRIPTS_DIR/fetch-seeds.sh"
FILTER_SH="$SCRIPTS_DIR/filter-seeds.sh"
BUILD_SH="$SCRIPTS_DIR/build-afl-fast.sh"
DICT_FILE="$SCRIPTS_DIR/${TARGET}.dict"
SERVICE_FILE="$SCRIPTS_DIR/${TARGET}-fuzz.service"
APT_FILE="$SCRIPTS_DIR/apt-packages.txt"
SETUP_DOC="$SETUP_ROOT/SETUP.md"

HARNESS_SUBPATH="$(strip_assignment "$START_SH" HARNESS_SUBPATH || true)"
HARNESS_ARGS="$(strip_assignment "$START_SH" HARNESS_ARGS || true)"
SRC_GIT_URL="$(strip_assignment "$BUILD_SH" SRC_GIT_URL || true)"
SRC_GIT_REF="$(strip_assignment "$BUILD_SH" SRC_GIT_REF || true)"

HARNESS_SUBPATH="$(normalize_value "$HARNESS_SUBPATH")"
HARNESS_ARGS="$(normalize_value "$HARNESS_ARGS")"
SRC_GIT_URL="$(normalize_value "$SRC_GIT_URL")"
SRC_GIT_REF="$(normalize_value "$SRC_GIT_REF")"

read_into_array SOURCES list_array_entries "$FETCH_SH" SOURCES
read_into_array VALID_EXTENSIONS list_array_entries "$FILTER_SH" VALID_EXTENSIONS
read_into_array VALID_MAGIC list_array_entries "$FILTER_SH" VALID_MAGIC_HEX
read_into_array APT_PACKAGES awk 'NF && $1 !~ /^#/' "$APT_FILE"
PLACEHOLDERS=()
if [[ "${SRC_GIT_URL:-}" == *REPLACE_WITH* || "${SRC_GIT_URL:-}" == *REPLACE_ME* ]]; then
  PLACEHOLDERS+=("build-afl-fast.sh: SRC_GIT_URL still has a placeholder")
fi
if [[ "${SRC_GIT_REF:-}" == *REPLACE_WITH* || "${SRC_GIT_REF:-}" == *REPLACE_ME* ]]; then
  PLACEHOLDERS+=("build-afl-fast.sh: SRC_GIT_REF still has a placeholder")
fi
for ((i = 0; i < $(array_length SOURCES); i++)); do
  eval "source=\${SOURCES[$i]}"
  if [[ "$source" == *REPLACE_WITH* || "$source" == *REPLACE_ME* ]]; then
    PLACEHOLDERS+=("fetch-seeds.sh: SOURCES contains a placeholder entry: $source")
  fi
done
for ((i = 0; i < $(array_length VALID_EXTENSIONS); i++)); do
  eval "ext=\${VALID_EXTENSIONS[$i]}"
  if [[ "$ext" == *REPLACE_WITH* || "$ext" == *REPLACE_ME* ]]; then
    PLACEHOLDERS+=("filter-seeds.sh: VALID_EXTENSIONS contains a placeholder entry: $ext")
  fi
done
for ((i = 0; i < $(array_length VALID_MAGIC); i++)); do
  eval "magic=\${VALID_MAGIC[$i]}"
  if [[ "$magic" == *REPLACE_WITH* || "$magic" == *REPLACE_ME* ]]; then
    PLACEHOLDERS+=("filter-seeds.sh: VALID_MAGIC_HEX contains a placeholder entry: $magic")
  fi
done
if [[ -f "$SETUP_DOC" ]]; then
  while IFS= read -r line; do
    PLACEHOLDERS+=("$line")
  done < <(rg -n '<URL>|<path-to-binary>|REPLACE_WITH|REPLACE_ME' "$SETUP_DOC" || true)
fi

echo "=== target inspect: $TARGET ==="
echo "  setup root:    $SETUP_ROOT"
echo "  scripts dir:   $SCRIPTS_DIR"
echo "  setup doc:     $SETUP_DOC"
echo "  service file:  $SERVICE_FILE"
echo
echo "Build:"
echo "  repo:          ${SRC_GIT_URL:-?}"
echo "  ref:           ${SRC_GIT_REF:-default-branch}"
echo "  harness path:  ${HARNESS_SUBPATH:-?}"
echo "  harness args:  ${HARNESS_ARGS:-?}"
echo
echo "Seeds:"
print_array "sources" SOURCES
print_array "extensions" VALID_EXTENSIONS
if (( $(array_length VALID_MAGIC) == 0 )); then
  echo "  magic bytes:   disabled"
else
  print_array "magic bytes" VALID_MAGIC
fi
echo
echo "Dictionary:"
if [[ -f "$DICT_FILE" ]]; then
  echo "  local dict:    $DICT_FILE"
else
  echo "  local dict:    (none)"
fi
echo
echo "Packages:"
print_array "apt" APT_PACKAGES
echo
echo "Readiness:"
if (( $(array_length PLACEHOLDERS) == 0 )); then
  echo "  placeholders:  none found"
else
  echo "  placeholders:"
  for ((i = 0; i < $(array_length PLACEHOLDERS); i++)); do
    eval "item=\${PLACEHOLDERS[$i]}"
    echo "    - $item"
  done
fi
echo
echo "Safe to commit:"
echo "  - SETUP.md"
echo "  - scripts/*.sh"
echo "  - scripts/*.dict"
echo "  - scripts/*-fuzz.service"
echo "  - scripts/apt-packages.txt"
echo "Do not commit:"
echo "  - src/"
echo "  - build-afl*/"
echo "  - seeds/raw or seeds/corpus.min if they are large/generated"
echo "  - findings/ or crashes-triaged/"
echo "=== end inspect ==="
