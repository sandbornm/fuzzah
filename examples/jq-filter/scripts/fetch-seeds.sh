#!/usr/bin/env bash
# Fetch seed corpora into seeds/raw/<source>/. Each source is one public repo
# (cloned shallow) or URL. filter-seeds.sh then cleans/dedupes the union.
#
# EDIT THIS PER TARGET: populate the SOURCES array with git URLs that contain
# valid sample inputs for your harness.
#
# Idempotent: re-running updates existing clones.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(dirname "$SCRIPT_DIR")}"
MAX_SIZE="${MAX_SIZE:-200k}"
SCRATCH="${SCRATCH:-/tmp/${USER}-$(basename "$TARGET_DIR")-seed-scratch}"

mkdir -p "$TARGET_DIR/seeds/raw"
mkdir -p "$SCRATCH"

# ── EDIT PER TARGET ─────────────────────────────────────────────────────────
# Each entry is: <label>|<git url>|<extension to collect>
#
# Examples (replace these with target-appropriate sources):
#   upstream-tests|https://github.com/acme/acme.git|png
#   sample-files|https://github.com/some/corpus.git|bin
#
# Tip: prefer 2–5 distinct projects with genuinely different input styles.
# Diversity matters more than volume.
SOURCES=(
  "jq-upstream|https://github.com/jqlang/jq.git|jq"
  "gojq|https://github.com/itchyny/gojq.git|jq"
  "jaq|https://github.com/01mf02/jaq.git|jq"
)
# ────────────────────────────────────────────────────────────────────────────

clone_or_update() {
  local url="$1" dest="$2" depth="${3:-1}"
  if [[ -d "$dest/.git" ]]; then
    echo "[=] updating $dest"
    git -C "$dest" fetch --depth="$depth" origin >/dev/null 2>&1 || true
  else
    echo "[+] cloning $url -> $dest"
    git clone --depth="$depth" "$url" "$dest"
  fi
}

# Walk src_dir, copy every file matching *.ext under MAX_SIZE into raw/<label>/.
collect() {
  local src_dir="$1" label="$2" ext="$3"
  local raw="$TARGET_DIR/seeds/raw/$label"
  rm -rf "$raw"
  mkdir -p "$raw"
  local count=0
  while IFS= read -r -d '' f; do
    local base out
    base="$(basename "$f")"
    out="$raw/$base"
    if [[ -e "$out" ]]; then
      out="$raw/$count-$base"
    fi
    cp "$f" "$out"
    count=$((count + 1))
  done < <(find "$src_dir" -type f -iname "*.$ext" -size "-$MAX_SIZE" -print0)
  echo "[=] $label: $count file(s) with ext=.$ext (<= $MAX_SIZE)"
}

write_curated_filters() {
  local raw="$TARGET_DIR/seeds/raw/curated"
  rm -rf "$raw"
  mkdir -p "$raw"

  cat > "$raw/identity.jq" <<'EOF'
.
EOF
  cat > "$raw/field.jq" <<'EOF'
.foo
EOF
  cat > "$raw/select.jq" <<'EOF'
select(type == "object")
EOF
  cat > "$raw/map_values.jq" <<'EOF'
map_values(type)
EOF
  cat > "$raw/reduce.jq" <<'EOF'
reduce .[] as $x (0; . + $x)
EOF
  cat > "$raw/paths.jq" <<'EOF'
paths
EOF
  cat > "$raw/trycatch.jq" <<'EOF'
try .foo catch .
EOF
  cat > "$raw/def.jq" <<'EOF'
def f: . + 1; f
EOF
  cat > "$raw/interp.jq" <<'EOF'
"\(.foo)"
EOF
  cat > "$raw/update.jq" <<'EOF'
.foo |= tonumber?
EOF

  echo "[=] curated: $(find "$raw" -type f | wc -l | tr -d ' ') handwritten filter seed(s)"
}

for entry in "${SOURCES[@]}"; do
  IFS='|' read -r label url ext <<< "$entry"
  if [[ "$label" == "REPLACE_ME" ]]; then
    echo "[!] fetch-seeds.sh has placeholder sources — edit the SOURCES array" >&2
    exit 1
  fi
  clone_or_update "$url" "$SCRATCH/$label"
  collect "$SCRATCH/$label" "$label" "$ext"
done

write_curated_filters

echo
echo "=== fetch summary ==="
find "$TARGET_DIR/seeds/raw" -maxdepth 2 -mindepth 2 -type d | while read -r d; do
  printf "  %-40s %s files\n" "${d#$TARGET_DIR/seeds/raw/}" "$(find "$d" -type f | wc -l)"
done
echo
echo "Next: bash $SCRIPT_DIR/filter-seeds.sh"
