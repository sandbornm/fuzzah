#!/usr/bin/env bash
# Dashboard: counts of targets + triaged crashes + workflow state.
#
# Workflow state is read from each crash dir's `.status` file (one word):
#   new           — freshly triaged; human has not looked yet  (default if missing)
#   reviewed      — human confirmed it's worth chasing; needs fresh-build repro
#   repro-ok      — reproduced on fresh build; needs upstream bug report drafted
#   reported      — upstream issue filed; tracking only
#   dup | ignore  — noise or duplicate; not actionable
#
# Mark state manually, e.g.:
#   echo reviewed > ~/fuzzing/targets/<target>/crashes-triaged/<hash>/.status
set -uo pipefail

TARGETS_DIR="${TARGETS_DIR:-$HOME/fuzzing/targets}"

if [[ ! -d "$TARGETS_DIR" ]]; then
  echo "no targets dir at $TARGETS_DIR" >&2
  exit 1
fi

declare -A STATE_CRASHES  # "state|target|hash|top_frame|first_seen|hit" lines, indexed by state

total_targets=0
total_crashes=0
declare -A COUNT_BY_STATE

# Header
echo "=== Fuzz check-in @ $(date +'%Y-%m-%d %H:%M:%S') ==="
echo

# Per-target summary
printf '%-12s %-7s %-9s %-9s %-10s %-9s %-7s\n' \
  "target" "fuzzers" "execs/s" "crashes" "needs-rev" "repro?" "done"
printf '%-12s %-7s %-9s %-9s %-10s %-9s %-7s\n' \
  "------" "-------" "-------" "-------" "---------" "------" "----"

for tdir in "$TARGETS_DIR"/*/; do
  [[ -d "$tdir" ]] || continue
  target="$(basename "$tdir")"
  total_targets=$((total_targets + 1))

  n_fuzz=$(pgrep -fc "afl-fuzz.*targets/$target" 2>/dev/null || echo 0)

  # execs/sec via afl-whatsup
  execs=0
  if [[ -d "$tdir/findings" ]] && command -v "$HOME/fuzzing/tools/AFLplusplus/afl-whatsup" >/dev/null; then
    execs=$("$HOME/fuzzing/tools/AFLplusplus/afl-whatsup" -s "$tdir/findings" 2>/dev/null \
      | awk -F': *' '/Cumulative speed/ {gsub(/[^0-9].*/,"",$2); print $2; exit}' || echo 0)
    execs="${execs:-0}"
  fi

  triage_dir="$tdir/crashes-triaged"
  n_crashes=0; n_new=0; n_rev=0; n_repro=0; n_done=0
  if [[ -d "$triage_dir" ]]; then
    while IFS= read -r -d '' cd; do
      n_crashes=$((n_crashes + 1))
      status="new"
      [[ -s "$cd/.status" ]] && status="$(head -n1 "$cd/.status" | tr -d '[:space:]')"
      hash="$(basename "$cd")"
      top="?"; seen="?"; hit="?"
      if [[ -s "$cd/meta.json" ]] && command -v jq >/dev/null; then
        top="$(jq -r '.top_frame // "?"'   "$cd/meta.json" 2>/dev/null)"
        seen="$(jq -r '.first_seen // "?"' "$cd/meta.json" 2>/dev/null)"
        hit="$(jq -r '.hit_count // 0'     "$cd/meta.json" 2>/dev/null)"
      fi
      case "$status" in
        new)         n_new=$((n_new + 1)) ;;
        reviewed)    n_rev=$((n_rev + 1)) ;;
        repro-ok)    n_repro=$((n_repro + 1)) ;;
        reported)    n_done=$((n_done + 1)) ;;
        dup|ignore)  : ;;
        *)           n_new=$((n_new + 1)) ;;  # unknown → treat as new
      esac
      COUNT_BY_STATE[$status]=$(( ${COUNT_BY_STATE[$status]:-0} + 1 ))
      # Accumulate for later per-state listing. Pipe-delimited, skip 'done' states.
      if [[ "$status" != "reported" && "$status" != "dup" && "$status" != "ignore" ]]; then
        STATE_CRASHES[$status]+="$target|$hash|$top|$seen|$hit"$'\n'
      fi
    done < <(find "$triage_dir" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)
  fi
  total_crashes=$((total_crashes + n_crashes))

  printf '%-12s %-7s %-9s %-9s %-10s %-9s %-7s\n' \
    "$target" "$n_fuzz" "$execs" "$n_crashes" "$n_new" "$n_rev" "$n_done"
done

echo
echo "totals: $total_targets target(s), $total_crashes unique crash(es)"

render_state() {
  local state="$1" label="$2"
  local blob="${STATE_CRASHES[$state]:-}"
  [[ -z "$blob" ]] && { echo "  (none)"; return; }
  echo "$blob" | awk -F'|' 'NF>=5 {
    printf "  %-8s %-14s %-40s  hits=%s  seen=%s\n", $1, $2, substr($3,1,40), $5, $4
  }'
}

echo
echo "── Needs review (state: new) ─────────────────────────────────────────"
render_state new "new"

echo
echo "── Ready for repro verification (state: reviewed) ────────────────────"
render_state reviewed "reviewed"

echo
echo "── Ready for upstream report (state: repro-ok) ───────────────────────"
render_state repro-ok "repro-ok"

echo
echo "Mark a crash:"
echo "  echo <state> > ~/fuzzing/targets/<target>/crashes-triaged/<hash>/.status"
echo "  states: new | reviewed | repro-ok | reported | dup | ignore"
