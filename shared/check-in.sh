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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ON_FUZZ_HOST="$SCRIPT_DIR/run-on-fuzz-host.sh"
SELF_PATH="$SCRIPT_DIR/$(basename "$0")"
HOST_TARGETS_ROOT="${FUZZAH_HOST_TARGETS_ROOT:-$HOME/fuzzing-mac/targets}"

# ADDITIVE: macOS-host (jackalope) targets live on the local fs (no VM). They
# expose a normalized findings/stats.json instead of AFL's fuzzer_stats. This
# prints a dashboard section for them; it is a no-op when there are no such
# targets, so the VM-only output is unchanged.
print_host_targets_section() {
  local hroot="$HOST_TARGETS_ROOT"
  [[ -d "$hroot" ]] || return 0

  local tdir found=0
  for tdir in "$hroot"/*/; do
    [[ -d "$tdir" && -f "$tdir/engine" ]] || continue
    found=1; break
  done
  [[ "$found" == "1" ]] || return 0

  echo
  echo "── macOS-host targets (jackalope) ────────────────────────────────────"
  printf '%-12s %-7s %-9s %-9s %-10s %-9s\n' \
    "target" "alive" "execs/s" "corpus" "coverage" "crashes"
  printf '%-12s %-7s %-9s %-9s %-10s %-9s\n' \
    "------" "-----" "-------" "------" "--------" "-------"

  for tdir in "$hroot"/*/; do
    [[ -d "$tdir" && -f "$tdir/engine" ]] || continue
    local target stats alive eps corpus cov tcrashes
    target="$(basename "$tdir")"
    stats="$tdir/findings/stats.json"
    alive="no-stats"; eps="0"; corpus="0"; cov="0"
    if [[ -s "$stats" ]]; then
      if command -v jq >/dev/null 2>&1; then
        alive="$(jq -r 'if .alive then "yes" else "no" end' "$stats" 2>/dev/null || echo '?')"
        eps="$(jq -r '.execs_per_sec // 0'  "$stats" 2>/dev/null || echo 0)"
        corpus="$(jq -r '.corpus_count // 0' "$stats" 2>/dev/null || echo 0)"
        cov="$(jq -r '.coverage // 0'        "$stats" 2>/dev/null || echo 0)"
      else
        # python3 fallback (system interpreter; avoids the uv PATH shim).
        local py; py="$(command -v /usr/bin/python3 || command -v python3 || true)"
        if [[ -n "$py" ]]; then
          read -r alive eps corpus cov < <("$py" - "$stats" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
print("yes" if d.get("alive") else "no",
      int(d.get("execs_per_sec") or 0),
      int(d.get("corpus_count") or 0),
      int(d.get("coverage") or 0))
PY
)
        fi
      fi
    fi
    tcrashes=0
    if [[ -d "$tdir/crashes-triaged" ]]; then
      tcrashes="$(find "$tdir/crashes-triaged" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    fi
    printf '%-12s %-7s %-9s %-9s %-10s %-9s\n' \
      "$target" "$alive" "$eps" "$corpus" "$cov" "$tcrashes"
  done
}

if [[ "$(uname -s)" != "Linux" || ! -d "$HOME/fuzzing" ]]; then
  # VM dashboard first (unchanged) — then append the macOS-host section.
  "$RUN_ON_FUZZ_HOST" \
    "if [[ -f \"$SELF_PATH\" ]]; then bash \"$SELF_PATH\"; else bash \"\$HOME/fuzzig-shared/check-in.sh\"; fi"
  print_host_targets_section
  exit 0
fi

TARGETS_DIR="${TARGETS_DIR:-$HOME/fuzzing/targets}"
if [[ ! -d "$TARGETS_DIR" ]]; then
  echo "=== Fuzz check-in @ $(date +'%Y-%m-%d %H:%M:%S') ==="
  echo
  echo "no targets yet under $TARGETS_DIR"
  exit 0
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

  # Engine for this VM target (default afl). A fuzzilli target sources its row
  # from findings/stats.json (handled after the AFL reads below) rather than
  # fuzzer_stats; afl targets are unaffected.
  engine="afl"
  [[ -r "$tdir/engine" ]] && engine="$(tr -d '[:space:]' < "$tdir/engine" 2>/dev/null | head -c 64)"

  # Count live fuzzers by reading fuzzer_pid from each fuzzer_stats file and
  # probing it with kill -0. pgrep counts processes by pattern but can't
  # distinguish stale fuzzer_stats files left behind by a crashed afl-fuzz
  # from truly running ones — regression seen 2026-04-23 poppler outage where
  # crashed workers left stale stats and over-reported fuzzers alive.
  n_fuzz=0
  if [[ -d "$tdir/findings" ]]; then
    while IFS= read -r stats; do
      pid="$(awk '/^fuzzer_pid/ {print $3; exit}' "$stats" 2>/dev/null)"
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        n_fuzz=$((n_fuzz + 1))
      fi
    done < <(find "$tdir/findings" -maxdepth 2 -name "fuzzer_stats" 2>/dev/null)
  fi

  # execs/sec via afl-whatsup
  execs=0
  if [[ -d "$tdir/findings" ]] && command -v "$HOME/fuzzing/tools/AFLplusplus/afl-whatsup" >/dev/null; then
    execs=$("$HOME/fuzzing/tools/AFLplusplus/afl-whatsup" -s "$tdir/findings" 2>/dev/null \
      | awk -F': *' '/Cumulative speed/ {gsub(/[^0-9].*/,"",$2); print $2; exit}' || true)
    execs="$(printf '%s' "$execs" | tr -cd '0-9')"
    execs="${execs:-0}"
  fi
  if [[ "${execs:-0}" == "0" && -d "$tdir/findings" ]]; then
    # Some dumb-mode targets synthesize minimal fuzzer_stats files for the
    # dashboard even when afl-whatsup cannot infer a cumulative speed from the
    # nonstandard output layout. Only count stats for live PIDs.
    stats_execs=0
    while IFS= read -r stats; do
      pid="$(awk '/^fuzzer_pid/ {print $3; exit}' "$stats" 2>/dev/null)"
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        eps="$(awk '/^execs_per_sec/ {printf "%d", $3 + 0; exit}' "$stats" 2>/dev/null)"
        stats_execs=$((stats_execs + ${eps:-0}))
      fi
    done < <(find "$tdir/findings" -maxdepth 2 -name "fuzzer_stats" 2>/dev/null)
    if (( stats_execs > 0 )); then
      execs="$stats_execs"
    fi
  fi

  # ADDITIVE: a VM target with engine=fuzzilli carries a normalized
  # findings/stats.json (engine/alive/execs_per_sec/...) instead of AFL
  # fuzzer_stats, so the reads above found nothing for it. Source its live-fuzzer
  # count + execs/s from stats.json here. afl targets keep the fuzzer_stats /
  # afl-whatsup numbers computed above. If stats.json doesn't exist yet (the
  # adapter is still warming up) the row stays 0/0 — i.e. calibrating/empty.
  if [[ "$engine" == "fuzzilli" && -s "$tdir/findings/stats.json" ]]; then
    fstats="$tdir/findings/stats.json"
    f_alive="no"; f_eps="0"
    if command -v jq >/dev/null 2>&1; then
      f_alive="$(jq -r 'if .alive then "yes" else "no" end' "$fstats" 2>/dev/null || echo no)"
      f_eps="$(jq -r '(.execs_per_sec // 0) | floor' "$fstats" 2>/dev/null || echo 0)"
    else
      py="$(command -v /usr/bin/python3 || command -v python3 || true)"
      if [[ -n "$py" ]]; then
        read -r f_alive f_eps < <("$py" - "$fstats" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
print("yes" if d.get("alive") else "no", int(d.get("execs_per_sec") or 0))
PY
)
      fi
    fi
    f_eps="$(printf '%s' "$f_eps" | tr -cd '0-9')"; f_eps="${f_eps:-0}"
    n_fuzz=0; [[ "$f_alive" == "yes" ]] && n_fuzz=1
    execs="$f_eps"
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
  local state="$1"
  local blob="${STATE_CRASHES[$state]:-}"
  [[ -z "$blob" ]] && { echo "  (none)"; return; }
  echo "$blob" | awk -F'|' 'NF>=5 {
    printf "  %-8s %-14s %-40s  hits=%s  seen=%s\n", $1, $2, substr($3,1,40), $5, $4
  }'
}

echo
echo "── Needs review (state: new) ─────────────────────────────────────────"
render_state new

echo
echo "── Ready for repro verification (state: reviewed) ────────────────────"
render_state reviewed

echo
echo "── Ready for upstream report (state: repro-ok) ───────────────────────"
render_state repro-ok

echo
echo "Mark a crash:"
echo "  echo <state> > ~/fuzzing/targets/<target>/crashes-triaged/<hash>/.status"
echo "  states: new | reviewed | repro-ok | reported | dup | ignore"
