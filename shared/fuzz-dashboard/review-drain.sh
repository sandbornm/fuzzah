#!/usr/bin/env bash
# Manual crash-review worker. Drains crashes in state `review-requested`,
# dedupes by top_frame, runs a READ-ONLY claude review per unique frame, and
# (this script — never the agent) writes REVIEW.md + a ledger row + flips
# same-frame .status -> reviewed. Runs from the control host (Mac/Linux);
# reaches the fuzz host via run-on-fuzz-host.sh.
#
# Frame dedup happens in the VM-side python pass (one canonical hash per
# frame), so this script needs no associative arrays / mapfile and runs fine
# under the macOS system bash 3.2.
#
# usage: review-drain.sh [--force] [--dry-run] <target>
#   --force     re-review frames that already have a REVIEW.md
#   --dry-run   list what would be reviewed; run no agent, write nothing
# env: REVIEW_MODEL (default: sonnet; set REVIEW_MODEL=opus to escalate a tricky frame)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"           # fuzzah repo root
RUN="$ROOT/shared/run-on-fuzz-host.sh"
MODEL="${REVIEW_MODEL:-sonnet}"
FORCE=0; DRY=0
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --force) FORCE=1;; --dry-run) DRY=1;;
    *) echo "unknown flag $1" >&2; exit 2;;
  esac; shift
done
TARGET="${1:-}"; [[ -n "$TARGET" ]] || { echo "usage: review-drain.sh [--force] [--dry-run] <target>" >&2; exit 2; }
CT="\$HOME/fuzzing/targets/$TARGET/crashes-triaged"
LEDGER="$CT/reviews-ledger.tsv"

# One python pass on the VM: dedupe crashes in state review-requested by
# top_frame, pick the highest-hits hash per frame, and report whether the
# frame already has a REVIEW.md anywhere. Emits: frame<TAB>hash<TAB>reviewed(Y/N)
FRAMES=()
while IFS= read -r line; do
  [[ -n "$line" ]] && FRAMES+=("$line")
done < <(bash "$RUN" "
cd $CT 2>/dev/null || exit 0
python3 - <<'PY'
import json, os, re
best = {}        # frame -> (hits, hash)
reviewed = set() # frames that already have a REVIEW.md
def status_of(path):
    try:
        return open(path).read().strip().split()[0]
    except (OSError, IndexError):
        return 'new'
for h in sorted(d for d in os.listdir('.') if re.fullmatch(r'[0-9a-f]{12}', d) and os.path.isdir(d)):
    st = status_of(h+'/.status')
    if st != 'review-requested':
        continue
    tf, hits = '?', 0
    try:
        m = json.load(open(h+'/meta.json')); tf = m.get('top_frame') or m.get('signature') or '?'; hits = int(m.get('hit_count',0) or 0)
    except Exception:
        pass
    if os.path.exists(h+'/REVIEW.md'):
        reviewed.add(tf)
    if tf not in best or hits > best[tf][0]:
        best[tf] = (hits, h)
for tf, (hits, h) in best.items():
    print('%s\t%s\t%s' % (tf, h, 'Y' if tf in reviewed else 'N'))
PY
")

[[ ${#FRAMES[@]} -gt 0 ]] || { echo "[=] nothing in state review-requested for $TARGET"; exit 0; }

total_cost=0; reviewed=0
for line in "${FRAMES[@]}"; do
  IFS=$'\t' read -r tf h hr <<<"$line"
  if [[ "$hr" == "Y" && $FORCE -eq 0 ]]; then
    echo "[=] skip frame '$tf' (already reviewed; --force to redo)"; continue
  fi
  if [[ $DRY -eq 1 ]]; then
    echo "[dry] would review frame '$tf' via canonical hash $h (model=$MODEL)"; continue
  fi
  echo "[*] reviewing frame '$tf' (hash $h, model $MODEL) ..."
  prompt="You are doing a focused, READ-ONLY crash review for target $TARGET, crash $h, top frame $tf. Do not modify, create, or delete any files; return the review as your final message only. Read the trace + meta + relevant source on the fuzz host using: bash shared/run-on-fuzz-host.sh '<cmd>' (e.g. cat \$HOME/fuzzing/targets/$TARGET/crashes-triaged/$h/trace.txt ; cat .../meta.json ; grep -rn \"$tf\" \$HOME/fuzzing/targets/$TARGET/src --include=*.cc --include=*.h | head ; sed -n ranges of the source). Derive the root cause from the source. Output tight markdown (~250-400 words) with sections: Summary; Root cause (file:line); Classification (bug class, severity, exploitability); Real bug or noise?; Confidence."
  json="$(cd "$ROOT" && claude -p "$prompt" --model "$MODEL" --output-format json --permission-mode bypassPermissions </dev/null)" || { echo "[!] claude failed for $tf" >&2; continue; }

  # Extract fields with python (stdlib json), from the JSON on stdin.
  read -r cost tin tout secs < <(printf '%s' "$json" | python3 -c '
import json,sys
d=json.load(sys.stdin); u=d.get("usage",{})
print(d.get("total_cost_usd",0), u.get("input_tokens",0), u.get("output_tokens",0), int(d.get("duration_ms",0)/1000))')
  body="$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("result",""))')"
  when="$(date -Iseconds)"

  # Build REVIEW.md (frontmatter + body), base64 it, and write it on the VM
  # (base64 transfer keeps arbitrary markdown intact through the shell).
  review_md="$(printf -- '---\nreviewed_at: %s\nframe: %s\nreviewed_hash: %s\nmodel: %s\ncost_usd: %s\ntokens_in: %s\ntokens_out: %s\nseconds: %s\n---\n%s\n' \
    "$when" "$tf" "$h" "$MODEL" "$cost" "$tin" "$tout" "$secs" "$body")"
  b64="$(printf '%s' "$review_md" | base64)"
  bash "$RUN" "printf '%s' '$b64' | base64 -d > $CT/$h/REVIEW.md"

  # Append ledger row.
  row="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$when" "$tf" "$h" "$MODEL" "$cost" "$tin" "$tout" "$secs")"
  brow="$(printf '%s' "$row" | base64)"
  bash "$RUN" "printf '%s' '$brow' | base64 -d >> $LEDGER; echo >> $LEDGER"

  # Flip .status -> reviewed for ALL hashes sharing this frame.
  bash "$RUN" "
cd $CT 2>/dev/null || exit 0
TF='$tf' python3 - <<'PY'
import json, os, re
target = os.environ['TF']
for d in os.listdir('.'):
    if not re.fullmatch(r'[0-9a-f]{12}', d) or not os.path.isdir(d):
        continue
    try:
        m = json.load(open(d+'/meta.json'))
        tf = m.get('top_frame') or m.get('signature') or '?'
    except Exception:
        tf = '?'
    if tf == target:
        open(d+'/.status','w').write('reviewed')
PY
"
  echo "[+] frame '$tf' reviewed — \$$cost, ${secs}s"
  total_cost="$(python3 -c "print(round($total_cost + ${cost:-0}, 4))")"
  reviewed=$((reviewed+1))
done

echo "[=] done: $reviewed frame(s), \$$total_cost total"
