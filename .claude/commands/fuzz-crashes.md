---
description: List all unique triaged crashes for a fuzz target from its INDEX.md.
argument-hint: "<target>"
allowed-tools: Bash(orb -m fuzzer:*)
---

Dump the crash roster for the target.

```bash
target="${ARGUMENTS:-}"
if [[ -z "$target" ]]; then
  echo "usage: /fuzz-crashes <target>" >&2
  exit 1
fi
orb -m fuzzer cat "$HOME/fuzzing/targets/${target}/crashes-triaged/INDEX.md"
```

After the table, also report:

- Total unique count
- Most recent `first_seen` timestamp
- Count of entries with `no-frames` or `no-asan-report` top_frame (worth re-examining with a manual gdb run)
- Count of entries with `memlimit-kill` top_frame (operator-noise artifacts auto-ignored by triage)
