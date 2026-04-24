---
name: fuzz-crashes
description: List all unique triaged crashes for a fuzz target from its INDEX.md. Use when the operator asks "what crashes do we have", "list crashes for <target>", or invokes $fuzz-crashes <target>. Equivalent of /fuzz-crashes in Claude Code.
---

Dump the crash roster for the target.

```bash
target="${TARGET:?target name required}"
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/run-on-fuzz-host.sh" \
  "cat \"\$HOME/fuzzing/targets/${target}/crashes-triaged/INDEX.md\""
```

After the table, also report:

- Total unique count
- Most recent `first_seen` timestamp
- Count of entries with `no-frames` or `no-asan-report` top_frame (worth re-examining with a manual gdb run)
- Count of entries with `memlimit-kill` top_frame (auto-ignored artifacts)
