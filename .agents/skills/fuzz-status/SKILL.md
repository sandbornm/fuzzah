---
name: fuzz-status
description: Show fuzz rig status for a single target — live fuzzer count, execs/sec, coverage, crashes, disk. Use when the operator asks for the status of a specific target or invokes $fuzz-status <target>. Equivalent of /fuzz-status in Claude Code. For a multi-target summary, use $check-in instead.
---

Run the target's `status.sh` and summarize.

```bash
# The skill expects a target name in the invocation (e.g. $fuzz-status mytool).
target="${TARGET:?target name required}"
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/run-on-fuzz-host.sh" \
  "bash \"\$HOME/fuzzing/targets/${target}/scripts/status.sh\""
```

(`run-on-fuzz-host.sh` chooses direct Linux execution vs Orb automatically.)

After running, call out anything unusual:

- Fuzzers below expected count (3 per target by default)
- execs/sec that's suspiciously low (< 200/s is a red flag)
- Disk filling up (< 5 GB free)
- A jump in raw-crashes-since-last-check
