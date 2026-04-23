---
description: Show fuzz rig status for one target — live fuzzer count, execs/sec, coverage, crashes, disk.
argument-hint: "<target>"
allowed-tools: Bash(orb -m fuzzer:*)
---

Run the target's `status.sh` and summarize the result.

```bash
target="${ARGUMENTS:-}"
if [[ -z "$target" ]]; then
  echo "usage: /fuzz-status <target>" >&2
  exit 1
fi
orb -m fuzzer bash "$HOME/fuzzing/targets/${target}/scripts/status.sh"
```

After running, call out anything unusual: fuzzers below expected count,
execs/sec that's suspiciously low (< 200/s is a red flag), disk filling up
(< 5 GB free), or a jump in raw-crashes-since-last-check.
