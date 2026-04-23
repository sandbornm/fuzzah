---
name: check-in
description: Cross-target fuzz dashboard. Prints live fuzzer counts, execs/sec, unique crash counts, and a breakdown of crashes by workflow state (new → reviewed → repro-ok → reported). Use when the operator asks for a health snapshot, wants to know where to focus today, or invokes $check-in. Equivalent of /check-in in Claude Code.
---

Runs `check-in.sh` across every `~/fuzzing/targets/*` in the fuzzing host/VM.

```bash
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/check-in.sh"
```

The script auto-detects: if you're inside the fuzzing VM, it runs commands
directly; otherwise it proxies through `orb -m fuzzer`.

After the dashboard prints, summarize in prose:

- Any target with zero fuzzers alive (systemd unit dead or never enabled).
- Any target with execs/sec < 200 (calibration stalled or target crashing at exec-0).
- Count of crashes in `new` state — the operator's immediate queue.
- Any crash with `hit_count` > 20 (stable repro; upstream-report candidate) —
  suggest marking `reviewed` or running `$fuzz-review <hash> <target>`.
- If any target shows disk < 5 GB free, flag it.

If the dashboard is entirely empty (no targets or no crashes yet), say so
plainly — don't hallucinate follow-ups.
