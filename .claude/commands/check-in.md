---
description: Dashboard across all fuzz targets — counts, fuzzer health, and crashes needing review / repro / reporting.
argument-hint: ""
allowed-tools: Bash(orb -m fuzzer:*), Bash(bash:*)
---

Runs the shared check-in script across every `~/fuzzing/targets/*` target.
Reports: live fuzzer count, execs/sec, unique crash count, and a breakdown of
crashes by workflow state (new → reviewed → repro-ok → reported).

```bash
bash shared/check-in.sh
```

(If running from a Mac host against an orb VM, the script auto-proxies
through orb when it detects a non-VM environment. If you prefer an explicit
invocation: `orb -m fuzzer bash -lc 'bash "$HOME/fuzzig-shared/check-in.sh"'`.)

After the dashboard prints, summarize in prose:

- Any target with zero fuzzers alive (systemd unit dead or never enabled).
- Any target with execs/sec < 200 (calibration stalled or target crashing at exec-0).
- Count of crashes in `new` state — these are the operator's immediate queue.
- Any crash with `hit_count` > 20 (stable repro; good candidate for upstream
  bug report) — suggest marking `reviewed` or running `/fuzz-review <hash>`.
- If any target shows disk < 5 GB free, flag it.

If the dashboard is entirely empty (no targets or no crashes yet), say so
plainly — don't hallucinate follow-ups.
