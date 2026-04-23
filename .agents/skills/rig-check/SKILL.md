---
name: rig-check
description: System-domain health snapshot of the fuzz rig — host memory/disk/swap, systemd unit state, worker counts with uptime, OOM-kill events from dmesg, watchdog respawn rate, spurious kernel signals. Orthogonal to $check-in (which only covers fuzz-domain state). Use when the operator asks about VM/host health, OOM investigation, why workers keep dying, or invokes $rig-check. Equivalent of /rig-check in Claude Code.
---

Run the shared `rig-check.sh`. It auto-detects host:

- **Mac / Linux host with `orb`** → proxies commands through `orb -m fuzzer`
- **Inside the fuzzing VM / host** → runs commands directly

```bash
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/rig-check.sh"
```

After the output prints, summarize anything flagged with `[!]`:

- **Available memory < 512 MiB** — under pressure; check afl-tmin or concurrent ASAN children.
- **Disk free < 5 GB** — archive `findings/` or extend storage.
- **Systemd service inactive** — report which unit, suggest `systemctl --user start …`.
- **OOM-kill count ≥ 5** — categorize victims:
  - `total-vm ≈ 38 TB` = ASAN child (unavoidable; ASAN shadow needs unbounded virtual). Expected noise.
  - `total-vm few GB` = fast-build child that escaped `-m 1024` — check if afl-tmin is invoked with the right flag.
- **Watchdog respawns > 10/hr** — flap loop; drill into which role dies.
- **Spurious kernel signals** — non-fuzzer-child SIGSEGV / GPF; surface the listed process.

If nothing is flagged, report "rig healthy" — don't manufacture follow-ups.
