---
description: System-domain health snapshot — memory/disk/swap, systemd unit state, worker counts, OOM events from dmesg, watchdog respawn rate. Orthogonal to /check-in (which covers fuzz state only).
argument-hint: ""
allowed-tools: Bash(orb -m fuzzer:*), Bash(bash:*)
---

Run the shared `rig-check.sh`. It auto-detects host environment (Mac with
orb, Linux with orb, or directly inside the fuzzing VM/host) and routes
commands accordingly.

```bash
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/rig-check.sh"
```

After the output prints, summarize anything flagged with `[!]`:

- **VM memory under 512 MiB available** — full-host pressure; check afl-tmin or concurrent ASAN children.
- **Disk free < 5 GB** — archive old `findings/` or rotate crashes-triaged archives.
- **Systemd service inactive** — report which unit, suggest `systemctl --user start …`.
- **OOM-kill count ≥ 5 in dmesg buffer** — categorize by victim and total-vm size. A ≈38 TB virtual signature = ASAN child (inherent, unavoidable). Few-GB virtual on a fast-build child = the `-m` cap didn't apply (check afl-tmin flag).
- **Watchdog respawns > 10/hr** — flap loop; drill into which role dies.
- **Spurious kernel signals** — non-fuzzer-child SIGSEGV / GPF; investigate the listed process.

If nothing is flagged, report "rig healthy" and move on — don't manufacture follow-ups.
