# fuzzah (Fuzzing Assistant Harness) — CLAUDE.md

> Claude Code loads this file automatically. The Codex counterpart is
> `AGENTS.md` — keep both in sync when the mental model changes.
> Slash commands work in Claude Code; Codex has the equivalent skills
> (`$check-in`, etc.).
>
> First time here? Read `README.md` for the end-to-end walkthrough.

## Mental model

```
┌────────────── your host (Mac, Linux, or VM) ──────────────┐
│ This repo:                                                 │
│   CLAUDE.md, AGENTS.md   (tool-specific entry docs)       │
│   .claude/{commands,skills,settings.json}                 │
│   .agents/skills/        (Codex equivalents)              │
│   shared/                (cross-target infra scripts)     │
│   target-template/       (per-target script pack to copy) │
│                                                            │
│   ┌──── fuzzing host (this machine or an orb VM) ────┐    │
│   │ $HOME/fuzzing/                                   │    │
│   │   tools/AFLplusplus/                             │    │
│   │   targets/<name>/       ← one dir per target     │    │
│   │     src/                — upstream source        │    │
│   │     build-afl/          — fast build             │    │
│   │     build-afl-asan/     — ASAN + UBSAN build     │    │
│   │     build-afl-cmplog/   — CMPLOG companion       │    │
│   │     seeds/corpus.min/   — minimized corpus       │    │
│   │     findings/           — AFL queue + crashes    │    │
│   │     crashes-triaged/    — deduped by ASAN/GDB    │    │
│   │     scripts/            — rig automation         │    │
│   │     SETUP.md            — operator doc           │    │
│   │                                                  │    │
│   │ tmux session per target: `<target>-fuzz`         │    │
│   │ systemd user units: <target>-fuzz.service,       │    │
│   │   fuzz-watchdog.timer (shared, 5 min)            │    │
│   └──────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

## How things run

- Scripts can execute on the fuzzing host directly (Linux) or be proxied
  via `orb -m <vm>` from a Mac. The `shared/rig-check.sh` script auto-
  detects which mode you're in.
- Each target runs **three** concurrent AFL++ workers:
  - `primary` — fast build + CMPLOG companion (`-m 1024`)
  - `asan`    — ASAN + UBSAN build (`-m none`)
  - `explore` — fast build with broader power schedule (`-m 1024`)
- Plus a `triage` loop and a `status` window per target, all in tmux.
- A shared `fuzz-watchdog.timer` (user systemd, 5 min) re-invokes every
  target's `start-fuzz.sh` — idempotent, only relaunches dead roles.

## Common ops

```sh
# Cross-target fuzz-domain dashboard
/check-in

# System-domain health (memory/OOM/systemd) — orthogonal to /check-in
/rig-check

# Status of one target's rig
/fuzz-status <target>

# List all unique crashes for a target
/fuzz-crashes <target>

# Deep-dive review of a specific crash
/fuzz-review <hash> <target>

# Or ad-hoc, without a slash command:
orb -m fuzzer bash ~/fuzzing/targets/<target>/scripts/status.sh
orb -m fuzzer cat  ~/fuzzing/targets/<target>/crashes-triaged/INDEX.md
```

### Crash workflow state

Each triaged crash dir can hold a `.status` file (one word). `/check-in`
buckets crashes by this. Default when absent is `new`.

| state     | meaning                                                        |
|-----------|----------------------------------------------------------------|
| new       | freshly triaged; human has not looked yet                      |
| reviewed  | human confirmed it's worth chasing; needs fresh-build repro    |
| repro-ok  | reproduced on fresh build; needs upstream bug report drafted   |
| reported  | upstream issue filed; tracking only                            |
| dup       | duplicate of another hash (lower priority or older)            |
| ignore    | false positive / noise (includes auto-tagged `memlimit-kill`)  |

Mark a crash:
```sh
orb -m fuzzer bash -c \
  'echo reviewed > ~/fuzzing/targets/<target>/crashes-triaged/<hash>/.status'
```

## Adding a new target

Invoke the `fuzz-add-target` skill — it walks the full pipeline (seeds →
3 builds → cmin → triage → systemd). Works for cmake, autoconf, meson, and
custom build systems. Copies `target-template/` into a per-target scripts
dir and guides the edits.

## Where Claude-specific config lives

- `.claude/skills/`           — Claude skills (fuzz-crash-review, fuzz-add-target)
- `.claude/commands/`         — Claude slash commands (check-in, rig-check, fuzz-status, fuzz-crashes, fuzz-review)
- `.claude/settings.json`     — pre-allowed `orb` commands (no permission prompts)
- `shared/`                   — cross-target tooling (watchdog, check-in, rig-check)
- `target-template/`          — the per-target script pack copied per new target

Target-specific docs live in `~/fuzzing/targets/<target>/SETUP.md` on the
fuzzing host.
