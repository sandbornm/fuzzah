# fuzzah (Fuzzing Assistant Harness) — AGENTS.md

> This file is the Codex-side counterpart to `CLAUDE.md`. Both describe the
> same rig; the only differences are tool-specific invocation syntax
> (`/check-in` in Claude Code ↔ `$check-in` in Codex). Keep this file and
> `CLAUDE.md` in sync when the mental model changes.
>
> First time here? Read `README.md` for the end-to-end walkthrough.

## Mental model

```
┌────────────── your host (Mac, Linux, or VM) ──────────────┐
│ This repo:                                                 │
│   AGENTS.md        (this file — Codex)                    │
│   CLAUDE.md        (equivalent — Claude Code)             │
│   .agents/skills/  (Codex-invokable skills: $name)        │
│   .claude/         (Claude skills + slash commands)       │
│   shared/          (cross-target infra scripts)           │
│   target-template/ (per-target script pack to copy)       │
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

- Everything lives under `$HOME/fuzzing/` inside the fuzzing host (your
  Mac/Linux box directly, or an orb VM proxied via `orb -m <vm>`).
- Shared infra (`shared/*.sh`) and per-target scripts (`~/fuzzing/targets/<t>/scripts/*.sh`)
  run as the operator user, never as root (except for the specific `sudo`
  calls in `harden.sh` and the occasional `dmesg`).
- Each target runs **three** concurrent AFL++ workers under tmux:
  `primary` (master), `asan` (secondary on sanitizer build), `explore`
  (secondary with broader power schedule). Plus a `triage` loop and a
  `status` tail.

### Memory caps (critical)

- `primary` + `explore` use `-m 1024` (1 GB RSS cap per child)
- `asan` uses `-m none` (ASAN shadow memory needs unbounded virtual)
- These values ship in `target-template/start-fuzz.sh`; don't blanket-change
  without understanding why.

A shared `fuzz-watchdog.timer` (user systemd, fires every 5 min) re-invokes
every target's `start-fuzz.sh` — idempotent, only restarts roles that died
(e.g. OOM). Logs at `~/fuzzing/logs/watchdog.log`.

## Skills (Codex)

Invoke as `$skill-name`:

| Skill | Purpose |
|-------|---------|
| `$check-in`          | Cross-target fuzz-domain dashboard (fuzzer counts, crashes by state)   |
| `$rig-check`         | System-domain health (host mem/disk/swap, systemd, OOM, watchdog)      |
| `$fuzz-status`       | Single-target rig status                                               |
| `$fuzz-crashes`      | List all unique triaged crashes for a target                           |
| `$fuzz-review`       | Deep-dive one crash by hash — loads meta.json + trace.txt              |
| `$fuzz-crash-review` | The per-crash triage workflow (used by `$fuzz-review`)                 |
| `$fuzz-add-target`   | Full pipeline to bring a new target online                             |

Skills live at `.agents/skills/<name>/SKILL.md`. The two long-form workflow
skills (`fuzz-crash-review`, `fuzz-add-target`) are symlinked from
`.claude/skills/` so both tools share the same source of truth.

Claude Code equivalents: `/check-in`, `/rig-check`, `/fuzz-status`,
`/fuzz-crashes`, `/fuzz-review`.

## Common ops

```sh
# Cross-target dashboard (fuzz state)
bash shared/check-in.sh

# System health (memory, OOM, systemd)
bash shared/rig-check.sh

# Status of one target's rig
bash shared/run-on-fuzz-host.sh 'bash "$HOME/fuzzing/targets/<target>/scripts/status.sh"'

# Triaged crash index for a target
bash shared/run-on-fuzz-host.sh 'cat "$HOME/fuzzing/targets/<target>/crashes-triaged/INDEX.md"'

# Mark a crash (advance the workflow state)
bash shared/run-on-fuzz-host.sh \
  'echo reviewed > "$HOME/fuzzing/targets/<target>/crashes-triaged/<hash>/.status"'

# Inspect a target setup before bootstrap
bash shared/inspect-target.sh <target>
```

`shared/run-on-fuzz-host.sh` auto-detects direct Linux execution vs Orb and
ensures `~` / `$HOME` expand on the fuzz host.

If OrbStack is unhealthy on macOS, use `bash shared/orb-debug.sh`. Do not
assume `orbctl status` is authoritative by itself; a wedged helper can report
`Stopped` even when the backend has partially started.

### Crash workflow state

Each triaged crash dir can hold a `.status` file (one word). `$check-in`
buckets crashes by this. Default when absent is `new`.

| state     | meaning                                                        |
|-----------|----------------------------------------------------------------|
| new       | freshly triaged; human has not looked yet                      |
| reviewed  | human confirmed it's worth chasing; needs fresh-build repro    |
| repro-ok  | reproduced on fresh build; needs upstream bug report drafted   |
| reported  | upstream issue filed; tracking only                            |
| dup       | duplicate of another hash (lower priority or older)            |
| ignore    | false positive / noise (includes auto-tagged `memlimit-kill`)  |

### Known noise patterns

- **`memlimit-kill`** top_frame — auto-marked `ignore` by `triage-one.sh`.
  These are inputs that ballooned past the 1 GB `-m 1024` cap on fast-build
  fuzzers; not memory-safety bugs.
- **`no-frames unknown-sig`** with `asan > 0` hits — potential stack
  corruption / stack overflow. ASAN saw the crash but couldn't unwind.
  Keep in `new`, manual review required.
- **`no-frames unknown-sig`** with `asan == 0` hits — likely memlimit
  artifact that slipped past the auto-tagger. Low value.

## Adding a new target

Invoke `$fuzz-add-target` — it walks the full pipeline (seeds → 3 builds →
cmin → triage → systemd). Reuses `target-template/` as the starting point.
Works for cmake, autoconf, meson, and custom build systems.

Helper scripts under `shared/` simplify the manual path:

- `scaffold-target.sh <target>` — create `<control-root>/<target>-setup/`
- `sync-target.sh <target>` — push that setup into `$HOME/fuzzing/targets/<target>/`
- `bootstrap-target.sh <target>` — sync + build + cmin + systemd start

## Cross-tool contract

Both Claude Code and Codex sessions should converge on the same operator
view. If you touch operator workflow:

1. Update the **shared script** under `shared/` or the per-target scripts
2. Update **both** `AGENTS.md` and `CLAUDE.md` if the mental model changed
3. Update **both** skill trees (or the symlinked source if shared)

Target-specific docs live in `~/fuzzing/targets/<target>/SETUP.md` on the
fuzzing host.
