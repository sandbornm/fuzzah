# fuzzah (Fuzzing Assistant Harness) - AGENTS.md

> Codex loads this file automatically. The Claude Code counterpart is
> `CLAUDE.md` - keep both in sync when the mental model changes.
> Codex skills use `$skill-name`; Claude Code has equivalent slash commands
> (`/check-in`, etc.).
>
> First time here? Read `README.md` for the end-to-end walkthrough.

## Mental model

```
┌────────────── your host (Mac, Linux, or VM) ──────────────┐
│ This repo:                                                 │
│   AGENTS.md, CLAUDE.md    (tool-specific entry docs)       │
│   .agents/skills/         (Codex entry points)             │
│   .claude/{commands,skills,settings.json}                  │
│   shared/                 (cross-target infra scripts)     │
│   target-template/        (per-target script pack to copy) │
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
  via `orb -m <vm>` from a Mac. Use `shared/run-on-fuzz-host.sh` for commands
  that must run on the fuzz host so `$HOME` expands on the right machine.
- Shared infra (`shared/*.sh`) and per-target scripts
  (`~/fuzzing/targets/<t>/scripts/*.sh`) run as the operator user, never as
  root except for the specific `sudo` calls in `harden.sh` and diagnostics
  such as `dmesg`.
- Each target runs **three** concurrent AFL++ workers:
  - `primary` - fast build + CMPLOG companion (`-m 1024`)
  - `asan` - ASAN + UBSAN build (`-m none`)
  - `explore` - fast build with broader power schedule (`-m 1024`)
- Plus a `triage` loop and a `status` window per target, all in tmux.
- A shared `fuzz-watchdog.timer` (user systemd, 5 min) re-invokes every
  target's `start-fuzz.sh` - idempotent, only relaunches dead roles.
- For fuzzer roles (`primary`, `asan`, `explore`), `start-fuzz.sh` waits for
  `findings/<role>/fuzzer_stats`, reads `fuzzer_pid`, and verifies it with
  `kill -0` before logging success. Startup failures exit non-zero instead of
  printing an optimistic `[+] launched`.

## Skills (Codex)

Invoke as `$skill-name`:

| Skill | Purpose |
|-------|---------|
| `$check-in`          | Cross-target fuzz-domain dashboard (fuzzer counts, crashes by state)   |
| `$rig-check`         | System-domain health (host mem/disk/swap, systemd, OOM, watchdog)      |
| `$fuzz-status`       | Single-target rig status                                               |
| `$fuzz-crashes`      | List all unique triaged crashes for a target                           |
| `$fuzz-review`       | Deep-dive one crash by hash — loads meta.json + trace.txt              |
| `$fuzz-dashboard`    | Launch the fuhq browser dashboard                                      |
| `$fuzz-crash-review` | The per-crash triage workflow (used by `$fuzz-review`)                 |
| `$fuzz-add-target`   | Full pipeline to bring a new target online                             |

Skills live at `.agents/skills/<name>/SKILL.md`. The two long-form workflow
skills (`fuzz-crash-review`, `fuzz-add-target`) are symlinked from
`.claude/skills/` so both tools share the same source of truth.

Claude Code equivalents: `/check-in`, `/rig-check`, `/fuzz-status`,
`/fuzz-crashes`, `/fuzz-review`, `/fuzz-dashboard`.

## Common ops

```sh
# Cross-target fuzz-domain dashboard
$check-in

# System-domain health (memory/OOM/systemd) - orthogonal to $check-in
$rig-check

# Status of one target's rig
$fuzz-status <target>

# List all unique crashes for a target
$fuzz-crashes <target>

# Deep-dive review of a specific crash
$fuzz-review <hash> <target>

# Live browser dashboard (fuhq). Foreground server; Ctrl-C to stop.
$fuzz-dashboard

# Or ad-hoc, without a skill:
bash shared/fuzz-status.sh <target>
bash shared/fuzz-crashes.sh <target>
bash shared/run-on-fuzz-host.sh \
  'echo reviewed > "$HOME/fuzzing/targets/<target>/crashes-triaged/<hash>/.status"'
bash shared/inspect-target.sh <target>
```

`shared/run-on-fuzz-host.sh` auto-detects direct Linux execution vs Orb and
ensures `~` / `$HOME` expand on the fuzz host.

`shared/check-in.sh` also counts fuzzers from `fuzzer_stats` `fuzzer_pid` plus
`kill -0`, not broad process-name matching, so stale AFL stats files do not
inflate the alive count.

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

- `setup-macos-orb.sh` — bootstrap a fresh macOS + OrbStack fuzz host
- `scaffold-target.sh <target>` — create `<control-root>/<target>-setup/`
- `sync-target.sh <target>` — push that setup into `$HOME/fuzzing/targets/<target>/`
- `bootstrap-target.sh <target>` — sync + build + cmin + systemd start

## Where Codex-specific config lives

- `.agents/skills/` - Codex skills for check-in, rig-check, status, crash
  listing/review, dashboard launch, and target bootstrap.
- `.agents/skills/fuzz-add-target` and `.agents/skills/fuzz-crash-review` are
  symlinks to the Claude skill sources, so long-form workflows stay shared.
- `AGENTS.md` - this file; Codex-facing operator model and entry points.
- `shared/` - cross-target tooling used by both Codex and Claude.
- `shared/fuzz-dashboard/` - fuhq browser dashboard (`run.sh`, `server.py`,
  and review-drain helpers).
- `shared/crash-digest/` - six-hour crash email pipeline: bounded raw triage,
  deterministic repro/report promotion, JSON collection, and Resend delivery.

## Crash digest automation

`shared/crash-digest/send-digest.sh` is the stable entry point for scheduled
email reports. It runs three VM-side stages through `shared/run-on-fuzz-host.sh`
before sending from the control host:

1. `triage-drain.sh` drains a capped number of unseen AFL crash files into
   `crashes-triaged/`.
2. `promote-repros.py` replays high-signal crashes and writes `REPORT.md`,
   `REPRO.md`, and `POC.md`; reproducible crashes move to `.status=repro-ok`.
3. `collect.py` emits the normalized snapshot used by the email renderer.

The generated crash page is the source of truth for phone review:
`/c/<target>/<hash>` renders `REPORT.md`, `POC.md`, `REPRO.md`, optional
`REVIEW.md`, raw PoC hexdump/download, `trace.txt`, and `meta.json`.
The dashboard's priority column uses `REPORT.md` `report_priority` when it
exists; raw `hit_count` remains visible as stability/repro frequency only.
The six-hour email top list is narrower than the dashboard by default:
`FUZZ_DIGEST_MIN_REPORT_PRIORITY=80` and `FUZZ_DIGEST_ONLY_HIGH_VALUE=1`
mean only likely memory-corruption candidates should be flagged for manual
review. Assertions, UBSan-only reports, JavaScript exceptions, and parser DoS
stay clickable in the dashboard but do not consume the email triage lane.

`promote-repros.py` is deterministic and templates reports from observed replay
facts. Richer LLM root-cause explanation belongs in `REVIEW.md`, generated by
the separate `shared/fuzz-dashboard/review-drain.sh` flow for crashes marked
`review-requested`.

JSC/Fuzzilli promotion is first-class: it replays `poc.reduced.js` or `poc.js`
with recorded Fuzzilli `processArguments` minus `--reprl`. It prefers an ASan
JSC shell when `JSC_ASAN_BIN`, `<TARGET>_ASAN_BIN`, `jsc-asan/WebKitBuild/bin/jsc`,
or `jsc/WebKitBuild-ASAN/bin/jsc` exists. ASan findings become
`memory-bug/HIGH`; JSC assertions, UBSan-only findings, and ASan replays that
only hit the timeout stay low-priority unless a sanitized replay shows native
memory corruption. The JSC ASan replay command unsets build-only `JSC_ASAN_*`
variables and redirects non-halting UBSan output to `/tmp/fuzzah-jsc-ubsan.*`
because the current WebKit/libpas ASan+UBSan build emits startup UBSan noise.

Mac install:

```sh
bash shared/crash-digest/install-macos.sh --dry-run
bash shared/crash-digest/install-macos.sh --tailscale-serve
```

Private Resend/Tailscale config lives outside git, normally at
`/Users/minimo/fuzzig/.secrets/fuzz-crash-digest.env`.

With `--tailscale-serve`, the dashboard is served only inside the tailnet,
proxies to `127.0.0.1:8765`, and the launchd dashboard runs
`FUZZ_DASHBOARD_READ_ONLY=1` so email links can view reports/PoCs but cannot
change workflow state. Do not enable Tailscale Funnel for crash reports.

## Cross-tool contract

Both Claude Code and Codex sessions should converge on the same operator
view. If you touch operator workflow:

1. Update the **shared script** under `shared/` or the per-target scripts
2. Update **both** `AGENTS.md` and `CLAUDE.md` if the mental model changed
3. Update **both** skill trees (or the symlinked source if shared)

Target-specific docs live in `~/fuzzing/targets/<target>/SETUP.md` on the
fuzzing host.

## Working with git worktrees (concurrent agents)

When more than one agent (e.g. Codex and Claude) may be working in this repo at
once, do **not** `git checkout` / `switch` / `branch` inside the shared `fuzzah/`
checkout — you'd yank the other agent's branch out from under them, and the
running fuhq dashboard + the fuzzig symlinks (`shared/`, `.claude/*`, `.agents/`)
all point at that one checkout. Use a **git worktree**: an isolated second
checkout on its own branch that shares the same `.git`.

**When to use one:**
- Another agent is actively working in `fuzzah/` (the common case here).
- You want to build/test a branch without disturbing the live checkout.

**Setup — branch off the latest `main`:**
```sh
git -C /path/to/fuzzah fetch origin
git -C /path/to/fuzzah worktree add -b feat/<name> \
  /Users/minimo/fuzzig/.wt-<name> origin/main
# then edit / test / commit inside /Users/minimo/fuzzig/.wt-<name>
```

**Caveats:**
- The fuzzig `shared/`, `.claude/*`, `.agents/` symlinks resolve to the **main**
  checkout, not your worktree — so your changes are **not live** for the rig
  until the branch merges to `main`. Test using the worktree's own copies
  (e.g. run `shared/fuzz-dashboard/server.py` from the worktree on a non-8765
  port; run `shared/check-in.sh` from the worktree path).
- Keep worktrees fuzzig-local (`/Users/minimo/fuzzig/.wt-*`), never inside
  `fuzzah/`. Commit on the branch; do **not** `git push` without the operator's
  ok.

**Cleanup (after merge or abandon):**
```sh
git -C /path/to/fuzzah worktree remove /Users/minimo/fuzzig/.wt-<name>
git -C /path/to/fuzzah branch -D feat/<name>   # only if abandoning unmerged
```
