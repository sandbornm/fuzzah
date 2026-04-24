# fuzzah — Fuzzing Assistant Harness

A minimal, target-agnostic kit for running AFL++ fuzz rigs with the same
conventions across many targets, driven from either the terminal or an
AI coding agent (Claude Code / Codex).

Each target gets three concurrent AFL++ workers (fast + ASAN + explore),
a CMPLOG companion, a crash-triage loop that deduplicates by ASAN stack
hash, a workflow state machine for crashes, and a shared 5-minute
watchdog that respawns anything that dies. Two commands — `check-in`
("are we finding bugs?") and `rig-check` ("is the box healthy?") — tell
you everything you need in under a second.

## Expected layout

`fuzzah` assumes a strict split between control-plane files and runtime state:

```text
<control-root>/
  fuzzah/                    # reusable toolkit repo
    shared/
    target-template/         # blank per-target script pack
    examples/                # filled-in illustrations of target-template
    .agents/skills/
    .claude/{commands,skills}/
  <target>-setup/            # host-side, versioned target setup
    SETUP.md
    scripts/

$HOME/fuzzig-shared/         # installed shared scripts on the fuzz host
  check-in.sh
  rig-check.sh
  fuzz-watchdog.sh

$HOME/fuzzing/               # live runtime state on the fuzz host
  tools/AFLplusplus/
  targets/<target>/
    src/
    build-afl/
    build-afl-asan/
    build-afl-cmplog/
    seeds/
    findings/
    crashes-triaged/
    scripts/
    SETUP.md
```

The helpers under `shared/` assume that shape. If you keep `fuzzah/` nested
inside a larger control-plane repo, set `FUZZAH_CONTROL_ROOT` or rely on the
current parent-directory auto-detection.

## Is this for me?

**Yes**, if you want long-lived fuzz rigs that survive OOMs, reboots,
and operator absences, across multiple targets, with deduplicated
crashes organized for review.

**No**, if you want a one-shot `afl-fuzz` run on a single target — just
use AFL++ directly.

## The picture

```
┌── your host (Mac via orb, or Linux directly) ──┐
│                                                 │
│  $HOME/fuzzing/                                 │
│    tools/AFLplusplus/                           │
│    logs/watchdog.log                            │
│    targets/<name>/                              │
│      src/                 — upstream checkout   │
│      build-afl/           — plain AFL build     │
│      build-afl-asan/      — ASAN + UBSAN build  │
│      build-afl-cmplog/    — CMPLOG companion    │
│      seeds/corpus.min/    — minimized corpus    │
│      findings/            — live AFL output     │
│      crashes-triaged/     — deduped PoCs        │
│      scripts/             — per-target automation│
│                                                 │
│  systemd --user:                                │
│    <name>-fuzz.service    — target rig          │
│    fuzz-watchdog.timer    — 5-min respawn loop  │
│                                                 │
│  tmux sessions:                                 │
│    <name>-fuzz  {primary, asan, explore,        │
│                  triage, status}                │
└─────────────────────────────────────────────────┘
```

---

## Quickstart

Two paths. Pick the one that matches your host.

### Path A — Mac + orb (recommended on macOS)

**Prereq:** [Orbstack](https://orbstack.dev/) installed (`brew install --cask orbstack`).

```sh
# 1. Clone
git clone https://github.com/sandbornm/fuzzah.git && cd fuzzah

# 2. Create a Linux VM named `fuzzer` (10 cores / 8 GB — see "Sizing" below)
orb create ubuntu:22.04 fuzzer --cpu 10 --memory 8 --user "$USER"

# 3. Install AFL++ and build deps inside the VM
orb -m fuzzer bash -c '
  sudo apt-get update && sudo apt-get install -y \
    build-essential clang llvm lld cmake git python3 python3-dev \
    automake libtool pkg-config libglib2.0-dev bison flex gdb jq \
    nftables tmux
  mkdir -p $HOME/fuzzing/tools && cd $HOME/fuzzing/tools
  git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git
  cd AFLplusplus && make distrib -j$(nproc)
'

# 4. Install the shared infrastructure (watchdog, check-in, rig-check)
orb -m fuzzer bash -c '
  mkdir -p $HOME/fuzzig-shared $HOME/fuzzing/logs $HOME/.config/systemd/user
  cp '"$PWD"'/shared/{check-in,rig-check,fuzz-watchdog}.sh $HOME/fuzzig-shared/
  chmod +x $HOME/fuzzig-shared/*.sh
  cp '"$PWD"'/shared/fuzz-watchdog.{service,timer} $HOME/.config/systemd/user/
  systemctl --user daemon-reload
  systemctl --user enable --now fuzz-watchdog.timer
'

# 5. Smoke test
bash shared/rig-check.sh
```

Done. `rig-check` will report "no targets yet" until you add one (next section).

For any command that should run on the fuzz host, prefer:

```sh
bash shared/run-on-fuzz-host.sh '<command that should run on the fuzz host>'
```

It auto-detects direct Linux vs Orb-on-macOS and makes sure `$HOME` expands on
the fuzz host.

If OrbStack is present but unhealthy, this wrapper now prints a diagnostic hint
instead of silently assuming the proxy path works. For a focused host-side
debug snapshot, run:

```sh
bash shared/orb-debug.sh
```

If you keep target setup dirs outside the `fuzzah/` repo itself, set
`FUZZAH_CONTROL_ROOT=/path/to/control-plane`. If `fuzzah/` is nested under a
larger control-plane repo that has `AGENTS.md` / `CLAUDE.md` at the parent
level, the helpers auto-detect that parent as the control root.

### Path B — Linux host (bare metal, VM, cloud box)

SSH into the host, then:

```sh
git clone https://github.com/sandbornm/fuzzah.git && cd fuzzah

# Install AFL++ and deps
sudo apt-get update && sudo apt-get install -y \
  build-essential clang llvm lld cmake git python3 python3-dev \
  automake libtool pkg-config libglib2.0-dev bison flex gdb jq \
  nftables tmux
mkdir -p $HOME/fuzzing/tools && cd $HOME/fuzzing/tools
git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus && make distrib -j$(nproc)
cd -

# Install shared infrastructure
mkdir -p $HOME/fuzzig-shared $HOME/fuzzing/logs $HOME/.config/systemd/user
cp shared/{check-in,rig-check,fuzz-watchdog}.sh $HOME/fuzzig-shared/
chmod +x $HOME/fuzzig-shared/*.sh
cp shared/fuzz-watchdog.{service,timer} $HOME/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now fuzz-watchdog.timer

# Smoke test
bash shared/rig-check.sh
```

### Sizing

- **CPU:** 3 cores per target (fast + asan + explore). 10 cores fits 3
  targets with headroom.
- **RAM:** 8 GB minimum per target. ASAN shadow memory allocates
  virtual address space aggressively; 4 GB hosts OOM constantly.
- **Disk:** 5–15 GB per target (source + 3 build dirs + findings growth).

---

## Add your first target

The fastest path: let an agent walk you through it.

- **Claude Code:** open this directory and say *"add a fuzz target for `<name>`"*.
- **Codex:** same, or invoke `$fuzz-add-target`.

The `fuzz-add-target` skill handles everything — copying the template,
wiring your build system, scraping seeds, and starting the rig.

### By hand

Copy the per-target template and edit four files. Assume target name
`mytool`:

```sh
# Create a host-side editable setup dir.
bash shared/scaffold-target.sh mytool

# Sync that setup dir into the fuzz host.
bash shared/sync-target.sh mytool
```

By default this creates:

```sh
<control-root>/mytool-setup/
  SETUP.md
  scripts/
```

Now edit these files in the host-side `mytool-setup/scripts/` dir
(every other script auto-derives the target name from its filesystem
location):

| file              | what to set                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `start-fuzz.sh`   | `HARNESS_SUBPATH` (binary path inside each build dir), `HARNESS_ARGS` (`@@` = input) |
| `build-afl-fast.sh` | Uncomment your build system (autoconf / cmake / meson), set `SRC_GIT_URL`; mirror into `build-afl-asan.sh` and `build-afl-cmplog.sh` |
| `fetch-seeds.sh`  | Fill `SOURCES=()` with 2–5 seed repos: `label|url|extension`                |
| `filter-seeds.sh` | Set `VALID_MAGIC_HEX` (e.g. `"25504446"` for PDF) and `VALID_EXTENSIONS`   |
| `apt-packages.txt` | Optional extra Debian packages for this target's build (one per line)      |

Then bootstrap and launch:

```sh
# One command for sync + seed prep + 3 builds + cmin + systemd start.
bash shared/bootstrap-target.sh mytool

# Wait ~30 s for calibration, then:
bash shared/check-in.sh
# mytool  3  <execs/s>  0  0  0  0   ← 3 fuzzers alive, zero crashes yet
```

Every step is idempotent; re-run the one that failed after fixing the edit.

Before you bootstrap, inspect the target summary:

```sh
bash shared/inspect-target.sh mytool
```

## AFL++ assumptions

This toolkit is intentionally opinionated around a baseline AFL++ workflow:

- fast build
- ASAN build
- CMPLOG build
- three long-lived workers (`primary`, `asan`, `explore`)
- dictionary support via `scripts/<target>.dict`
- seed scraping, filtering, and corpus minimization
- crash triage via ASAN/GDB-style post-processing

That baseline is what the current helpers, skills, watchdog, and review flow
understand.

## Not first-class yet

`fuzzah` does **not** currently automate grammar-aware or schema-aware target
types as a first-class workflow. In practice that means:

- no built-in custom mutator build/install flow
- no grammar/tree sidecar directory conventions
- no grammar-aware seed generation bootstrap
- no mutator-specific crash replay/triage assumptions

If you want to go there, use the current toolkit as the process shell and layer
your mutator work in manually for now. Good starting points:

- AFL++ custom mutators: https://aflplus.plus/docs/custom_mutators/
- AFL++ Grammar-Mutator: https://github.com/AFLplusplus/Grammar-Mutator
- libprotobuf-mutator: https://github.com/google/libprotobuf-mutator

---

## Daily ops

Two commands cover 90% of what you'll do:

```sh
bash shared/check-in.sh    # fuzz domain: crashes, workflow state
bash shared/rig-check.sh   # system domain: memory, OOM, systemd, disk
```

Or from an agent session:

| task                    | Claude Code                    | Codex                         |
|-------------------------|--------------------------------|-------------------------------|
| fuzz dashboard          | `/check-in`                    | `$check-in`                   |
| system health           | `/rig-check`                   | `$rig-check`                  |
| one target's status     | `/fuzz-status mytool`          | `$fuzz-status mytool`         |
| list crashes            | `/fuzz-crashes mytool`         | `$fuzz-crashes mytool`        |
| triage one crash        | `/fuzz-review <hash> mytool`   | `$fuzz-review <hash> mytool`  |

### Crash triage workflow

Every unique crash lands at `~/fuzzing/targets/<t>/crashes-triaged/<hash>/`
with `meta.json` + `trace.txt` + `poc.bin`, and moves through states:

```
new → reviewed → repro-ok → reported     (progress)
  \→ dup                                  (duplicate of another hash)
  \→ ignore                               (false positive / noise)
```

Mark state:

```sh
bash shared/run-on-fuzz-host.sh \
  'echo reviewed > "$HOME/fuzzing/targets/mytool/crashes-triaged/<hash>/.status"'
```

The `fuzz-crash-review` skill (Claude + Codex) walks classification —
loads the trace, inspects source at the top frame, recommends action.

---

## Orb troubleshooting

On macOS, an OrbStack control-plane failure does **not** usually mean your fuzz
state is gone. The backing disk image persists separately from the CLI state.

- Orb-backed commands fail but `vmgr.log` still shows `container started`:
  the backend likely booted, but the client/proxy path is wedged.
- `orbctl status` says `Stopped` while the helper is alive:
  treat `orbctl status` as advisory only and probe with a real `orb -m ...`
  command before assuming the VM is absent.
- `proxy dialer did not pass back a connection` or `mm_receive_fd`:
  OrbStack is stuck in the proxy handoff path. Fully quit and relaunch the app;
  if it persists, reboot macOS.
- very large `OrbStack Helper vmgr` RSS on the Mac host:
  the helper is likely wedged; quit and relaunch OrbStack before trusting any
  status output.

Useful commands:

```sh
bash shared/orb-debug.sh
bash shared/rig-check.sh
```

On macOS, the persisted OrbStack disk image is usually under:

```sh
$HOME/Library/Group Containers/*.dev.orbstack/data/data.img.raw
```

That image is where your `~/fuzzing/targets/*/{findings,crashes-triaged}` data
lives, so access failures are usually a control-plane problem rather than a
data-loss event.

---

## What To Commit

Safe to commit/push from a target setup dir like `<control-root>/poppler-setup/`
(or one of the illustration examples under `fuzzah/examples/`, e.g.
`fuzzah/examples/jq/`):

- `SETUP.md`
- `scripts/*.sh`
- `scripts/*.dict`
- `scripts/*-fuzz.service`
- `scripts/apt-packages.txt`

Do not commit/push runtime artifacts from the fuzz host:

- `src/`
- `build-afl/`, `build-afl-asan/`, `build-afl-cmplog/`
- large generated seed corpora
- `findings/`
- `crashes-triaged/`

---

## Design notes

**Three workers per target.** Standard AFL++ multi-core pattern: `primary`
accumulates coverage-enriched entries; `asan` runs the ASAN build so
crashes come with stack traces without taxing the master's execs/s;
`explore` uses the broader power schedule to prioritize novel paths.

**CMPLOG on primary.** CMPLOG logs comparison operands at runtime and
feeds them back to the mutator — the difference between "random bytes"
and "the exact magic sentinel the parser expects" for format-heavy
targets. Often worth 10× in coverage growth.

**`-m 1024` on fast workers, `-m none` on ASAN.** AFL++ applies `-m`
as `RLIMIT_AS` on the target child. ASAN pre-allocates tebibytes of
virtual address space for shadow memory, so any finite limit kills it
at startup. Fast workers get 1 GB — high enough for normal decodes,
low enough that six concurrent children can't OOM an 8 GB host.

**Watchdog at 5 minutes.** systemd's `Restart=on-failure` handles
service-level crashes. The watchdog covers the sub-service case where
one `afl-fuzz` worker dies and its siblings keep running — without it,
a dead worker silently drops a third of throughput.

## Tuning when things feel slow

- **Seeds** — the biggest lever. 20 curated seeds beat 2000 random ones.
  Favor diverse samples. Re-run `min-corpus.sh` after adding any.
- **Dict files** — drop one at `scripts/<target>.dict` in the target setup
  (preferred, self-contained) or at
  `$HOME/fuzzing/tools/AFLplusplus/dictionaries/<target>.dict`. `start-fuzz.sh`
  now prefers the target-local file and falls back to AFL++'s shared
  dictionaries. AFL++ ships dicts for pdf, json, xml, png, and more.
- **Persistent-mode harness** — 10–100× execs/s on fork-heavy targets.
  Worth it if you're stuck below 1k execs/s on a fast machine.
- **Timeout** — `start-fuzz.sh` uses 3000 ms (fast) / 5000 ms (ASAN).
  Raise for legitimate slow inputs; lower if the queue fills with
  pathological long-runners.

---

## Troubleshooting

**Watchdog keeps respawning workers.** OOM flap. Run `rig-check` and
read the dmesg section. ASAN children that balloon to 6+ GB are normal
(watchdog handles it). Fast-build children over 1 GB are not — inspect
with `pgrep -af afl-fuzz`.

**`dmesg` shows OOM kills at `total-vm ≈ 38 TB`.** That's ASAN shadow
memory. The RSS number tells you the real pressure. Sporadic: expected.
More than 10/hour: investigate.

**`check-in` shows `execs/s < 200` for a target.** Either calibration
(wait a minute), a slow harness (you may have picked a binary that
renders when you wanted a parse), or pathological inputs in the queue
(check `hangs/`).

**Memlimit-kill entries cluttering `new` state.** `triage-one.sh`
auto-tags new ones as `ignore`. For old pre-fix entries, bulk-sweep:

```sh
cd ~/fuzzing/targets/<t>/crashes-triaged
for d in */; do
  tf=$(python3 -c "import json;print(json.load(open('$d/meta.json')).get('top_frame',''))" 2>/dev/null)
  [[ "$tf" != "no-frames"* ]] && continue
  asan=$(python3 -c "import json;print(json.load(open('$d/meta.json')).get('fuzzers',{}).get('asan',0))" 2>/dev/null)
  [[ "$asan" == "0" ]] && echo ignore > "$d/.status"
done
```

**Without orb?** Use any Linux host. `shared/*.sh` auto-detects — if
`$HOME/fuzzing/targets/` exists locally, it runs commands directly
instead of via `orb`.

**Without Claude or Codex?** Every script in `shared/` and
`target-template/` is pure bash. Agents just wrap them with summaries.
Run the rig entirely from the CLI if you prefer.

---

## What's not included

- **No default CVE scrape.** Seed sources are target-specific; wire
  your own in `fetch-seeds.sh`.
- **No libfuzzer / honggfuzz / libafl integration.** AFL++ only by design.
- **No coverage visualization.** `afl-cov` exists; adding it would
  balloon the kit's scope.
- **No email or Slack alerts.** Crashes land in `crashes-triaged/<hash>/`
  and in `INDEX.md` — wire your own alerting on top.
- **No upstream bug-report templates.** Write your own in each target's
  `SETUP.md` once you land a real bug.

## License

Personal fuzzing rig, shared as-is. AFL++ itself is Apache-2.0 (see
upstream). This kit contains no copyleft code; do what you want with it.
