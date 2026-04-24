---
name: fuzz-add-target
description: Use when standing up a new AFL++ fuzz target. Triggers on "add new target", "set up fuzzing for X", "fuzz <name>", "new fuzz target", "start fuzzing <library>". Walks the full pipeline (seeds → 3 builds → cmin → triage → systemd) adapted to the target's build system (cmake / autoconf / meson / custom). Uses the fuzzah kit's `target-template/` as the starting point.
---

# Add a Fuzz Target

Brings a new target online with three build variants (plain AFL /
AFL+ASAN+UBSAN / AFL+CMPLOG), a minimized seed corpus, a triage loop, and a
systemd unit. Safe to invoke on an in-progress target — reuses existing
state where possible.

Throughout: use `shared/run-on-fuzz-host.sh` for commands that must execute on
the fuzz host. It auto-detects direct Linux execution vs Orb and ensures `~` /
`$HOME` expand inside the fuzz host.

## Phase 1: Scope

Ask the operator (one at a time, not a wall of questions):

1. **Target name** — used as the dir name under `~/fuzzing/targets/`.
2. **Upstream repo URL** — git clone source.
3. **Fuzz entry point** — a CLI binary OR a dedicated fuzz harness in the
   source tree. Specify binary name + argument shape (e.g. `@@` file arg,
   stdin, etc.).
4. **Build system** — cmake / autoconf (configure) / meson / bazel / custom.
5. **Seed corpus sources** — 2–5 public repos/URLs with sample inputs. Keep
   under ~200 KB per file; prefer diversity.
6. **Any known tricky deps** — e.g. "wants yasm", "needs pkg-config", etc.

Confirm the list back before building anything.

## Phase 2: Scaffold

Prefer the helper scripts:

```
bash shared/scaffold-target.sh <target>
bash shared/sync-target.sh <target>
```

`scaffold-target.sh` creates the host-side edit copy under the detected
control root (`FUZZAH_CONTROL_ROOT` if set, otherwise the parent repo if
`fuzzah/` is nested there). `sync-target.sh` pushes `SETUP.md` plus the
`scripts/` tree into `~/fuzzing/targets/<target>/` on the fuzz host.

## Phase 3: Edit the small set of per-target values

All scripts auto-derive the target name from their filesystem location, so
you never hardcode it. The **three** things you do edit per target:

1. In `start-fuzz.sh`, set `HARNESS_SUBPATH` (e.g. `bin/mytool` or
   `utils/myparser`) and `HARNESS_ARGS` (e.g. `"@@ /dev/null"` or
   `"@@ -o /dev/null"`).
2. In `build-afl-fast.sh` / `asan.sh` / `cmplog.sh`, set the
   `$SRC/configure` (or cmake/meson) invocation for the target's build
   system. Preserve the env vars and sanitizer flags that are already
   wired up.
3. In `fetch-seeds.sh`, list the upstream seed sources (clone URLs +
   subdirs inside them containing valid inputs).

Everything else (`filter-seeds.sh`, `triage-one.sh`, `triage-loop.sh`,
`start-fuzz.sh`, `stop-fuzz.sh`, `status.sh`, `min-corpus.sh`, `harden.sh`,
the systemd unit) is already generic — no per-target edits
needed beyond file-magic values in `filter-seeds.sh` (first N bytes the
format starts with) and any format-specific file extensions.

## Phase 4: Build-system quick reference

| System     | Minimal build invocation (with AFL++) |
|------------|---------------------------------------|
| cmake      | `cmake -S src -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)` |
| autoconf   | `cd src && ./configure --disable-shared && make -j$(nproc)` |
| meson      | `meson setup build src && meson compile -C build` |
| custom     | Check upstream's README or `configure` script for expected flags |

For each of the three build variants, keep the sanitizer env:

- **fast build** — nothing extra
- **asan** — `AFL_USE_ASAN=1 AFL_USE_UBSAN=1` + `CFLAGS="-g -O1 -fno-omit-frame-pointer"`
- **cmplog** — `AFL_LLVM_CMPLOG=1`

Each build must end with a sanity check (run the binary on one seed).

## Phase 5: Execute the pipeline

Prefer the one-shot helper:

```
bash shared/bootstrap-target.sh <target>
```

This runs sync + harden + seed prep + the three builds + cmin + systemd
enable/start.

If you need to debug manually, run one phase at a time through the wrapper:

```
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash harden.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash fetch-seeds.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash filter-seeds.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash build-afl-fast.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash build-afl-asan.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash build-afl-cmplog.sh'
bash shared/run-on-fuzz-host.sh 'cd "$HOME/fuzzing/targets/<target>/scripts" && bash min-corpus.sh'
```

Then bring up the rig:
```
bash shared/run-on-fuzz-host.sh 'bash "$HOME/fuzzing/targets/<target>/scripts/start-fuzz.sh"'
```

## Phase 6: Systemd unit

Rename the template unit to match the target and install:
```
cp "$HOME/fuzzing/targets/<target>/scripts/<target>-fuzz.service" \
   "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now <target>-fuzz.service
```

## Phase 7: Verify and document

1. Wait ~2 minutes for calibration to finish.
2. Invoke `$fuzz-status <target>` (Codex) or `/fuzz-status <target>` (Claude)
   — expect 3 fuzzers alive, nonzero execs/sec.
3. Let it run ~10 minutes, check if any crashes appear.
4. Update the root `AGENTS.md` / `CLAUDE.md` to list the new target if you
   keep a target roster there.
5. Write a `SETUP.md` inside the target dir with any target-specific notes
   (tricky build flags, seed provenance, known harness limitations).

## Common pitfalls

- **tmux session name collision** — default session per target is
  `<target>-fuzz`. The auto-derived `SESSION="${SESSION:-$(basename
  "$TARGET_DIR")-fuzz}"` in `start-fuzz.sh` handles this cleanly; don't
  override `SESSION` unless you know why.
- **Disk pressure** — each target keeps a `src/` + 3 build dirs + findings.
  Budget 5–15 GB per target. `df -h` before starting a new target.
- **Core contention** — each target runs 3 fuzzers. On a 10-core host, two
  targets × 3 = 6 busy cores plus triage + watchdog. Don't run 3+ targets
  concurrently without tuning fuzzer counts down.
- **Memory limits (-m)** — `start-fuzz.sh` ships with `-m 1024` on fast
  builds and `-m none` on ASAN. ASAN needs unbounded virtual; fast builds
  need a cap to survive pathological inputs. Don't blanket-change either
  without understanding why.
- **Egress block** — `harden.sh` may set nftables rules that affect the
  host VM-wide. If a later target needs network for seed fetch, temporarily
  allow tcp/443 during fetch-seeds, then restore the block.
