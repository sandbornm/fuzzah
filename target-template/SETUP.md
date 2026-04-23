# Target: `<TARGET>`

> Rename this file and fill in the blanks once the target is online. This doc
> lives alongside the target's scripts (`~/fuzzing/targets/<target>/SETUP.md`)
> and serves as the operator runbook for this specific target.

## Quick facts

- **Upstream repo:** <URL>
- **Harness:** `build-afl{,-asan,-cmplog}/<path-to-binary>`
- **Input format:** <e.g. PDF / IVF / PNG>  (magic bytes: `<hex>`)
- **Systemd unit:** `<target>-fuzz.service`
- **tmux session:** `<target>-fuzz`
- **Expected throughput:** ~N execs/sec cumulative across 3 workers

## Per-target edits applied

Changes from `fuzzah/target-template/*` that are specific to this target:

- `start-fuzz.sh` — `HARNESS_SUBPATH=`… , `HARNESS_ARGS=`…
- `fetch-seeds.sh` — SOURCES entries
- `filter-seeds.sh` — `VALID_MAGIC_HEX` + `VALID_EXTENSIONS`
- `build-afl-fast.sh` / `-asan.sh` / `-cmplog.sh` — configure/cmake/meson invocation
- `<target>-fuzz.service` — renamed from `TARGET-fuzz.service`, paths updated

## Bootstrap

From inside the host/VM at `~/fuzzing/targets/<target>/`:

```sh
# 0. deps + core_pattern (one-shot; pass --block-egress if you want the network
#    restricted after seed fetch completes)
bash scripts/harden.sh

# 1. seeds
bash scripts/fetch-seeds.sh
bash scripts/filter-seeds.sh

# 2. build all three variants
bash scripts/build-afl-fast.sh
bash scripts/build-afl-asan.sh
bash scripts/build-afl-cmplog.sh

# 3. minimize corpus against the fast build
bash scripts/min-corpus.sh

# 4. start the rig (or enable the systemd unit for auto-restart on reboot)
bash scripts/start-fuzz.sh
```

## Quirks / known issues

_(Fill in any target-specific weirdness: odd build deps, parser-level
input validation gotchas, checksums to bypass, persistent-mode notes, etc.)_

## Known bugs found

_(Link to upstream bug reports + triaged hashes here as you file them.)_
