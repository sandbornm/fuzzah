# Target: `jq-filter` (example)

> **Illustration-only.** This directory lives under `fuzzah/examples/` as a
> reference for what a filled-in `<target>-setup/` looks like — specifically
> a dictionary-assisted byte-fuzzing target for a language input (jq filter
> programs). It stays within the byte-oriented rig scope; no custom mutator
> is involved. The systemd unit ships as `jq-filter-fuzz.service.example` on
> purpose. See [fuzzah/examples/README.md](../README.md) for how to promote
> this example into a live `jq-filter-setup/` target at the control root.

Once promoted, the operator runbook copy of this doc lives at
`~/fuzzing/targets/jq-filter/SETUP.md` on the fuzz host.

## Quick facts

- **Upstream repo:** `https://github.com/jqlang/jq.git`
- **Harness:** `build-afl{,-asan,-cmplog}/jq -n -f @@ >/dev/null`
- **Input format:** jq filter programs (`.jq`)  (no magic-byte gate)
- **Systemd unit (when live):** `jq-filter-fuzz.service` (shipped here as `.example`)
- **tmux session:** `jq-filter-fuzz`
- **Expected throughput:** establish after the first real run; depends heavily
  on seed mix and worker count

## Per-target edits applied

Changes from `fuzzah/target-template/*` that are specific to this target:

- `start-fuzz.sh` — `HARNESS_SUBPATH=`… , `HARNESS_ARGS=`…
- `fetch-seeds.sh` — SOURCES entries
- `filter-seeds.sh` — `VALID_MAGIC_HEX` + `VALID_EXTENSIONS`
- `build-afl-fast.sh` / `-asan.sh` / `-cmplog.sh` — configure/cmake/meson invocation
- `jq-filter.dict` — target-local jq grammar tokens and operator fragments
- `jq-filter-fuzz.service` — renamed from `TARGET-fuzz.service`, paths updated

## Concrete choices

- **Release:** `jq-1.8.1`
- **Seed sources:** `jqlang/jq`, `itchyny/gojq`, `01mf02/jaq`, plus a small
  handwritten starter corpus in `fetch-seeds.sh`
- **Dictionary strategy:** keep the dictionary in `scripts/jq-filter.dict`
  rather than depending on a shared AFL++ install path
- **Scope:** this target is for jq **filter grammar / parser / compiler**
  coverage. Keep it separate from the JSON-input `jq` target.

## Bootstrap

From inside the host/VM at `~/fuzzing/targets/jq-filter/`:

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

- `jq-filter` and `jq` should stay separate. Mixing `.jq` filters and JSON
  data into one target would dilute coverage and make triage noisier.
- `-n -f @@` primarily exercises parsing, compilation, and no-input execution
  paths. If you want heavy evaluator coverage against real JSON inputs, use the
  `jq` target instead.

## Example seeds

Representative handwritten filters that are worth keeping tiny and readable:

```jq
.
.foo
select(type == "object")
reduce .[] as $x (0; . + $x)
def f: . + 1; f
try .foo catch .
```

## Known bugs found

_(Link to upstream bug reports + triaged hashes here as you file them.)_

## Safe to commit

Safe to commit/push from this example dir (`fuzzah/examples/jq-filter/`) —
same set that is safe to commit from a live `jq-filter-setup/` after
promotion:

- `SETUP.md`
- `scripts/*.sh`
- `scripts/jq-filter.dict`
- `scripts/jq-filter-fuzz.service`
- `scripts/apt-packages.txt`

Do not commit runtime artifacts from the fuzz host:

- `src/`
- `build-afl*/`
- generated seed corpora
- `findings/`
- `crashes-triaged/`
