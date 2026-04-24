# Target: `jq` (example)

> **Illustration-only.** This directory lives under `fuzzah/examples/` as a
> reference for what a filled-in `<target>-setup/` looks like. The systemd
> unit ships as `jq-fuzz.service.example` on purpose — nothing here is wired
> up to the live fuzz host. See [fuzzah/examples/README.md](../README.md)
> for how to promote this example into a live `jq-setup/` target at the
> control root.

Once promoted, the operator runbook copy of this doc lives at
`~/fuzzing/targets/jq/SETUP.md` on the fuzz host.

## Quick facts

- **Upstream repo:** `https://github.com/jqlang/jq.git`
- **Harness:** `build-afl{,-asan,-cmplog}/jq . @@ >/dev/null`
- **Input format:** JSON text (`.json`)  (no magic-byte gate)
- **Systemd unit (when live):** `jq-fuzz.service` (shipped here as `.example`)
- **tmux session:** `jq-fuzz`
- **Expected throughput:** establish after the first real run; depends heavily
  on seed mix and worker count

## Per-target edits applied

Changes from `fuzzah/target-template/*` that are specific to this target:

- `start-fuzz.sh` — `HARNESS_SUBPATH=`… , `HARNESS_ARGS=`…
- `fetch-seeds.sh` — SOURCES entries
- `filter-seeds.sh` — `VALID_MAGIC_HEX` + `VALID_EXTENSIONS`
- `build-afl-fast.sh` / `-asan.sh` / `-cmplog.sh` — configure/cmake/meson invocation
- `jq.dict` — target-local JSON token dictionary
- `jq-fuzz.service` — renamed from `TARGET-fuzz.service`, paths updated

## Concrete choices

- **Release:** `jq-1.8.1`
- **Seed sources:** `jqlang/jq`, `nst/JSONTestSuite`,
  `nlohmann/json_test_data`, `miloyip/nativejson-benchmark`,
  `minimaxir/big-list-of-naughty-strings`
- **Dictionary strategy:** keep the dictionary in `scripts/jq.dict`
  rather than depending on a shared AFL++ install path
- **Scope:** this target is for jq **JSON input parsing/execution**. Keep it
  separate from the jq filter-grammar target.

## Bootstrap

From inside the host/VM at `~/fuzzing/targets/jq/`:

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

- This target feeds JSON data to a fixed filter (`.`). It is intentionally not
  a grammar target for jq programs.
- For evaluator or parser bugs tied to jq filter syntax, use `jq-filter`
  instead of expanding this target.

## Example seeds

Representative JSON fragments that are worth keeping around even after cmin:

```json
{}
[]
{"foo":1}
{"nested":{"arr":[1,true,null,"x"]}}
["\u0000","\ud800","\uffff"]
18446744073709551616
```

## Known bugs found

_(Link to upstream bug reports + triaged hashes here as you file them.)_

## Safe to commit

Safe to commit/push from this example dir (`fuzzah/examples/jq/`) — same set
that is safe to commit from a live `jq-setup/` after promotion:

- `SETUP.md`
- `scripts/*.sh`
- `scripts/jq.dict`
- `scripts/jq-fuzz.service`
- `scripts/apt-packages.txt`

Do not commit runtime artifacts from the fuzz host:

- `src/`
- `build-afl*/`
- generated seed corpora
- `findings/`
- `crashes-triaged/`
