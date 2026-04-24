# fuzzah examples

Filled-in, illustration-only `<target>-setup/` directories that show what the
blank `fuzzah/target-template/` looks like once the per-target edits have been
applied. Read these when standing up a new target to see concrete examples of:

- autoconf-based build flows (`configure && make`) vs. the cmake baseline
- a simple byte-input harness (`jq/`) against a fixed filter
- a dictionary-heavy language-input harness (`jq-filter/`) against a filter
  program, staying within the byte-oriented rig scope

## Layout

```text
fuzzah/examples/
  jq/           # jq JSON-input target   (filter = .)
    SETUP.md
    scripts/
      *.sh
      apt-packages.txt
      jq.dict
      jq-fuzz.service.example
  jq-filter/    # jq filter-program target  (harness = -n -f @@)
    SETUP.md
    scripts/
      *.sh
      apt-packages.txt
      jq-filter.dict
      jq-filter-fuzz.service.example
```

## Not live

These are **reference material only**. No live fuzz runs depend on them. The
systemd units ship as `*.service.example` on purpose — installing one would
need a corresponding `<target>-setup/` dir at the control root, which does not
exist for these examples until you promote them (see below).

Also note: neither target is bug-ripe. `jq` has been continuously fuzzed by
OSS-Fuzz since ~2018. These examples exist to demonstrate rig mechanics, not
to find new bugs. Use for learning the harness, not for research.

## Promoting an example to a live target — 1, 2, 3

Pick a name (e.g. `jq-filter`). From the control root:

```bash
# 1. Scaffold + copy per-target edits from this example, then rename the
#    service template so it will actually be installed.
NAME=jq-filter
bash fuzzah/shared/scaffold-target.sh "$NAME"
cp fuzzah/examples/"$NAME"/scripts/{build-afl-*.sh,fetch-seeds.sh,filter-seeds.sh,start-fuzz.sh,*.dict,apt-packages.txt} "$NAME"-setup/scripts/
cp fuzzah/examples/"$NAME"/SETUP.md "$NAME"-setup/
cp fuzzah/examples/"$NAME"/scripts/"$NAME"-fuzz.service.example "$NAME"-setup/scripts/"$NAME"-fuzz.service

# 2. Bootstrap — sync to host, harden, seed, 3 builds, cmin, enable+start systemd.
bash fuzzah/shared/bootstrap-target.sh "$NAME"

# 3. Verify.
bash shared/run-on-fuzz-host.sh 'bash "$HOME/fuzzing/targets/'"$NAME"'/scripts/status.sh"'
#   or just:   /fuzz-status jq-filter    (Claude)   /   $fuzz-status jq-filter   (Codex)
```

Expect 3 fuzzers alive and nonzero execs/sec within ~2 minutes. If step 2
fails at the build stage, re-run the individual phase manually (see the
fuller list of `run-on-fuzz-host.sh` invocations in `fuzz-add-target`
skill).

## Keeping examples fresh

If `fuzzah/target-template/` gains a new file or convention, update the
examples too, so future readers see the current canonical shape. Examples
that lag behind the template are worse than no examples.
