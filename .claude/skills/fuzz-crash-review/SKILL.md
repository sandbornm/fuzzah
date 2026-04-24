---
name: fuzz-crash-review
description: Use when reviewing, triaging, or classifying AFL++ crashes in ~/fuzzing/targets/*/crashes-triaged/. Triggers on "review crashes", "triage crashes", "look at the crashes", "what bugs did we find", "classify crashes", "which crashes matter". Reads INDEX.md + trace.txt per hash, classifies by bug type and severity, inspects source at the top frame, and outputs a prioritized action table.
---

# Fuzz Crash Review

Systematic triage of crashes collected by the AFL++ fuzz rig. Operates on
triaged output at `~/fuzzing/targets/<target>/crashes-triaged/` inside the
fuzzer host/VM.

## Workflow

1. **Scope** — confirm the target. If multiple targets exist and it's
   ambiguous, ask the operator. (Target = the directory name under
   `~/fuzzing/targets/`.)

2. **Read roster** — run through the shared wrapper so `~` / `$HOME` expand on
   the fuzz host:
   ```
   bash shared/run-on-fuzz-host.sh 'cat "$HOME/fuzzing/targets/<target>/crashes-triaged/INDEX.md"'
   ```
   Note each `<hash>`, `first_seen`, `fuzzer`, `hit_count`, `top_frame`.

3. **Per-crash inspection** — for each hash:
   a. Read `meta.json` for hit count, fuzzers, sizes.
   b. Read `trace.txt` (first 80–120 lines). The file has two sections:
      `=== ASAN output ===` and `=== GDB backtrace (fallback) ===`.
   c. Classify into one of:

      | Class | Signature | Severity | Notes |
      |-------|-----------|----------|-------|
      | **memory-bug**   | ASAN report: `heap-buffer-overflow`, `heap-use-after-free`, `stack-buffer-overflow` | HIGH | Real bug; file upstream |
      | **ubsan**        | ASAN log contains `UndefinedBehaviorSanitizer` / `runtime error:` | MED  | Real bug unless in a known-benign path |
      | **assertion**    | GDB bt shows `abort`/`__assert_fail`/internal `error(-1, …)` | LOW  | Usually WAI — parser rejected malformed input |
      | **segv**         | GDB: `SIGSEGV`, non-sanitizer top frame | HIGH | Treat as real memory bug |
      | **trap**         | GDB: `SIGTRAP`, top frame is application code (not `__ubsan`) | MED  | Check source — could be `__builtin_trap` from a safe-arithmetic check |
      | **memlimit-kill**| `top_frame` starts with `memlimit-kill` | — | Auto-tagged artifact of the `-m` cap; already `.status=ignore` |
      | **no-frames**    | `top_frame` starts with `no-frames`; check `fuzzers` field: if `asan > 0`, potential stack corruption (keep); if `asan == 0`, likely memlimit slippage (ignore) | varies | |
      | **dup-likely**   | Same `top_frame` as an earlier triaged hash | — | Possibly mis-hashed; note but deprioritize |

   d. Look up source at `top_frame` (GDB output shows file:line already).
      Optional: read a few lines of context with:
      ```
      bash shared/run-on-fuzz-host.sh 'sed -n "<start>,<end>p" "$HOME/fuzzing/targets/<target>/src/<file>"'
      ```

4. **Recommend action** — per crash, pick one:
   - **file-upstream** — real memory-safety bug; the PoC is ready
   - **investigate** — ambiguous; worth reproducing under a debugger
   - **ignore-intended** — target's own error handler correctly rejecting bad input
   - **wontfix-already-fixed** — top frame matches a known-fixed upstream bug
   - **dup** — same root cause as another hash

5. **Output** — a single markdown table, severity-descending. Columns:
   `hash | class | severity | top_frame | action | rationale`. Then a short
   paragraph: counts by class, and what you'd do next if you were the human.

## Reproducing a crash for deeper analysis

The ASAN build's binary is at `~/fuzzing/targets/<target>/build-afl-asan/<harness>`
where `<harness>` is the harness subpath declared in the target's
`start-fuzz.sh`. Example invocation:

```
env ASAN_OPTIONS=symbolize=1:detect_leaks=0 \
  ~/fuzzing/targets/<target>/build-afl-asan/<harness-subpath> \
  ~/fuzzing/targets/<target>/crashes-triaged/<hash>/poc.<ext> <extra-args>
```

Check the target's `SETUP.md` or `start-fuzz.sh` for the exact binary path
and harness invocation for that target.

## Tone

Be decisive. "This is a heap-buffer-overflow in ParserX::readToken at line
996, worth filing upstream" is better than "This could potentially be a
memory issue that may warrant further review." If something is genuinely
ambiguous, say so and pick the next step rather than hedging forever.

## Don't

- Don't re-run the fuzzer or restart anything — review only.
- Don't modify `crashes-triaged/` or `INDEX.md` without asking.
- Don't attempt to fix bugs in the target's source from this skill; filing
  them upstream is the end state.
