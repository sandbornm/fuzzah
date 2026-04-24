---
name: fuzz-review
description: Deep-dive a specific crash by hash. Loads meta.json + trace.txt and applies the fuzz-crash-review per-crash workflow (classify by signal class, inspect top-frame source, recommend action). Use when the operator asks to review, triage, or explain a specific crash hash, or invokes $fuzz-review <hash> <target>. Equivalent of /fuzz-review in Claude Code.
---

Parse the invocation arguments as `<hash> <target>`.

1. Load the crash artifacts:

   ```bash
   hash="${HASH:?hash required}"
   target="${TARGET:?target required}"
   runner="$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/run-on-fuzz-host.sh"
   bash "$runner" "cat \"\$HOME/fuzzing/targets/${target}/crashes-triaged/${hash}/meta.json\""
   bash "$runner" "head -120 \"\$HOME/fuzzing/targets/${target}/crashes-triaged/${hash}/trace.txt\""
   ```

2. Apply the `fuzz-crash-review` skill's per-crash workflow (classify,
   inspect top-frame source, recommend action) for this one hash. Output a
   concise verdict:

   ```
   Hash:       <hash>
   Class:      <memory-bug | ubsan | assertion | segv | trap | no-frames | dup-likely>
   Severity:   <HIGH | MED | LOW | UNKNOWN>
   Top frame:  <sym> at <file>:<line>
   Verdict:    <one-line summary>
   Action:     <file-upstream | investigate | ignore-intended | dup | wontfix-already-fixed>
   Reasoning:  <2–4 sentences>
   ```

3. If the operator asks follow-ups (reproduce, read more source, draft a
   bug report), continue from there.
