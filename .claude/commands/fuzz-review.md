---
description: Review a single crash by hash — loads meta.json, trace.txt, and invokes the fuzz-crash-review skill to classify and recommend action. Usage: /fuzz-review <hash> <target>
argument-hint: "<hash> <target>"
allowed-tools: Bash(orb -m fuzzer:*), Bash(bash:*)
---

Deep-dive a specific crash.

Parse `$ARGUMENTS` as `<hash> <target>`.

1. Load the crash artifacts:
   ```bash
   read hash target <<< "$ARGUMENTS"
   if [[ -z "$hash" || -z "$target" ]]; then
     echo "usage: /fuzz-review <hash> <target>" >&2
     exit 1
   fi
   bash shared/run-on-fuzz-host.sh "cat \"\$HOME/fuzzing/targets/${target}/crashes-triaged/${hash}/meta.json\""
   bash shared/run-on-fuzz-host.sh "head -120 \"\$HOME/fuzzing/targets/${target}/crashes-triaged/${hash}/trace.txt\""
   ```

2. Apply the `fuzz-crash-review` skill's per-crash workflow (classify,
   inspect top-frame source, recommend action) to just this one hash.
   Output a concise verdict in this format:

   ```
   Hash:       <hash>
   Class:      <memory-bug | ubsan | assertion | segv | trap | no-frames | dup-likely>
   Severity:   <HIGH | MED | LOW | UNKNOWN>
   Top frame:  <sym> at <file>:<line>
   Verdict:    <one-line summary>
   Action:     <file-upstream | investigate | ignore-intended | dup | wontfix-already-fixed>
   Reasoning:  <2–4 sentences>
   ```

3. If the user asks follow-ups (reproduce, read more source, draft a bug
   report), handle from here.
