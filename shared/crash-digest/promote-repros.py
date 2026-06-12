#!/usr/bin/env python3
"""Promote interesting triaged crashes to reproducible reports.

This script runs on the fuzz host. It does not fuzz; it replays existing
crashes, writes durable artifacts into each crash directory, and advances
reproducible actionable crashes to `.status = repro-ok`.

Artifacts:
  REPORT.md  - phone-friendly summary for the dashboard
  REPRO.md   - replay command and observed output
  POC.md     - exact PoC/reproducer code or shell
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SHARED_DIR = SCRIPT_DIR.parent
RUN_ON_HOST = SHARED_DIR / "run-on-fuzz-host.sh"
HEX12 = re.compile(r"^[0-9a-f]{12}$")
NOISE_RE = re.compile(r"(memlimit|timeout|unknown-js-crash|unknown-sig|no-frames|killed|rc=124|rc=137)", re.I)
DONE_STATES = {"ignore", "dup", "reported"}
PROMOTABLE_STATES = {"new", "review-requested", "reviewed", "repro-ok"}
FRAME_LOC_RE = re.compile(r"\((?P<path>.*?/src/(?P<rel>lib/[^:]+)):(?P<line>\d+):(?P<col>\d+)\)")


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def maybe_reexec_on_fuzz_host() -> None:
    if platform.system() == "Linux" and (Path.home() / "fuzzing").is_dir():
        return
    if not RUN_ON_HOST.exists():
        return
    argv = " ".join(sh_quote(a) for a in sys.argv[1:])
    cmd = f"python3 {sh_quote(str(Path(__file__).resolve()))} {argv}".strip()
    r = subprocess.run(["bash", str(RUN_ON_HOST), cmd], text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    raise SystemExit(r.returncode)


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return default


def write_text(path: Path, text: str) -> None:
    path.write_text(text)


def read_json(path: Path) -> dict:
    try:
        with path.open() as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None


def status_of(crash_dir: Path) -> str:
    parts = read_text(crash_dir / ".status", "new").strip().split()
    return parts[0] if parts else "new"


def symbolized(frame: str) -> bool:
    return bool(frame and frame != "?" and not NOISE_RE.search(frame))


def parse_start_fuzz(script: Path) -> tuple[str, str]:
    text = read_text(script)
    harness_subpath = ""
    harness_args = "@@"
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("HARNESS_SUBPATH="):
            harness_subpath = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("HARNESS_ARGS="):
            harness_args = line.split("=", 1)[1].strip().strip('"').strip("'")
    return harness_subpath, harness_args


def shell_reproducer(target_dir: Path, crash_dir: Path, meta: dict, timeout_s: int) -> str:
    reproducer = str(meta.get("reproducer") or "").strip()
    if reproducer:
        return f"timeout {timeout_s} bash -lc {sh_quote(reproducer)}"

    target = target_dir.name
    harness_subpath, harness_args = parse_start_fuzz(target_dir / "scripts" / "start-fuzz.sh")
    if not harness_subpath:
        harness_subpath = target
    poc = first_existing([crash_dir / "poc.bin", crash_dir / "poc.pdf", crash_dir / "poc.original.bin", crash_dir / "poc.original.pdf"])
    if poc is None:
        raise FileNotFoundError(f"no PoC file in {crash_dir}")
    asan_bin = target_dir / "build-afl-asan" / harness_subpath
    fast_bin = target_dir / "build-afl" / harness_subpath
    binary = asan_bin if asan_bin.exists() else fast_bin
    if not binary.exists():
        raise FileNotFoundError(f"no replay binary found: {asan_bin} or {fast_bin}")

    if "@@" in harness_args:
        args = harness_args.replace("@@", shlex.quote(str(poc)))
    else:
        args = f"{harness_args} < {shlex.quote(str(poc))}"
    return (
        f"timeout {timeout_s} env "
        "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0:halt_on_error=1:print_stacktrace=1 "
        "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 "
        f"{shlex.quote(str(binary))} {args}"
    )


def classify(text: str, top_frame: str, rc: int, timed_out: bool) -> tuple[str, str, str]:
    blob = f"{top_frame}\n{text}"
    low = blob.lower()
    if timed_out:
        return "timeout", "LOW", "investigate if repeatable outside timeout"
    if any(x in low for x in ("heap-buffer-overflow", "stack-buffer-overflow", "heap-use-after-free", "double-free", "global-buffer-overflow")):
        return "memory-bug", "HIGH", "file-upstream"
    if "undefinedbehaviorsanitizer" in low or "runtime error:" in low:
        return "ubsan", "MED", "file-upstream"
    if "sigsegv" in low or "segmentation fault" in low:
        return "segv", "HIGH", "file-upstream"
    if "sigtrap" in low:
        return "trap", "MED", "investigate"
    if "unexpected fuzz harness exception" in low or "node-abort" in low or rc in (134, 139):
        return "js-exception", "MED", "investigate"
    if rc != 0:
        return "nonzero-replay", "LOW", "investigate"
    return "no-repro", "INFO", "monitor"


def excerpt(text: str, max_lines: int = 80, max_chars: int = 12000) -> str:
    lines = text.splitlines()[:max_lines]
    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars] + "\n...[truncated]"
    return out


def frame_location(top_frame: str) -> tuple[str, int, int] | None:
    match = FRAME_LOC_RE.search(top_frame or "")
    if not match:
        return None
    try:
        return match.group("rel"), int(match.group("line")), int(match.group("col"))
    except ValueError:
        return None


def source_excerpt(target_dir: Path, top_frame: str, radius: int = 7) -> tuple[str, str]:
    loc = frame_location(top_frame)
    if not loc:
        return "", ""
    rel, line, _col = loc
    path = target_dir / "src" / rel
    text = read_text(path)
    if not text:
        return rel, ""
    lines = text.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    out = []
    for n in range(start, end + 1):
        marker = ">" if n == line else " "
        out.append(f"{marker} {n:5d} {lines[n - 1]}")
    return rel, "\n".join(out)


def node_oracledb_assessment(meta: dict, top_frame: str, output: str) -> dict:
    frame = top_frame or ""
    blob = f"{frame}\n{output}"
    assessment = {
        "issue_class": "thin-js-exception",
        "surface": "unknown Thin-mode parser surface",
        "impact": "robustness",
        "severity": "LOW",
        "confidence": "medium",
        "report_priority": 45,
        "triage_verdict": "Reproducible JavaScript exception. No ASAN/native memory-corruption signal was observed.",
        "reachability": "Unknown from the harness alone; confirm against the product call path before filing as security.",
        "harness_notes": "The harness converts unexpected JavaScript exceptions to process aborts so AFL records them. The abort itself is not the product bug.",
        "recommended_action": "Review the product call path and decide whether this should be filed as parser hardening or security DoS.",
    }

    if "ERR_OUT_OF_RANGE" in blob or "ERR_BUFFER_OUT_OF_BOUNDS" in blob:
        assessment["triage_verdict"] = (
            "Node.js Buffer bounds exception in JavaScript parser code. This is not native memory corruption; "
            "it is an unhandled parser exception/DoS signal if reachable in normal node-oracledb flows."
        )

    if "OsonDecoder" in frame:
        assessment.update(
            {
                "surface": "OSON binary JSON decoder",
                "impact": "parser-dos",
                "severity": "MED",
                "confidence": "high",
                "report_priority": 78,
                "reachability": (
                    "Potentially reachable when Thin mode decodes OSON/JSON payloads from the database or local OSON data. "
                    "Malformed OSON should reject cleanly instead of throwing raw TypeError/RangeError."
                ),
                "recommended_action": "Prioritize for upstream robustness/security review; add bounds/depth validation and a clean driver error.",
            }
        )
        if "Maximum call stack size exceeded" in blob:
            assessment.update(
                {
                    "issue_class": "oson-recursion-dos",
                    "impact": "stack-exhaustion-dos",
                    "report_priority": 86,
                    "triage_verdict": (
                        "Recursive OSON decoding can exhaust the JavaScript stack. This is a stronger DoS signal than a simple short-buffer read."
                    ),
                }
            )
        elif "_getFieldNames" in frame:
            assessment["issue_class"] = "oson-field-name-bounds"
        elif "_decodeContainerNode" in frame:
            assessment["issue_class"] = "oson-container-bounds"
    elif "EZConnectResolver" in frame:
        assessment.update(
            {
                "issue_class": "easy-connect-parser-exception",
                "surface": "Easy Connect connection string parser",
                "impact": "input-validation-robustness",
                "severity": "LOW",
                "confidence": "high",
                "report_priority": 62,
                "reachability": (
                    "Reachable through connection-string parsing. Security impact depends on whether an application accepts untrusted connection strings."
                ),
                "recommended_action": "File as a clean input-validation bug if the PoC is a plausible connection string; otherwise keep as robustness.",
            }
        )
    elif any(name in frame for name in ("AcceptPacket", "RefusePacket", "RedirectPacket", "MarkerPacket")):
        assessment.update(
            {
                "issue_class": "sqlnet-short-packet-bounds",
                "surface": "SQL*Net receive packet parser",
                "impact": "client-side-parser-dos",
                "severity": "MED",
                "confidence": "medium",
                "report_priority": 58,
                "reachability": (
                    "Likely reachable only from packets supplied by an Oracle listener/server or a network attacker able to tamper with SQL*Net traffic. "
                    "The PoCs are very short synthetic packets, so confirm against the real session state machine before treating as security."
                ),
                "recommended_action": "Group these by packet class and review for missing minimum-length checks before each Buffer read.",
            }
        )
    elif "DataPacket." in frame:
        assessment.update(
            {
                "issue_class": "sqlnet-send-path-harness-amplified",
                "surface": "SQL*Net DataPacket send helper",
                "impact": "harness-amplified",
                "severity": "LOW",
                "confidence": "medium",
                "report_priority": 35,
                "reachability": (
                    "Lower confidence: the harness calls send-path helpers after constructing a packet from arbitrary bytes. "
                    "This may not correspond to a real product receive path."
                ),
                "recommended_action": "Deprioritize unless a normal node-oracledb call path can reach the same invalid state.",
            }
        )

    if "Attempt to access memory outside buffer bounds" in blob:
        assessment["harness_notes"] += (
            " The phrase 'memory outside buffer bounds' is Node's safe Buffer bounds check, not proof of C/C++ memory corruption."
        )
    return assessment


def target_assessment(target_dir: Path, meta: dict, top_frame: str, output: str, fallback_severity: str, fallback_action: str) -> dict:
    if target_dir.name == "node-oracledb" or meta.get("target_kind") == "node-oracledb-thin-js":
        return node_oracledb_assessment(meta, top_frame, output)
    return {
        "issue_class": "generic-crash",
        "surface": "target harness",
        "impact": "unknown",
        "severity": fallback_severity,
        "confidence": "medium",
        "report_priority": 55 if fallback_action == "file-upstream" else 45,
        "triage_verdict": "Generic crash classification; inspect sanitizer output and source context.",
        "reachability": "Unknown from generic harness metadata.",
        "harness_notes": "No target-specific assessment is available.",
        "recommended_action": fallback_action,
    }


def poc_script(target_dir: Path, crash_dir: Path, command: str, meta: dict) -> str:
    target = target_dir.name
    poc = first_existing([crash_dir / "poc.bin", crash_dir / "poc.pdf", crash_dir / "poc.original.bin", crash_dir / "poc.original.pdf"])
    poc_name = poc.name if poc else "poc.bin"
    sha = sha256_file(poc) if poc else "?"
    size = poc.stat().st_size if poc and poc.exists() else 0
    if target == "node-oracledb" or meta.get("target_kind") == "node-oracledb-thin-js":
        mode_set = str(meta.get("fuzz_mode_set") or "").strip()
        mode_export = f'export FUZZ_MODE_SET="${{FUZZ_MODE_SET:-{mode_set}}}"\n' if mode_set else ""
        code = f"""#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${{TARGET_DIR:-$HOME/fuzzing/targets/node-oracledb}}"
POC="${{1:-$TARGET_DIR/crashes-triaged/{crash_dir.name}/{poc_name}}}"

export NODE_ORACLEDB_SRC="${{NODE_ORACLEDB_SRC:-$TARGET_DIR/src}}"
export NODE_OPTIONS="${{NODE_OPTIONS:---max-old-space-size=128}}"
{mode_export.rstrip()}

node --stack_size=1024 "$TARGET_DIR/scripts/fuzz-harness.js" "$POC"
"""
        note = "Node.js replay script for the Thin-mode parser harness."
    else:
        code = f"""#!/usr/bin/env bash
set -euo pipefail

{command}
"""
        note = "Shell replay script for the target harness."
    return f"""---
generated_at: {iso_now()}
target: {target}
hash: {crash_dir.name}
poc_file: {poc_name}
poc_size: {size}
poc_sha256: {sha}
---

# PoC / Reproducer

{note}

```sh
{code.rstrip()}
```

PoC artifact: `{poc_name}` ({size} bytes, sha256 `{sha}`).
"""


def write_artifacts(target_dir: Path, crash_dir: Path, command: str, rc: int, output: str, reproduced: bool, klass: str, severity: str, action: str, timed_out: bool, meta: dict) -> None:
    status = status_of(crash_dir)
    top_frame = meta.get("top_frame") or meta.get("signature") or "?"
    first_seen = meta.get("first_seen") or "?"
    hit_count = int(meta.get("hit_count") or 0)
    when = iso_now()
    out_excerpt = excerpt(output)
    assessment = target_assessment(target_dir, meta, str(top_frame), output, severity, action)
    severity = str(assessment.get("severity") or severity)
    action = str(assessment.get("recommended_action") or action)
    report_priority = int(assessment.get("report_priority") or 0)
    source_rel, source_ctx = source_excerpt(target_dir, str(top_frame))

    repro_md = f"""---
reproduced_at: {when}
target: {target_dir.name}
hash: {crash_dir.name}
reproduced: {str(reproduced).lower()}
class: {klass}
severity: {severity}
action: {action}
exit_code: {rc}
timeout: {str(timed_out).lower()}
issue_class: {assessment.get("issue_class")}
impact: {assessment.get("impact")}
confidence: {assessment.get("confidence")}
report_priority: {report_priority}
---

# Reproduction

```sh
{command}
```

Result: `rc={rc}`, reproduced=`{str(reproduced).lower()}`, class=`{klass}`.

## Output Excerpt

```text
{out_excerpt}
```
"""
    write_text(crash_dir / "REPRO.md", repro_md)
    write_text(crash_dir / "POC.md", poc_script(target_dir, crash_dir, command, meta))

    summary = (
        f"Reproducible `{assessment.get('issue_class')}` in `{target_dir.name}` at `{top_frame}`."
        if reproduced
        else f"Replay did not reproduce a crash for `{target_dir.name}` at `{top_frame}`."
    )
    source_section = ""
    if source_ctx:
        source_section = f"""
## Source Context

`{source_rel}`

```js
{source_ctx}
```
"""
    report_md = f"""---
generated_at: {when}
target: {target_dir.name}
hash: {crash_dir.name}
status_at_start: {status}
reproduced: {str(reproduced).lower()}
class: {klass}
severity: {severity}
action: {action}
issue_class: {assessment.get("issue_class")}
impact: {assessment.get("impact")}
confidence: {assessment.get("confidence")}
report_priority: {report_priority}
---

# Crash Report

## Summary

{summary}

## Signal

- Top frame: `{top_frame}`
- First seen: `{first_seen}`
- Hit count: `{hit_count}`
- Replay classification: `{klass}`
- Assessed issue class: `{assessment.get("issue_class")}`
- Impact: `{assessment.get("impact")}`
- Severity: `{severity}`
- Confidence: `{assessment.get("confidence")}`
- Report priority: `{report_priority}/100`
- Recommended action: `{action}`

## Assessment

{assessment.get("triage_verdict")}

Reachability: {assessment.get("reachability")}

Harness note: {assessment.get("harness_notes")}

{source_section}

## Reproduction

The replay command and observed output are in `REPRO.md`. The copy/paste PoC
script is in `POC.md`.

```sh
{command}
```

## Output Excerpt

```text
{out_excerpt}
```

## Next Step

{assessment.get("recommended_action")}
"""
    write_text(crash_dir / "REPORT.md", report_md)
    if reproduced and status not in DONE_STATES:
        write_text(crash_dir / ".status", "repro-ok\n")


def run_repro(command: str, timeout_s: int) -> tuple[int, str, bool]:
    try:
        r = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=timeout_s + 5)
        return r.returncode, (r.stdout or "") + (r.stderr or ""), False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout or b"").decode(errors="replace")
        err = (e.stderr or "") if isinstance(e.stderr, str) else (e.stderr or b"").decode(errors="replace")
        return 124, out + err, True


def candidates(targets_dir: Path, only_target: str | None, force: bool) -> list[tuple[int, Path, Path, dict]]:
    out = []
    for target_dir in sorted(p for p in targets_dir.iterdir() if p.is_dir() and not p.name.startswith("_")):
        if only_target and target_dir.name != only_target:
            continue
        triaged = target_dir / "crashes-triaged"
        if not triaged.is_dir():
            continue
        for crash_dir in sorted(p for p in triaged.iterdir() if p.is_dir() and HEX12.match(p.name)):
            status = status_of(crash_dir)
            if not force and (status in DONE_STATES or status not in PROMOTABLE_STATES):
                continue
            if not force and (crash_dir / "REPORT.md").is_file() and (crash_dir / "POC.md").is_file() and status == "repro-ok":
                continue
            meta = read_json(crash_dir / "meta.json")
            top_frame = meta.get("top_frame") or meta.get("signature") or "?"
            if status == "new" and not symbolized(top_frame):
                continue
            hits = int(meta.get("hit_count") or 0)
            score = hits
            score += {"repro-ok": 70, "reviewed": 60, "review-requested": 50, "new": 30}.get(status, 0)
            score += 20 if (crash_dir / "REVIEW.md").is_file() else 0
            score += 10 if (crash_dir / "NOTES.md").is_file() else 0
            score += 15 if symbolized(top_frame) else -20
            out.append((score, target_dir, crash_dir, meta))
    out.sort(key=lambda row: row[0], reverse=True)
    return out


def main() -> int:
    maybe_reexec_on_fuzz_host()
    p = argparse.ArgumentParser(description="promote triaged crashes to reproducible reports")
    p.add_argument("--target", help="target name to process")
    p.add_argument("--limit", type=int, default=int(os.environ.get("FUZZ_DIGEST_REPRO_LIMIT", "6")))
    p.add_argument("--timeout", type=int, default=int(os.environ.get("FUZZ_DIGEST_REPRO_TIMEOUT", "45")))
    p.add_argument("--force", action="store_true", help="regenerate existing reports")
    args = p.parse_args()

    targets_dir = Path(os.environ.get("TARGETS_DIR", str(Path.home() / "fuzzing" / "targets")))
    if not targets_dir.is_dir():
        print(f"[promote-repros] no targets dir: {targets_dir}")
        return 0

    ledger = Path.home() / "fuzzing" / "logs" / "crash-digest-repro.log"
    ledger.parent.mkdir(parents=True, exist_ok=True)

    selected = candidates(targets_dir, args.target, args.force)[: max(0, args.limit)]
    print(f"[promote-repros] selected={len(selected)} limit={args.limit}")
    done = 0
    for _score, target_dir, crash_dir, meta in selected:
        key = f"{target_dir.name}/{crash_dir.name}"
        try:
            command = shell_reproducer(target_dir, crash_dir, meta, args.timeout)
            rc, output, timed_out = run_repro(command, args.timeout)
            klass, severity, action = classify(output or read_text(crash_dir / "trace.txt"), str(meta.get("top_frame") or "?"), rc, timed_out)
            reproduced = (rc != 0 and klass != "timeout") or klass in {"memory-bug", "ubsan", "segv", "trap", "js-exception"}
            write_artifacts(target_dir, crash_dir, command, rc, output, reproduced, klass, severity, action, timed_out, meta)
            print(f"[promote-repros] {key}: reproduced={reproduced} class={klass} severity={severity} rc={rc}")
            with ledger.open("a") as f:
                f.write(f"{iso_now()}\t{key}\t{reproduced}\t{klass}\t{severity}\t{rc}\n")
            done += 1
        except Exception as e:
            print(f"[promote-repros] {key}: failed: {e}", file=sys.stderr)
            with ledger.open("a") as f:
                f.write(f"{iso_now()}\t{key}\tfailed\t{e}\n")
    print(f"[promote-repros] done={done}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
