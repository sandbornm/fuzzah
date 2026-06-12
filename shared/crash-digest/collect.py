#!/usr/bin/env python3
"""Collect live fuzz/crash state as JSON for crash digest email generation.

Runs on the fuzz host. The sender consumes this snapshot and decides what is
interesting enough to mail; this collector only normalizes filesystem state.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SHARED_DIR = SCRIPT_DIR.parent
RUN_ON_HOST = SHARED_DIR / "run-on-fuzz-host.sh"
HEX12 = re.compile(r"^[0-9a-f]{12}$")


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def on_fuzz_host() -> bool:
    """True when this process is already running on the AFL fuzz host (the VM)."""
    return platform.system() == "Linux" and (Path.home() / "fuzzing").is_dir()


def collect_vm_snapshot_via_proxy() -> dict | None:
    """Return the AFL/VM snapshot, collected from the fuzz host.

    On the fuzz host (or when no proxy is available) we return ``None`` so the
    caller enumerates AFL targets locally — the byte-for-byte original path. On a
    control host (e.g. macOS) we re-run this same collector inside the VM via
    run-on-fuzz-host.sh and parse its JSON. The host (jackalope) lane is read
    separately on the local filesystem and is never proxied.
    """
    if on_fuzz_host() or not RUN_ON_HOST.exists():
        return None
    cmd = f"python3 {sh_quote(str(Path(__file__).resolve()))}"
    r = subprocess.run(["bash", str(RUN_ON_HOST), cmd], text=True, capture_output=True)
    if r.returncode != 0:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        raise SystemExit(r.returncode)
    text = r.stdout
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        raise SystemExit("collect.py: VM collector did not emit JSON")
    try:
        return json.loads(text[start : end + 1])
    except ValueError:
        sys.stderr.write(r.stderr)
        raise SystemExit("collect.py: could not parse VM collector JSON")


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return default


def read_json(path: Path) -> dict:
    try:
        with path.open() as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def normalize_status(text: str) -> str:
    parts = (text or "").strip().split()
    return parts[0] if parts else "new"


def parse_frontmatter(text: str) -> dict:
    if not text.startswith("---\n"):
        return {}
    meta: dict[str, str] = {}
    lines = text.splitlines()
    for line in lines[1:]:
        if line.strip() == "---":
            return meta
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip()
    return {}


def read_report_meta(crash_dir: Path) -> dict:
    report = crash_dir / "REPORT.md"
    if not report.is_file():
        return {}
    meta = parse_frontmatter(read_text(report))
    if "report_priority" in meta:
        try:
            meta["report_priority"] = int(meta["report_priority"])
        except (TypeError, ValueError):
            meta.pop("report_priority", None)
    return meta


def live_pid(pid: str) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def parse_stats(path: Path) -> dict:
    data: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        data[k.strip()] = v.strip()
    pid = data.get("fuzzer_pid", "")
    data["role"] = path.parent.name
    data["alive"] = live_pid(pid)
    try:
        data["stats_age_s"] = max(0, int(dt.datetime.now().timestamp()) - int(path.stat().st_mtime))
    except (OSError, ValueError):
        data["stats_age_s"] = None
    return data


def collect_roles(target_dir: Path) -> list[dict]:
    findings = target_dir / "findings"
    if not findings.is_dir():
        return []
    roles = []
    for stats in sorted(findings.glob("*/fuzzer_stats")):
        roles.append(parse_stats(stats))
    return roles


def count_raw_backlog(target_dir: Path) -> dict:
    findings = target_dir / "findings"
    seen_path = target_dir / "logs" / "triage-seen.txt"
    seen = set(read_text(seen_path).splitlines())
    by_role: dict[str, int] = {}
    unseen = 0
    total = 0
    if not findings.is_dir():
        return {"total": 0, "unseen": 0, "by_role": {}}
    for crashes_dir in sorted(findings.glob("*/crashes")):
        role = crashes_dir.parent.name
        for crash in crashes_dir.glob("id:*"):
            if not crash.is_file():
                continue
            total += 1
            by_role[role] = by_role.get(role, 0) + 1
            key = f"{role}/{crash.name}"
            if key not in seen:
                unseen += 1
    return {"total": total, "unseen": unseen, "by_role": by_role}


def poc_files(crash_dir: Path) -> list[dict]:
    out = []
    for name in ("poc.original.pdf", "poc.pdf", "poc.original.bin", "poc.bin"):
        path = crash_dir / name
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        out.append({"name": name, "size": size})
    return out


def collect_crashes(target_dir: Path) -> tuple[list[dict], dict[str, int]]:
    triaged = target_dir / "crashes-triaged"
    rows = []
    state_counts: dict[str, int] = {}
    if not triaged.is_dir():
        return rows, state_counts
    for crash_dir in sorted(p for p in triaged.iterdir() if p.is_dir() and HEX12.match(p.name)):
        status = normalize_status(read_text(crash_dir / ".status", "new"))
        meta = read_json(crash_dir / "meta.json")
        report_meta = read_report_meta(crash_dir)
        state_counts[status] = state_counts.get(status, 0) + 1
        rows.append(
            {
                "hash": crash_dir.name,
                "status": status,
                "top_frame": meta.get("top_frame") or meta.get("signature") or "?",
                "hit_count": int(meta.get("hit_count") or 0),
                "first_seen": meta.get("first_seen") or "?",
                "last_seen": meta.get("last_seen") or meta.get("first_seen") or "?",
                "target_kind": meta.get("target_kind") or "",
                "has_notes": (crash_dir / "NOTES.md").is_file(),
                "has_review": (crash_dir / "REVIEW.md").is_file(),
                "has_report": (crash_dir / "REPORT.md").is_file(),
                "has_repro": (crash_dir / "REPRO.md").is_file(),
                "has_poc": (crash_dir / "POC.md").is_file(),
                "issue_class": report_meta.get("issue_class", ""),
                "impact": report_meta.get("impact", ""),
                "confidence": report_meta.get("confidence", ""),
                "report_priority": report_meta.get("report_priority"),
                "assessed_severity": report_meta.get("severity", ""),
                "poc_files": poc_files(crash_dir),
                "dashboard_path": f"/c/{target_dir.name}/{crash_dir.name}",
            }
        )
    return rows, state_counts


def collect_target(target_dir: Path) -> dict:
    roles = collect_roles(target_dir)
    crashes, state_counts = collect_crashes(target_dir)
    try:
        execs_per_sec = sum(float(r.get("execs_per_sec") or 0) for r in roles if r.get("alive"))
    except ValueError:
        execs_per_sec = 0.0
    return {
        "name": target_dir.name,
        "path": str(target_dir),
        "dashboard_path": f"/t/{target_dir.name}",
        "roles": roles,
        "alive_roles": sum(1 for r in roles if r.get("alive")),
        "execs_per_sec": execs_per_sec,
        "raw_crashes": count_raw_backlog(target_dir),
        "state_counts": state_counts,
        "crashes": crashes,
    }


# ---------------------------------------------------------------------------
# Host (macOS) lane: jackalope targets under ~/fuzzing-mac/targets.
#
# This lane lives on the local filesystem of the control host and is read
# directly (never via run-on-fuzz-host.sh). A jackalope target has an `engine`
# file plus a normalized findings/stats.json instead of AFL's per-role
# fuzzer_stats. Its crashes-triaged/<hash>/ dirs carry meta.json + .status but
# none of the AFL-replay enrichment (REPORT.md / REPRO.md / POC.md).
# ---------------------------------------------------------------------------


def host_poc_files(crash_dir: Path) -> list[dict]:
    out = []
    for path in sorted(crash_dir.glob("poc.*")):
        if not path.is_file() or path.name.endswith(".md"):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        out.append({"name": path.name, "size": size})
    return out


def collect_host_crashes(target_dir: Path) -> tuple[list[dict], dict[str, int]]:
    triaged = target_dir / "crashes-triaged"
    rows = []
    state_counts: dict[str, int] = {}
    if not triaged.is_dir():
        return rows, state_counts
    for crash_dir in sorted(p for p in triaged.iterdir() if p.is_dir() and (p / "meta.json").is_file()):
        status = normalize_status(read_text(crash_dir / ".status", "new"))
        meta = read_json(crash_dir / "meta.json")
        state_counts[status] = state_counts.get(status, 0) + 1
        try:
            hit_count = int(meta.get("hit_count") or 0)
        except (TypeError, ValueError):
            hit_count = 0
        rows.append(
            {
                "hash": crash_dir.name,
                "status": status,
                "engine": "jackalope",
                "top_frame": meta.get("top_frame") or meta.get("signature") or "?",
                "signature": meta.get("signature") or "",
                "hit_count": hit_count,
                "first_seen": meta.get("first_seen") or "?",
                "last_seen": meta.get("last_seen") or meta.get("first_seen") or "?",
                "target_kind": meta.get("engine") or "jackalope",
                "fuzzers": meta.get("fuzzers") or "",
                "poc_size": meta.get("poc_size"),
                # jackalope crashes are triaged by their own lane; the AFL-replay
                # enrichment docs are intentionally absent (see README follow-up).
                "has_notes": (crash_dir / "NOTES.md").is_file(),
                "has_review": (crash_dir / "REVIEW.md").is_file(),
                "has_report": (crash_dir / "REPORT.md").is_file(),
                "has_repro": (crash_dir / "REPRO.md").is_file(),
                "has_poc": (crash_dir / "POC.md").is_file(),
                "has_trace": (crash_dir / "trace.txt").is_file(),
                "issue_class": "",
                "impact": "",
                "confidence": "",
                "report_priority": None,
                "assessed_severity": "",
                "poc_files": host_poc_files(crash_dir),
                "dashboard_path": f"/c/{target_dir.name}/{crash_dir.name}",
            }
        )
    return rows, state_counts


def collect_host_target(target_dir: Path) -> dict:
    stats = read_json(target_dir / "findings" / "stats.json")
    engine = read_text(target_dir / "engine").strip() or stats.get("engine") or "jackalope"
    crashes, state_counts = collect_host_crashes(target_dir)
    alive = bool(stats.get("alive"))
    try:
        execs_per_sec = float(stats.get("execs_per_sec") or 0)
    except (TypeError, ValueError):
        execs_per_sec = 0.0
    try:
        saved_total = int(stats.get("saved_crashes") or 0)
    except (TypeError, ValueError):
        saved_total = 0
    # Synthesize a single engine "role" so role-aware consumers keep working.
    role = {
        "role": engine,
        "engine": engine,
        "alive": alive,
        "execs_per_sec": stats.get("execs_per_sec"),
        "execs_done": stats.get("execs_done"),
        "corpus_count": stats.get("corpus_count"),
        "coverage": stats.get("coverage"),
        "saved_crashes": stats.get("saved_crashes"),
        "last_find": stats.get("last_find"),
        "start_time": stats.get("start_time"),
        "pid": stats.get("pid"),
    }
    return {
        "name": target_dir.name,
        "path": str(target_dir),
        "engine": engine,
        "dashboard_path": f"/t/{target_dir.name}",
        "roles": [role] if stats else [],
        "alive_roles": 1 if alive else 0,
        "execs_per_sec": execs_per_sec,
        "coverage": stats.get("coverage"),
        "corpus_count": stats.get("corpus_count"),
        "execs_done": stats.get("execs_done"),
        # No AFL-style raw crash backlog: the lane triages its own crashes, so
        # there is nothing here for the digest's triage-drain to chew on.
        "raw_crashes": {"total": saved_total, "unseen": 0, "by_role": {}},
        "state_counts": state_counts,
        "crashes": crashes,
    }


def collect_afl_targets(targets_dir: Path) -> list[dict]:
    targets = []
    if targets_dir.is_dir():
        for target_dir in sorted(p for p in targets_dir.iterdir() if p.is_dir() and not p.name.startswith("_")):
            targets.append(collect_target(target_dir))
    return targets


def collect_host_targets(mac_dir: Path) -> list[dict]:
    targets = []
    if mac_dir.is_dir():
        for target_dir in sorted(p for p in mac_dir.iterdir() if p.is_dir() and not p.name.startswith("_")):
            targets.append(collect_host_target(target_dir))
    return targets


def main() -> int:
    vm_snapshot = collect_vm_snapshot_via_proxy()
    targets_dir = Path(os.environ.get("TARGETS_DIR", str(Path.home() / "fuzzing" / "targets")))
    if vm_snapshot is None:
        afl_targets = collect_afl_targets(targets_dir)
        afl_targets_dir = str(targets_dir)
    else:
        afl_targets = vm_snapshot.get("targets", [])
        afl_targets_dir = vm_snapshot.get("targets_dir", str(targets_dir))

    mac_dir = Path(os.environ.get("MAC_TARGETS_DIR", str(Path.home() / "fuzzing-mac" / "targets")))
    host_targets = collect_host_targets(mac_dir)

    snapshot = {
        "generated_at": iso_now(),
        "host": platform.node(),
        "targets_dir": afl_targets_dir,
        "mac_targets_dir": str(mac_dir),
        "targets": afl_targets + host_targets,
    }
    json.dump(snapshot, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
