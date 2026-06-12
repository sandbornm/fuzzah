#!/usr/bin/env python3
"""fuzz-dashboard — browser TUI for the fuzzig/fuzzah AFL++ rig.

Stdlib-only. Run as a foreground server, bind 127.0.0.1, port-forward via
SSH from your local machine. Queries the live fuzz host via
shared/run-on-fuzz-host.sh so it works the same on a Mac with orb or
on the fuzz host itself.
"""

import argparse
import html
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

THIS_FILE = Path(__file__).resolve()
SHARED_DIR = THIS_FILE.parent.parent
RUN_ON_HOST = SHARED_DIR / "run-on-fuzz-host.sh"
CHECK_IN = SHARED_DIR / "check-in.sh"
READ_ONLY = os.environ.get("FUZZ_DASHBOARD_READ_ONLY", "").lower() in {"1", "true", "yes", "on"}

# macOS-host (jackalope/TinyInst) targets live on the LOCAL fs, not the VM. They
# expose a normalized findings/stats.json instead of AFL's fuzzer_stats and are
# reached without orb. Everything keyed on this root is the additive host-target
# lane; VM (afl) targets are untouched.
HOST_TARGETS_ROOT = Path(
    os.environ.get("FUZZAH_HOST_TARGETS_ROOT", os.path.expanduser("~/fuzzing-mac/targets"))
)


# ---------- VM-side data access ----------

def run_on_host(cmd, timeout=20):
    """Run a shell command on the fuzz host (orb VM on Mac, local on Linux)."""
    try:
        r = subprocess.run(
            ["bash", str(RUN_ON_HOST), cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"timeout after {timeout}s", -1
    except FileNotFoundError as e:
        return "", f"missing: {e}", -2


class TTLCache:
    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def get(self, key, ttl, fn):
        now = time.time()
        with self._lock:
            hit = self._d.get(key)
            if hit and hit[1] > now:
                return hit[0]
        # compute outside the lock so a slow call doesn't block readers
        val = fn()
        with self._lock:
            self._d[key] = (val, now + ttl)
        return val

    def invalidate(self, prefix=""):
        with self._lock:
            for k in list(self._d):
                if k.startswith(prefix):
                    del self._d[k]


CACHE = TTLCache()


def vm_path(p):
    """Convert a Python-side path (which may start with `~/`) into a form safe
    to embed in a VM-side shell command, with `~` correctly expanded to $HOME.

    shlex.quote() wraps the path in single quotes, which suppresses ~ expansion
    in bash. For `~/` paths we therefore emit `"$HOME/rest"` using double
    quotes. CALLER MUST validate any user-supplied components (target, hash)
    against a strict regex before constructing the path. All current callers
    do (target matches [a-zA-Z0-9_-]+, hash matches [0-9a-f]{12}).
    """
    if p.startswith("~/"):
        return '"$HOME/' + p[2:] + '"'
    return shlex.quote(p)


def read_reviews_ledger(target):
    """Sum the per-target reviews ledger. Returns {count, cost_usd, seconds}.
    Ledger is tab-separated: reviewed_at frame hash model cost_usd tok_in tok_out seconds."""
    path = f"~/fuzzing/targets/{target}/crashes-triaged/reviews-ledger.tsv"
    out, _, _ = run_on_host(f'cat {vm_path(path)} 2>/dev/null', timeout=10)
    count, cost, secs = 0, 0.0, 0
    for line in (out or "").splitlines():
        cols = line.split("\t")
        if len(cols) < 8:
            continue
        count += 1
        try:
            cost += float(cols[4])
        except ValueError:
            pass
        try:
            secs += int(cols[7])
        except ValueError:
            pass
    return {"count": count, "cost_usd": cost, "seconds": secs}


def fetch_check_in():
    out, err, rc = run_on_host(f'bash "$HOME/fuzzig-shared/check-in.sh" 2>&1 || bash {shlex.quote(str(CHECK_IN))} 2>&1', timeout=30)
    return out or err or f"(rc={rc})"


def host_ping():
    """Quick reachability probe. Returns (ok, error_message)."""
    out, err, rc = run_on_host('echo READY', timeout=8)
    if rc != 0 or "READY" not in out:
        return False, (err or out or f"rc={rc}").strip()
    return True, ""


def list_targets():
    out, _, _ = run_on_host('ls ~/fuzzing/targets/ 2>/dev/null')
    return sorted(t.strip() for t in out.splitlines() if t.strip() and not t.startswith('_'))


def target_proc_count(target):
    """Count of live afl-fuzz processes for a target (independent of fuzzer_stats freshness)."""
    out, _, _ = run_on_host(f'pgrep -cf "afl-fuzz .* targets/{shlex.quote(target)}/" 2>/dev/null || echo 0', timeout=8)
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def host_health():
    """Aggregate health summary used by the index banner. Cached at the route layer."""
    reachable, err = host_ping()
    if not reachable:
        return {"reachable": False, "error": err}
    targets = list_targets()
    summary = {
        "reachable": True, "targets": targets, "by_target": {},
        "total_alive": 0, "total_calibrating": 0,
        "total_execs_per_sec": 0.0, "total_crashes": 0,
    }
    for t in targets:
        roles = target_roles(t)
        alive = sum(1 for r in roles if r['alive'])
        eps = sum(float(r['execs_per_sec'] or 0) for r in roles if r['alive'])
        crashes = max((int(r['unique_crashes']) for r in roles if r['unique_crashes'].isdigit()), default=0)
        proc = target_proc_count(t)
        calibrating = max(0, proc - alive)
        summary["by_target"][t] = {
            "alive": alive, "calibrating": calibrating,
            "proc": proc, "execs_per_sec": eps, "crashes": crashes,
            "roles_seen": len(roles),
        }
        summary["total_alive"] += alive
        summary["total_calibrating"] += calibrating
        summary["total_execs_per_sec"] += eps
        summary["total_crashes"] += crashes

    # ADDITIVE: append macOS-host (jackalope) targets. Local fs, no VM round-trip.
    # The VM target data above is untouched; these only extend the summary.
    for t in list_host_targets():
        if t in summary["by_target"]:
            continue
        roles = roles_for(t)
        alive = sum(1 for r in roles if r['alive'])
        eps = sum(float(r['execs_per_sec'] or 0) for r in roles if r['alive'])
        crashes = max((int(r['unique_crashes']) for r in roles if r['unique_crashes'].isdigit()), default=0)
        summary["by_target"][t] = {
            "alive": alive, "calibrating": 0, "proc": alive,
            "execs_per_sec": eps, "crashes": crashes, "roles_seen": len(roles),
        }
        summary["targets"].append(t)
        summary["total_alive"] += alive
        summary["total_execs_per_sec"] += eps
        summary["total_crashes"] += crashes
    return summary


FUZZER_STATS_FIELDS = [
    "fuzzer_pid", "execs_per_sec", "execs_done", "last_find",
    "pending_total", "pending_favs", "unique_crashes", "saved_crashes",
    "saved_hangs", "corpus_count", "bitmap_cvg", "stability",
    "cycles_done", "cycles_wo_finds", "start_time",
]


def target_roles(target):
    """Per-role snapshot from fuzzer_stats. Returns list of dicts with rich fields."""
    fields = "|".join(f'$(awk "/^{f} /{{print \\$NF}}" "$f")' for f in FUZZER_STATS_FIELDS)
    cmd = (
        f'cd ~/fuzzing/targets/{shlex.quote(target)}/findings 2>/dev/null && '
        'for r in primary asan explore secondary; do '
        '  f=$r/fuzzer_stats; '
        '  [ -f "$f" ] || continue; '
        '  mt=$(stat -c "%Y" "$f"); now=$(date +%s); '
        '  pid=$(awk "/^fuzzer_pid/{print \\$NF}" "$f"); '
        '  alive=N; kill -0 "$pid" 2>/dev/null && alive=Y; '
        f'  echo "$r|$alive|$((now-mt))|{fields}"; '
        'done'
    )
    out, _, _ = run_on_host(cmd)
    roles = []
    for line in out.strip().splitlines():
        parts = line.split('|')
        # role + alive + stats_age + 15 fields = 18 columns
        if len(parts) != 3 + len(FUZZER_STATS_FIELDS):
            continue
        d = {
            "role": parts[0],
            "alive": parts[1] == "Y",
            "stats_age_s": int(parts[2]) if parts[2].isdigit() else -1,
        }
        for i, f in enumerate(FUZZER_STATS_FIELDS):
            d[f] = parts[3 + i].strip()
        # convenience aliases / numeric coercion
        d["pid"] = d["fuzzer_pid"]
        try:
            d["last_find_age_s"] = max(0, int(time.time()) - int(d["last_find"]))
        except (ValueError, KeyError):
            d["last_find_age_s"] = None
        roles.append(d)
    return roles


VALID_STATES = {"new", "review-requested", "reviewed", "repro-ok", "reported", "dup", "ignore"}


def set_status_on_host(target, h, new_state):
    """Write .status for a crash dir. Validates target/hash/state. Returns (ok, msg)."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', target):
        return False, "bad target"
    if not re.match(r'^[0-9a-f]{12}$', h):
        return False, "bad hash"
    if new_state not in VALID_STATES:
        return False, f"bad state {new_state!r}"
    path = f"~/fuzzing/targets/{target}/crashes-triaged/{h}/.status"
    qpath = vm_path(path)
    cmd = f'd=$(dirname {qpath}); [ -d "$d" ] && echo {shlex.quote(new_state)} > {qpath} && echo OK || echo MISSING_DIR'
    out, err, rc = run_on_host(cmd, timeout=8)
    if rc != 0:
        return False, err or out or f"rc={rc}"
    if "OK" not in out:
        return False, out.strip() or "write failed"
    CACHE.invalidate(f"status:{target}:{h}")
    CACHE.invalidate(f"crashes:{target}")
    return True, "ok"


def recommend_next_step(status, hits_str, has_notes):
    """Map (status, hit count, NOTES.md presence) → (short label, longer hint)."""
    s = (status or "new").strip()
    try:
        hits = int(hits_str)
    except (TypeError, ValueError):
        hits = 0
    if s == "new":
        if has_notes:
            return ("mark reviewed", "NOTES.md present — confirm classification then promote")
        if hits >= 20:
            return ("triage NOW", f"high-hit cluster ({hits}) — likely high-value")
        if hits >= 5:
            return ("triage", f"stable repro ({hits} hits)")
        return ("triage", "needs first-pass look")
    if s == "reviewed":
        return ("verify repro", "build fresh non-AFL, confirm trap, then mark repro-ok")
    if s == "repro-ok":
        return ("file upstream", "draft bug report + PoC, mark reported")
    if s == "reported":
        return ("monitor", "tracking upstream issue")
    if s == "dup":
        return ("done", "duplicate, no further action")
    if s == "ignore":
        return ("done", "noise / false positive")
    if s == "review-requested":
        return ("review queued", "run shared/fuzz-dashboard/review-drain.sh <target>")
    return ("?", "")


def frames_reviewed(crashes):
    """Set of top_frames for which at least one crash already has a REVIEW.md."""
    return {c['top_frame'] for c in crashes if c.get('has_review')}


def _maybe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def viability(top_frame, hits_str, has_notes, status, report_priority=None,
              issue_class="", impact="", confidence="", assessed_severity=""):
    """Coarse triage-worthiness/priority → (bucket, score 0-100, reason).

    If a generated REPORT.md exists, its report_priority is authoritative. Raw
    AFL hit count then remains a stability signal only; many inputs hitting the
    same safe parser exception should not outrank a lower-hit but higher-impact
    report. Targets without generated reports keep the legacy symbolization +
    hit-count heuristic.
    """
    try:
        hits = int(hits_str)
    except (TypeError, ValueError):
        hits = 0
    frame = top_frame or "?"
    if (status or "new") in ("dup", "ignore"):
        return ("ignore", 0, f"already marked '{status}' — out of the triage queue")
    priority = _maybe_int(report_priority)
    if priority is not None:
        score = max(0, min(100, priority))
        if score >= 75:
            bucket = "high"
        elif score >= 55:
            bucket = "med"
        elif score >= 30:
            bucket = "low"
        else:
            bucket = "noise"
        parts = []
        if impact:
            parts.append(str(impact))
        if issue_class:
            parts.append(str(issue_class))
        if confidence:
            parts.append(str(confidence))
        if assessed_severity:
            parts.append(f"severity={assessed_severity}")
        detail = " / ".join(parts) if parts else "REPORT.md assessment"
        return (
            bucket,
            score,
            f"report priority {score}/100 from REPORT.md ({detail}); "
            f"hits={hits} is stability only",
        )
    tf = frame.lower()
    symbolized = (
        bool(tf) and tf != "?"
        and "no-frames" not in tf and "unknown-sig" not in tf and "killed" not in tf
    )
    notes_bit = " + has NOTES.md" if has_notes else ""
    plural = "s" if hits != 1 else ""
    if not symbolized:
        return ("noise", min(15, 5 + hits),
                f"unsymbolized crash ({frame}) — usually a timeout or OOM-kill, rarely a real bug")
    score = min(100, 50 + min(hits, 120) // 3 + (15 if has_notes else 0))
    if hits >= 20:
        return ("high", score,
                f"symbolized frame {frame}, hit by {hits} inputs (>=20){notes_bit} — stable, reproducible, high-value")
    if hits >= 3 or has_notes:
        return ("med", score,
                f"symbolized frame {frame}, {hits} hit{plural}{notes_bit} — worth a look")
    return ("low", score,
            f"symbolized frame {frame} but only {hits} hit{plural} — may be hard to reproduce")


def poc_preview(target, h, fname, max_hex_bytes=512):
    """Fetch first N bytes of a PoC + size + sha256. Returns dict or None."""
    path = f"~/fuzzing/targets/{target}/crashes-triaged/{h}/{fname}"
    cmd = (
        f'p={vm_path(path)}; [ -f "$p" ] || exit 1; '
        f'size=$(stat -c "%s" "$p"); '
        f'sha=$(sha256sum "$p" | cut -c1-16); '
        f'hex=$(head -c {max_hex_bytes} "$p" | xxd -g1 -c16); '
        f'echo "SIZE=$size"; echo "SHA=$sha"; echo "---"; echo "$hex"'
    )
    out, _, rc = run_on_host(cmd, timeout=10)
    if rc != 0 or not out:
        return None
    info = {"size": None, "sha": None, "hexdump": ""}
    in_hex = False
    for line in out.splitlines():
        if line.startswith("SIZE="):
            try: info["size"] = int(line[5:])
            except ValueError: pass
        elif line.startswith("SHA="):
            info["sha"] = line[4:].strip()
        elif line == "---":
            in_hex = True
        elif in_hex:
            info["hexdump"] += line + "\n"
    return info


POC_CANDIDATES = {
    "original": [
        ("poc.original.pdf", "application/pdf", "original AFL input"),
        ("poc.original.bin", "application/octet-stream", "original AFL input"),
    ],
    "mut": [
        ("poc.pdf", "application/pdf", "minimized/current PoC"),
        ("poc.bin", "application/octet-stream", "minimized/current PoC"),
    ],
}


def resolve_poc(target, h, which):
    """Find the first crash artifact matching a logical PoC slot."""
    if which not in POC_CANDIDATES:
        return None
    for fname, content_type, label in POC_CANDIDATES[which]:
        path = f"~/fuzzing/targets/{target}/crashes-triaged/{h}/{fname}"
        out, _, rc = run_on_host(f'test -f {vm_path(path)} && echo OK', timeout=8)
        if rc == 0 and "OK" in out:
            return {"fname": fname, "content_type": content_type, "label": label}
    return None


def fmt_int(n):
    """Human-friendly large number: 1234567 → 1.2M, 4500 → 4.5K."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if n >= 1_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def normalize_status(text):
    parts = (text or "").strip().split()
    return parts[0] if parts else "new"


# One python3 process walks every crash dir and emits the table — vs the old
# shell loop that spawned ~3 python3 per crash (≈1600 processes for 500 crashes,
# which is what made the crash list slow to (re)load).
_CRASH_SCAN_PY = r'''
import json, os, re
pat = re.compile(r'^[0-9a-f]{12}$')

def normalize_status(text):
    parts = (text or '').strip().split()
    return parts[0] if parts else 'new'

def read_report_meta(path):
    try:
        with open(path, errors='replace') as f:
            text = f.read()
    except OSError:
        return {}
    if not text.startswith('---\n'):
        return {}
    out = {}
    for line in text.splitlines()[1:]:
        if line.strip() == '---':
            return out
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        out[k.strip()] = v.strip()
    return {}

for h in sorted(d for d in os.listdir('.') if pat.match(d) and os.path.isdir(d)):
    status = 'new'
    try:
        with open(h + '/.status') as f:
            status = normalize_status(f.read())
    except OSError:
        pass
    tf = hits = first = '?'
    try:
        with open(h + '/meta.json') as f:
            m = json.load(f)
        tf = m.get('top_frame') or m.get('signature') or '?'
        hits = m.get('hit_count', '?')
        first = m.get('first_seen', '?')
    except (OSError, ValueError):
        pass
    report = read_report_meta(h + '/REPORT.md')
    notes = 'Y' if os.path.exists(h + '/NOTES.md') else 'N'
    review = 'Y' if os.path.exists(h + '/REVIEW.md') else 'N'
    print(json.dumps({
        'hash': h,
        'status': status,
        'top_frame': tf,
        'hits': hits,
        'first_seen': first,
        'has_notes': notes == 'Y',
        'has_review': review == 'Y',
        'issue_class': report.get('issue_class', ''),
        'impact': report.get('impact', ''),
        'confidence': report.get('confidence', ''),
        'report_priority': report.get('report_priority', ''),
        'assessed_severity': report.get('severity', ''),
    }, sort_keys=True))
'''


def target_crashes(target):
    """List entries under crashes-triaged/<hash>/. Returns list of dicts."""
    cmd = (
        f'cd ~/fuzzing/targets/{shlex.quote(target)}/crashes-triaged 2>/dev/null || exit 0\n'
        "python3 - <<'PYEOF'\n" + _CRASH_SCAN_PY + "PYEOF\n"
    )
    out, _, _ = run_on_host(cmd, timeout=30)
    return _rows_from_scan_output(out)


def _rows_from_scan_output(out):
    """Parse the _CRASH_SCAN_PY emitter output (JSON lines, or the legacy
    pipe-delimited form) into normalized crash row dicts. Shared by the VM
    (run_on_host) and macOS-host (local subprocess) crash scans."""
    rows = []
    for line in (out or "").strip().splitlines():
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            rows.append({
                'hash': row.get('hash', ''),
                'status': normalize_status(row.get('status')),
                'top_frame': row.get('top_frame') or '?',
                'hits': str(row.get('hits', '?')),
                'first_seen': str(row.get('first_seen') or '?'),
                'has_notes': bool(row.get('has_notes')),
                'has_review': bool(row.get('has_review')),
                'issue_class': row.get('issue_class') or '',
                'impact': row.get('impact') or '',
                'confidence': row.get('confidence') or '',
                'report_priority': row.get('report_priority') or '',
                'assessed_severity': row.get('assessed_severity') or '',
            })
            continue
        parts = line.split('|', 6)
        if len(parts) != 7:
            continue
        h, status, tf, hits, first, notes, review = parts
        rows.append({
            'hash': h,
            'status': normalize_status(status),
            'top_frame': tf,
            'hits': hits,
            'first_seen': first,
            'has_notes': notes == 'Y',
            'has_review': review == 'Y',
            'issue_class': '',
            'impact': '',
            'confidence': '',
            'report_priority': '',
            'assessed_severity': '',
        })
    return rows


def target_families(target):
    """List entries under crashes-triaged/_families/."""
    cmd = f'ls -1 ~/fuzzing/targets/{shlex.quote(target)}/crashes-triaged/_families/ 2>/dev/null'
    out, _, _ = run_on_host(cmd)
    return [f.strip() for f in out.strip().splitlines() if f.strip()]


def read_vm_file(path, max_bytes=200_000):
    """Read a file from the VM. Returns text or None."""
    cmd = f'head -c {max_bytes} {vm_path(path)} 2>/dev/null'
    out, _, rc = run_on_host(cmd, timeout=15)
    if rc != 0 and not out:
        return None
    return out or None


def read_vm_binary(path, max_bytes=10_000_000):
    """Read a binary file from the VM via base64. Returns bytes or None."""
    cmd = f'base64 -w0 {vm_path(path)} 2>/dev/null | head -c {max_bytes * 4 // 3 + 100}'
    out, _, rc = run_on_host(cmd, timeout=20)
    if rc != 0 or not out:
        return None
    import base64
    try:
        return base64.b64decode(out)
    except Exception:
        return None


# ---------- macOS-host (jackalope) data access — ADDITIVE ----------
#
# Host targets are read from the local fs (~/fuzzing-mac/targets/<t>/) with no
# orb round-trip. The dispatchers below pick host vs VM behavior per target so
# the rest of the dashboard renders both kinds uniformly. VM (afl) code paths
# are unchanged.

def _list_host_targets():
    out = []
    try:
        for child in sorted(HOST_TARGETS_ROOT.iterdir()):
            if child.name.startswith('_'):
                continue
            if child.is_dir() and (child / "engine").is_file():
                out.append(child.name)
    except (OSError, FileNotFoundError):
        return []
    return out


def list_host_targets():
    """macOS-host targets: local dirs under HOST_TARGETS_ROOT with an engine file."""
    return CACHE.get("host_targets", 15, _list_host_targets)


def is_host_target(target):
    return target in list_host_targets()


def jackalope_roles_from_stats(stats_path):
    """Parse a jackalope findings/stats.json into the AFL-shaped role list the
    dashboard renders. Returns a single synthetic 'jackalope' role (the engine
    is single-process from the dashboard's POV), with the same keys target_roles
    emits for AFL; fields with no jackalope analogue are "0"/"—". Returns [] if
    the stats file is missing or unparseable."""
    try:
        with open(stats_path) as f:
            s = json.load(f)
    except (OSError, ValueError):
        return []

    def _i(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    now = int(time.time())
    alive = bool(s.get("alive"))
    execs_done = _i(s.get("execs_done"))
    eps = _i(s.get("execs_per_sec"))
    corpus = _i(s.get("corpus_count"))
    coverage = _i(s.get("coverage"))      # offsets reached (maps to bitmap_cvg)
    saved = _i(s.get("saved_crashes"))
    last_find = _i(s.get("last_find"))
    start_time = _i(s.get("start_time"))
    updated = _i(s.get("updated_at"))
    pid = str(s.get("pid") or "")

    role = {
        "role": "jackalope",
        "alive": alive,
        "stats_age_s": max(0, now - updated) if updated else -1,
        "fuzzer_pid": pid,
        "pid": pid,
        "execs_per_sec": str(eps),
        "execs_done": str(execs_done),
        "last_find": str(last_find),
        "pending_total": "0",
        "pending_favs": "0",
        "unique_crashes": str(saved),
        "saved_crashes": str(saved),
        "saved_hangs": "0",
        "corpus_count": str(corpus),
        "bitmap_cvg": str(coverage),
        "stability": "—",
        "cycles_done": "0",
        "cycles_wo_finds": "0",
        "start_time": str(start_time),
        "last_find_age_s": max(0, now - last_find) if last_find else None,
    }
    return [role]


def host_target_roles(target):
    stats_path = HOST_TARGETS_ROOT / target / "findings" / "stats.json"
    return jackalope_roles_from_stats(str(stats_path))


def host_crash_dir(target, h):
    return HOST_TARGETS_ROOT / target / "crashes-triaged" / h


def host_target_crashes(target):
    """Local crashes-triaged scan for a host target. Runs the SAME _CRASH_SCAN_PY
    emitter as the VM path, but locally (cwd in the crash dir), and reuses the
    shared parser so host + VM crash rows are identical in shape."""
    crashdir = HOST_TARGETS_ROOT / target / "crashes-triaged"
    if not crashdir.is_dir():
        return []
    try:
        r = subprocess.run(
            [sys.executable, "-c", _CRASH_SCAN_PY],
            cwd=str(crashdir), capture_output=True, text=True, timeout=30,
        )
        out = r.stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return _rows_from_scan_output(out)


def host_read_text(path, max_bytes=200_000):
    """Read a local text file (host crash artifacts). Returns text or None."""
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read(max_bytes)
    except OSError:
        return None
    return data or None


def _hexdump(data, width=16):
    """xxd-ish hexdump of a bytes chunk, for the PoC preview pane."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}: {hexpart}  {ascii_part}")
    return "\n".join(lines) + ("\n" if lines else "")


def host_resolve_poc(target, h, which):
    """Find a local PoC artifact for a host crash. 'mut' = the current poc.<ext>
    (jackalope writes one poc.<ext>); 'original' = poc.original.<ext> if present."""
    d = host_crash_dir(target, h)
    if not d.is_dir():
        return None
    try:
        names = sorted(p.name for p in d.iterdir() if p.is_file())
    except OSError:
        return None
    if which == "original":
        cands = [n for n in names if n.startswith("poc.original.")]
        label = "original input"
    elif which == "mut":
        cands = [n for n in names if n.startswith("poc.") and not n.startswith("poc.original.")]
        label = "current PoC"
    else:
        return None
    if not cands:
        return None
    fname = cands[0]
    ct = "application/pdf" if fname.lower().endswith(".pdf") else "application/octet-stream"
    return {"fname": fname, "content_type": ct, "label": label}


def host_poc_preview(target, h, fname, max_hex_bytes=512):
    """First N bytes (hexdump) + size + sha256 of a local PoC. Dict or None."""
    p = host_crash_dir(target, h) / fname
    if not p.is_file():
        return None
    import hashlib
    try:
        size = p.stat().st_size
        with open(p, "rb") as f:
            head = f.read(max_hex_bytes)
        sha = hashlib.sha256()
        with open(p, "rb") as f:
            for blk in iter(lambda: f.read(65536), b""):
                sha.update(blk)
    except OSError:
        return None
    return {"size": size, "sha": sha.hexdigest()[:16], "hexdump": _hexdump(head)}


def host_serve_poc(target, h, which, max_bytes=10_000_000):
    if not re.match(r'^[a-zA-Z0-9_-]+$', target) or not re.match(r'^[0-9a-f]{12}$', h):
        return None
    resolved = host_resolve_poc(target, h, which)
    if not resolved:
        return None
    p = host_crash_dir(target, h) / resolved["fname"]
    try:
        with open(p, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return None
    return data, resolved["fname"], resolved["content_type"]


def set_host_status(target, h, new_state):
    """Write .status for a host crash dir (local fs). Mirrors set_status_on_host."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', target):
        return False, "bad target"
    if not re.match(r'^[0-9a-f]{12}$', h):
        return False, "bad hash"
    if new_state not in VALID_STATES:
        return False, f"bad state {new_state!r}"
    d = host_crash_dir(target, h)
    if not d.is_dir():
        return False, "MISSING_DIR"
    try:
        (d / ".status").write_text(new_state + "\n")
    except OSError as e:
        return False, str(e)
    CACHE.invalidate(f"status:{target}:{h}")
    CACHE.invalidate(f"crashes:{target}")
    return True, "ok"


# --- per-target dispatchers: host (jackalope, local) vs VM (afl, orb) ---

def roles_for(target):
    return host_target_roles(target) if is_host_target(target) else target_roles(target)


def crashes_for(target):
    return host_target_crashes(target) if is_host_target(target) else target_crashes(target)


def families_for(target):
    # jackalope triage does not build crash families; VM targets keep their own.
    return [] if is_host_target(target) else target_families(target)


def read_crash_file(target, h, rel):
    if is_host_target(target):
        return host_read_text(host_crash_dir(target, h) / rel)
    base = f"~/fuzzing/targets/{target}/crashes-triaged/{h}"
    return read_vm_file(f"{base}/{rel}")


def resolve_poc_for(target, h, which):
    return host_resolve_poc(target, h, which) if is_host_target(target) else resolve_poc(target, h, which)


def poc_preview_for(target, h, fname):
    return host_poc_preview(target, h, fname) if is_host_target(target) else poc_preview(target, h, fname)


def serve_poc_dispatch(target, h, which):
    return host_serve_poc(target, h, which) if is_host_target(target) else serve_poc(target, h, which)


def apply_status_change(target, h, new_state):
    return set_host_status(target, h, new_state) if is_host_target(target) else set_status_on_host(target, h, new_state)


# ---------- HTML rendering ----------

CSS = """
* { box-sizing: border-box; }
body { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px;
       max-width: 1400px; margin: 0 auto; padding: 1em; background: #0d1117; color: #c9d1d9; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
h1, h2, h3 { color: #f0f6fc; font-weight: 600; }
h1 { font-size: 1.3em; margin: 0.2em 0; }
h2 { font-size: 1.1em; margin-top: 1.5em; border-bottom: 1px solid #30363d; padding-bottom: 0.3em; }
h3 { font-size: 1em; margin-top: 1em; }
pre { background: #010409; padding: 1em; overflow-x: auto; border-left: 3px solid #1f6feb;
      border-radius: 4px; line-height: 1.4; }
code { background: #161b22; padding: 1px 5px; border-radius: 3px; font-size: 0.95em; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0; }
th, td { padding: 4px 10px; text-align: left; border-bottom: 1px solid #21262d; }
th { background: #161b22; color: #f0f6fc; font-weight: 600; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px; }
tr:hover td { background: #161b22; }
.hdr { display: flex; justify-content: space-between; align-items: center;
       border-bottom: 1px solid #30363d; padding: 0.5em 0; margin-bottom: 1em; }
.hdr a { color: #c9d1d9; font-weight: 600; }
.hdr .crumbs { color: #6e7681; font-size: 0.95em; }
.hdr .crumbs a { color: #58a6ff; }
.live { color: #3fb950; }
.dead { color: #f85149; }
.warn { color: #d29922; }
.muted { color: #6e7681; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.85em;
       background: #21262d; color: #c9d1d9; }
.tag.new { background: #1f6feb; color: white; }
.tag.reviewed { background: #d29922; color: black; }
.tag.repro-ok { background: #3fb950; color: black; }
.tag.reported { background: #6e7681; color: white; }
.tag.review-requested { background: #8957e5; color: white; }
.tag.dup, .tag.ignore { background: #30363d; color: #6e7681; }
.tag.viab-high { background: #3fb950; color: black; }
.tag.viab-med { background: #d29922; color: black; }
.tag.viab-low { background: #30363d; color: #c9d1d9; }
.tag.viab-noise { background: #21262d; color: #6e7681; }
.tag.viab-ignore { background: #161b22; color: #484f58; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1em; }
.box { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 1em; }
.refresh { font-size: 0.85em; color: #6e7681; }
.hero { border-radius: 6px; padding: 1.5em 1.2em; margin-bottom: 1.2em; border: 1px solid #30363d; }
.hero h1 { margin: 0 0 0.4em 0; font-size: 1.4em; }
.hero p { margin: 0.2em 0; }
.hero .dot { font-size: 1.3em; vertical-align: -2px; margin-right: 0.3em; }
.hero-green { background: linear-gradient(180deg, #0d2818 0%, #0d1117 100%); border-color: #1f6f3a; }
.hero-yellow { background: linear-gradient(180deg, #2a200a 0%, #0d1117 100%); border-color: #6e5719; }
.hero-red { background: linear-gradient(180deg, #2a0e0e 0%, #0d1117 100%); border-color: #6e2024; }
.hero-blue { background: linear-gradient(180deg, #0e1c2a 0%, #0d1117 100%); border-color: #1f4068; }
.health-row { display: flex; gap: 2em; margin-top: 0.6em; font-size: 0.95em; }
.health-row b { color: #f0f6fc; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.7em; margin: 0.8em 0 1.2em; }
.kpi { background: #161b22; border: 1px solid #30363d; border-radius: 5px; padding: 0.7em 0.9em; }
.kpi .label { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.5px; color: #6e7681; }
.kpi .value { font-size: 1.6em; font-weight: 600; color: #f0f6fc; line-height: 1.2; margin-top: 0.15em; }
.kpi .sub { font-size: 0.8em; color: #6e7681; margin-top: 0.1em; }
.kpi.warn .value { color: #d29922; }
.kpi.live .value { color: #3fb950; }
.kpi.dead .value { color: #f85149; }
form.statusform { display: inline; }
form.statusform button { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 3px;
    padding: 2px 8px; font: inherit; font-size: 0.85em; cursor: pointer; margin-right: 4px; }
form.statusform button:hover { background: #30363d; border-color: #58a6ff; }
form.statusform button.danger { color: #f85149; }
.next { font-weight: 600; }
.next.urgent { color: #f85149; }
.next.todo { color: #d29922; }
.next.done { color: #6e7681; }
.filter-bar { margin: 0.6em 0; }
.filter-bar select, .filter-bar input { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
    border-radius: 3px; padding: 3px 6px; font: inherit; }
.poc-hex { font-size: 0.82em; line-height: 1.4; max-height: 320px; overflow-y: auto; }
.flash { background: #1f6f3a; color: #f0f6fc; padding: 0.5em 1em; border-radius: 4px; margin-bottom: 1em; }
.flash.err { background: #6e2024; }
details summary { cursor: pointer; padding: 0.3em 0; color: #58a6ff; }
blockquote { border-left: 3px solid #30363d; margin: 0.6em 0; padding: 0.2em 1em; color: #8b949e; }
.box ul, .box ol { margin: 0.5em 0; padding-left: 1.5em; }
.box li { margin: 0.25em 0; }
.box table { margin: 0.6em 0; }
th[title], .kpi .label[title], .tag[title] { cursor: help; }
"""


def page(title, body_html, refresh=None, crumbs=None):
    refresh_meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ''
    crumbs_html = ""
    if crumbs:
        crumbs_html = ' · '.join(crumbs)
    refresh_note = f'<span class="refresh">auto-refresh {refresh}s</span>' if refresh else ''
    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>{html.escape(title)} — fuhq</title>
{refresh_meta}
<style>{CSS}</style>
</head><body>
<div class="hdr">
  <div><a href="/">fuhq</a> <span class="crumbs">{crumbs_html}</span></div>
  <div>{refresh_note} <span class="muted">{html.escape(time.strftime('%Y-%m-%d %H:%M:%S'))}</span></div>
</div>
{body_html}
</body></html>"""


def render_status_tag(status):
    s = html.escape(status or 'new')
    cls = re.sub(r'[^a-z\-]', '', s.lower())
    return f'<span class="tag {cls}">{s}</span>'


def render_hero(health):
    """Top-of-page health banner. Distinct states for the four empty/active cases."""
    if not health.get("reachable"):
        return f"""<div class="hero hero-red">
  <h1><span class="dot dead">●</span>fuzz host unreachable</h1>
  <p class="muted">dashboard is up, but couldn't reach the fuzz host via <code>shared/run-on-fuzz-host.sh</code>.</p>
  <pre>{html.escape(health.get('error', '(no error message)'))}</pre>
  <p class="muted">on Mac+orb: <code>orb status</code>, then <code>orb start fuzzer</code>. on bare Linux: this is a wrapper bug.</p>
</div>"""
    if not health["targets"]:
        return """<div class="hero hero-blue">
  <h1><span class="dot muted">●</span>no targets configured</h1>
  <p>fuzz host is reachable, but <code>~/fuzzing/targets/</code> has no target directories.</p>
  <p class="muted">use the <code>fuzz-add-target</code> skill to onboard one.</p>
</div>"""
    alive, cal = health["total_alive"], health["total_calibrating"]
    eps, crashes = health["total_execs_per_sec"], health["total_crashes"]
    n_tgt = len(health["targets"])
    if alive > 0:
        return f"""<div class="hero hero-green">
  <h1><span class="dot live">●</span>{alive} role{'s' if alive != 1 else ''} alive · {eps:.0f} execs/s aggregate</h1>
  <div class="health-row">
    <span><b>{n_tgt}</b> target{'s' if n_tgt != 1 else ''}</span>
    <span><b>{alive}</b> alive</span>
    {f'<span><b>{cal}</b> calibrating</span>' if cal else ''}
    <span><b>{crashes}</b> unique crashes</span>
  </div>
</div>"""
    if cal > 0:
        return f"""<div class="hero hero-yellow">
  <h1><span class="dot warn">●</span>0 alive · {cal} role{'s' if cal != 1 else ''} calibrating</h1>
  <p>afl-fuzz processes are running but haven't written <code>fuzzer_stats</code> yet — usually finishes within 60–180s on ASAN+cmplog builds.</p>
</div>"""
    return f"""<div class="hero hero-red">
  <h1><span class="dot dead">●</span>0 fuzzers running</h1>
  <p>all {n_tgt} configured target{'s are' if n_tgt != 1 else ' is'} idle. dashboard is up, but no fuzzing in progress.</p>
  <p class="muted">restart: <code>systemctl --user start &lt;target&gt;-fuzz.service</code> (Mac+orb: prefix with <code>orb -m fuzzer</code> and the user-bus env vars).</p>
</div>"""


def aggregate_kpis(health):
    """Walk all targets' roles, return aggregate KPI dict for the index banner."""
    k = {
        "live_roles": health.get("total_alive", 0),
        "calibrating": health.get("total_calibrating", 0),
        "execs_per_sec": health.get("total_execs_per_sec", 0.0),
        "execs_done": 0, "saved_crashes": 0, "saved_hangs": 0,
        "pending_total": 0, "pending_favs": 0, "corpus_count": 0,
        "max_cov": 0.0, "min_last_find_s": None, "targets": len(health.get("targets") or []),
    }
    for t in health.get("targets") or []:
        roles = CACHE.get(f"roles:{t}", 10, lambda t=t: roles_for(t))
        for r in roles:
            for f, kk in [("execs_done", "execs_done"), ("saved_crashes", "saved_crashes"),
                          ("saved_hangs", "saved_hangs"), ("pending_total", "pending_total"),
                          ("pending_favs", "pending_favs"), ("corpus_count", "corpus_count")]:
                try: k[kk] += int(r.get(f) or 0)
                except (ValueError, TypeError): pass
            try:
                cov = float((r.get("bitmap_cvg") or "0").rstrip('%'))
                k["max_cov"] = max(k["max_cov"], cov)
            except (ValueError, TypeError): pass
            lf = r.get("last_find_age_s")
            if lf is not None and (k["min_last_find_s"] is None or lf < k["min_last_find_s"]):
                k["min_last_find_s"] = lf
    return k


def render_kpis(kpis, scope="global"):
    """Render KPI card row. scope='global' for index, 'target' for per-target."""
    live_cls = "live" if kpis["live_roles"] > 0 else "dead"
    t_live = "AFL++ workers whose fuzzer_pid is currently live (kill -0 verified, not just a stale stats file)."
    t_cal = "Worker processes that are running but haven't written fuzzer_stats yet — usually finishes within 60-180s on ASAN+cmplog builds."
    t_eps = "Sum of executions/sec across all live workers. A rough throughput gauge; below ~200/worker is worth investigating."
    t_execs = "Total target executions since the rig started, summed across workers."
    t_cov = "Best edge-coverage bitmap fill across workers — how much of the instrumented code has been reached."
    t_corpus = "Total saved corpus inputs; favs = the high-value subset AFL fuzzes first, pending = not-yet-fuzzed queue entries."
    t_crashes = "Crashes saved by AFL itself (per-worker count, before the triage loop dedupes them by ASAN stack hash)."
    t_lf = "Time since ANY worker last found a new coverage path. Hours-long gaps mean the rig may have plateaued."
    cal_html = f'<div class="kpi warn"><div class="label" title="{html.escape(t_cal, quote=True)}">calibrating</div><div class="value">{kpis["calibrating"]}</div><div class="sub">roles</div></div>' if kpis["calibrating"] else ""
    lf = kpis["min_last_find_s"]
    lf_html = fmt_age(lf) if lf is not None else "—"
    lf_cls = "warn" if (lf is not None and lf > 3600) else ""
    cards = [
        f'<div class="kpi {live_cls}"><div class="label" title="{html.escape(t_live, quote=True)}">live roles</div><div class="value">{kpis["live_roles"]}</div><div class="sub">across {kpis["targets"]} target{"s" if kpis["targets"] != 1 else ""}</div></div>',
        cal_html,
        f'<div class="kpi"><div class="label" title="{html.escape(t_eps, quote=True)}">execs/s</div><div class="value">{kpis["execs_per_sec"]:.0f}</div><div class="sub">aggregate</div></div>',
        f'<div class="kpi"><div class="label" title="{html.escape(t_execs, quote=True)}">execs total</div><div class="value">{fmt_int(kpis["execs_done"])}</div><div class="sub">since rig start</div></div>',
        f'<div class="kpi"><div class="label" title="{html.escape(t_cov, quote=True)}">coverage</div><div class="value">{kpis["max_cov"]:.1f}<span style="font-size:0.6em">%</span></div><div class="sub">best role bitmap</div></div>',
        f'<div class="kpi"><div class="label" title="{html.escape(t_corpus, quote=True)}">corpus</div><div class="value">{fmt_int(kpis["corpus_count"])}</div><div class="sub">{fmt_int(kpis["pending_favs"])} favs / {fmt_int(kpis["pending_total"])} pending</div></div>',
        f'<div class="kpi"><div class="label" title="{html.escape(t_crashes, quote=True)}">saved crashes</div><div class="value">{kpis["saved_crashes"]}</div><div class="sub">{kpis["saved_hangs"]} hangs</div></div>',
        f'<div class="kpi {lf_cls}"><div class="label" title="{html.escape(t_lf, quote=True)}">last new path</div><div class="value">{lf_html}</div><div class="sub">across all roles</div></div>',
    ]
    return f'<div class="kpis">{"".join(c for c in cards if c)}</div>'


def render_index():
    health = CACHE.get("health", 15, host_health)
    hero = render_hero(health)

    if not health.get("reachable") or not health["targets"]:
        return page("fuhq dashboard", hero, refresh=30)

    kpis = aggregate_kpis(health)
    kpi_block = render_kpis(kpis, scope="global")

    target_rows = []
    for t in health["targets"]:
        info = health["by_target"][t]
        if info["alive"] > 0:
            dot, state = '<span class="live">●</span>', f"{info['alive']}/{info['proc']} alive · {info['execs_per_sec']:.0f} execs/s"
        elif info["calibrating"] > 0:
            dot, state = '<span class="warn">●</span>', f"{info['calibrating']} calibrating"
        elif info["proc"] > 0:
            dot, state = '<span class="warn">●</span>', f"{info['proc']} proc, stale stats"
        else:
            dot, state = '<span class="dead">●</span>', "idle"
        target_rows.append(
            f'<tr><td>{dot}</td>'
            f'<td><a href="/t/{html.escape(t)}/">{html.escape(t)}</a></td>'
            f'<td>{state}</td>'
            f'<td class="muted">{info["crashes"]} crashes</td></tr>'
        )

    check_in = CACHE.get("check_in", 15, fetch_check_in)

    body = f"""
{hero}
{kpi_block}
<h2>targets</h2>
<table>{''.join(target_rows)}</table>
<details><summary>raw check-in output</summary><pre>{html.escape(check_in)}</pre></details>
"""
    return page("fuhq dashboard", body, refresh=15)


def fmt_age(secs):
    if secs < 0:
        return "?"
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs//60}m"
    if secs < 86400:
        return f"{secs//3600}h{(secs%3600)//60}m"
    return f"{secs//86400}d{(secs%86400)//3600}h"


def render_target(target):
    if not re.match(r'^[a-zA-Z0-9_-]+$', target):
        return page("err", "<p>bad target name</p>")
    roles = CACHE.get(f"roles:{target}", 10, lambda: roles_for(target))
    crashes = CACHE.get(f"crashes:{target}", 60, lambda: crashes_for(target))
    families = CACHE.get(f"families:{target}", 60, lambda: families_for(target))

    # Per-target KPIs from this target's roles
    def acc(field):
        s = 0
        for r in roles:
            try: s += int(r.get(field) or 0)
            except (ValueError, TypeError): pass
        return s
    def max_cov():
        best = 0.0
        for r in roles:
            try: best = max(best, float((r.get("bitmap_cvg") or "0").rstrip('%')))
            except (ValueError, TypeError): pass
        return best
    live_roles = sum(1 for r in roles if r["alive"])
    eps = sum(float(r.get("execs_per_sec") or 0) for r in roles if r["alive"])
    last_finds = [r["last_find_age_s"] for r in roles if r.get("last_find_age_s") is not None]
    kpis = {
        "live_roles": live_roles, "calibrating": 0, "targets": 1,
        "execs_per_sec": eps, "execs_done": acc("execs_done"),
        "saved_crashes": acc("saved_crashes"), "saved_hangs": acc("saved_hangs"),
        "pending_total": acc("pending_total"), "pending_favs": acc("pending_favs"),
        "corpus_count": acc("corpus_count"), "max_cov": max_cov(),
        "min_last_find_s": min(last_finds) if last_finds else None,
    }
    kpi_block = render_kpis(kpis, scope="target")

    # Role table
    role_rows = []
    for r in roles:
        alive_html = '<span class="live">●alive</span>' if r['alive'] else '<span class="dead">●dead</span>'
        age = r.get('stats_age_s', -1)
        age_html = fmt_age(age) if age >= 0 else "?"
        if age > 300:
            age_html = f'<span class="warn">{age_html}</span>'
        lf = r.get('last_find_age_s')
        lf_html = fmt_age(lf) if lf is not None else "—"
        cov = (r.get('bitmap_cvg') or '0').rstrip('%')
        role_rows.append(
            f"<tr><td>{html.escape(r['role'])}</td>"
            f"<td>{alive_html}</td>"
            f"<td>{html.escape(r['execs_per_sec'])}</td>"
            f"<td>{fmt_int(r.get('execs_done',0))}</td>"
            f"<td>{html.escape(cov)}%</td>"
            f"<td>{fmt_int(r.get('corpus_count',0))}</td>"
            f"<td>{html.escape(r.get('pending_total',''))} / fav {html.escape(r.get('pending_favs',''))}</td>"
            f"<td>{html.escape(r.get('saved_crashes',''))}</td>"
            f"<td>{lf_html}</td>"
            f"<td>{age_html}</td></tr>"
        )

    # Crash list with report-aware priority + next-step columns + status buttons.
    # Sort highest-priority first so the high-value crashes float to the top of
    # a long list (the priority column/filter then lets you slice further).
    for c in crashes:
        c['_viab'], c['_vscore'], c['_vreason'] = viability(
            c['top_frame'], c['hits'], c['has_notes'], c['status'],
            c.get('report_priority'), c.get('issue_class'), c.get('impact'),
            c.get('confidence'), c.get('assessed_severity'),
        )
    crashes = sorted(crashes, key=lambda c: c['_vscore'], reverse=True)

    reviewed_frames = frames_reviewed(crashes)
    # jackalope/host targets have no VM reviews ledger; avoid an orb round-trip.
    if is_host_target(target):
        ledger = {"count": 0, "cost_usd": 0.0, "seconds": 0}
    else:
        ledger = CACHE.get(f"ledger:{target}", 60, lambda: read_reviews_ledger(target))

    bucket = {}
    crash_rows = []
    for c in crashes:
        bucket[c['status']] = bucket.get(c['status'], 0) + 1
        notes_marker = ' <span class="muted">[N]</span>' if c['has_notes'] else ''
        label, _hint = recommend_next_step(c['status'], c['hits'], c['has_notes'])
        cls = "done" if c['status'] in ('dup', 'ignore', 'reported') else \
              ("urgent" if "NOW" in label else "todo")
        vbucket, vscore, vreason = c['_viab'], c['_vscore'], c['_vreason']
        if c['has_review']:
            review_cell = '<span class="tag viab-high">reviewed</span>'
        elif c['has_notes']:
            review_cell = '<span class="muted">noted</span>'
        elif c['top_frame'] in reviewed_frames:
            review_cell = '<span class="muted">frame done</span>'
        elif READ_ONLY:
            review_cell = '<span class="muted">read-only</span>'
        else:
            review_cell = (
                f'<form class="statusform" method="POST" action="/api/status/{html.escape(target)}/{html.escape(c["hash"])}">'
                f'<input type="hidden" name="new_status" value="review-requested">'
                f'<button type="submit" title="Queue agentic review for this frame.">review</button>'
                f'</form>')
        crash_rows.append(
            f'<tr data-status="{html.escape(c["status"])}" data-frame="{html.escape(c["top_frame"].lower())}" '
            f'data-viab="{vbucket}" data-vscore="{vscore}">'
            f'<td><a href="/c/{html.escape(target)}/{html.escape(c["hash"])}">{html.escape(c["hash"])}</a>{notes_marker}</td>'
            f'<td>{render_status_tag(c["status"])}</td>'
            f'<td>{html.escape(c["top_frame"])}</td>'
            f'<td>{html.escape(str(c["hits"]))}</td>'
            f'<td><span class="tag viab-{vbucket}" title="{html.escape(vreason, quote=True)}">{vbucket} · {vscore}</span></td>'
            f'<td>{review_cell}</td>'
            f'<td class="next {cls}">{html.escape(label)}</td>'
            f'<td class="muted">{html.escape(c["first_seen"])}</td>'
            f'</tr>'
        )

    bucket_html = " ".join(f"{render_status_tag(s)} <b>{n}</b>" for s, n in sorted(bucket.items()))

    fam_html = ""
    if families:
        items = "".join(
            f'<li><a href="/families/{html.escape(target)}/{html.escape(f)}">{html.escape(f)}</a></li>'
            for f in families
        )
        fam_html = f"<h2>families</h2><ul>{items}</ul>"

    body = f"""
<h1>{html.escape(target)}</h1>
{kpi_block}
<h2>roles</h2>
<table>
<tr>
<th title="AFL++ worker. primary = fast build + CMPLOG; asan = ASAN/UBSAN build (traces); explore = broader power schedule.">role</th>
<th title="alive = this worker's fuzzer_pid is live (kill -0). dead = stats file exists but the process is gone; the 5-min watchdog will relaunch it.">state</th>
<th title="Executions per second right now. Below ~200 usually means calibration, a slow harness, or pathological inputs.">execs/s</th>
<th title="Total target executions since this worker started.">execs</th>
<th title="Edge-coverage bitmap fill — how much of the instrumented map this worker has reached.">cvg</th>
<th title="Inputs kept in this worker's corpus (interesting/coverage-increasing test cases).">corpus</th>
<th title="Queue entries not yet fuzzed: total, and favored (the smaller high-value subset AFL prioritizes).">pending</th>
<th title="Unique crashes saved by this worker (AFL's own count, before cross-worker dedup).">crashes</th>
<th title="Time since this worker last discovered a new coverage path. Long gaps (hours) suggest it has plateaued.">last find</th>
<th title="Age of this worker's fuzzer_stats file. If it stops advancing, the worker has stalled or died.">stats age</th>
</tr>
{''.join(role_rows) or '<tr><td colspan=10 class="muted">no roles</td></tr>'}
</table>
{fam_html}
<h2>crashes ({len(crashes)})</h2>
<p>{bucket_html}</p>
<div class="filter-bar">
  filter status: <select id="fstatus" onchange="filterCrashes()">
    <option value="">all</option>
    {' '.join(f'<option value="{s}">{s}</option>' for s in ('new','review-requested','reviewed','repro-ok','reported','dup','ignore'))}
  </select>
  &nbsp; search frame: <input id="ffilter" oninput="filterCrashes()" placeholder="dblToCol, JBIG2…">
  &nbsp; priority: <select id="fviab" onchange="filterCrashes()">
    <option value="">all</option>
    {' '.join(f'<option value="{v}">{v}</option>' for v in ('high','med','low','noise','ignore'))}
  </select>
  &nbsp; <span class="muted" id="fcount">{len(crashes)} shown</span>
</div>
<table id="crashtab">
<tr>
<th title="Short ID of this unique crash (its triaged dir name). Click to open the full crash view. [N] = a NOTES.md exists.">hash</th>
<th title="Triage workflow state: new -> reviewed -> repro-ok -> reported. dup/ignore are parked. Set it on the crash page.">status</th>
<th title="Top symbolized stack frame from the ASAN trace — the function where it crashed. 'no-frames' means it was never symbolized (usually a timeout/OOM-kill).">top frame</th>
<th title="How many distinct fuzzer inputs landed on this same crash signature. Higher = more stable and reproducible.">hits</th>
<th title="Report-aware priority bucket + 0-100 score. If REPORT.md has report_priority, hits are only a stability signal; otherwise this falls back to symbolization plus hit count.">priority</th>
<th title="Request or see agentic review for this crash's frame. One review covers all crashes sharing a top frame.">review</th>
<th title="Suggested next action for this crash given its state, hit count, and whether it has NOTES.md.">next step</th>
<th title="Timestamp the fuzzer first saved an input with this crash signature.">first seen</th>
</tr>
{''.join(crash_rows) or '<tr><td colspan=8 class="muted">no triaged crashes</td></tr>'}
</table>
<p class="muted">reviews: {ledger['count']} · ${ledger['cost_usd']:.2f} total · {fmt_age(ledger['seconds'])}</p>
<script>
function filterCrashes() {{
  var s = document.getElementById('fstatus').value.toLowerCase();
  var q = document.getElementById('ffilter').value.toLowerCase();
  var v = document.getElementById('fviab').value;
  var rows = document.querySelectorAll('#crashtab tr[data-status]');
  var shown = 0;
  rows.forEach(function(r) {{
    var sm = !s || r.dataset.status === s;
    var qm = !q || r.dataset.frame.indexOf(q) !== -1;
    var vm = !v || r.dataset.viab === v;
    var on = sm && qm && vm;
    r.style.display = on ? '' : 'none';
    if (on) shown++;
  }});
  document.getElementById('fcount').textContent = shown + ' shown';
}}
</script>
"""
    crumbs = [f'<a href="/t/{html.escape(target)}/">{html.escape(target)}</a>']
    return page(target, body, refresh=15, crumbs=crumbs)


MD_HEADERS = re.compile(r'^(#{1,6})\s+(.+)$', re.M)
MD_CODE_FENCE = re.compile(r'```(\w*)\n([\s\S]*?)```')
MD_INLINE_CODE = re.compile(r'`([^`\n]+)`')
MD_BOLD = re.compile(r'\*\*([^*]+)\*\*')
MD_LINK = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')


MD_TABLE_SEP = re.compile(r'^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$')
MD_ULI = re.compile(r'^\s*[-*]\s+')
MD_OLI = re.compile(r'^\s*\d+\.\s+')
# NB: the markdown is html-escaped before block parsing runs, so a '>' quote
# marker has already become '&gt;' by the time we match here.
MD_QUOTE = re.compile(r'^\s*&gt;\s?')


def _split_table_row(s):
    s = s.strip()
    if s.startswith('|'):
        s = s[1:]
    if s.endswith('|'):
        s = s[:-1]
    return [c.strip() for c in s.split('|')]


def parse_review_frontmatter(text):
    """Split a leading `---`-delimited key: value frontmatter block from the body.
    Returns (meta_dict_of_strings, body). No frontmatter -> ({}, text)."""
    if not text or not text.startswith("---"):
        return {}, text or ""
    parts = text.split("\n")
    if parts[0].strip() != "---":
        return {}, text
    meta, end = {}, None
    for i in range(1, len(parts)):
        if parts[i].strip() == "---":
            end = i
            break
        if ":" in parts[i]:
            k, v = parts[i].split(":", 1)
            meta[k.strip()] = v.strip()
    if end is None:
        return {}, text
    return meta, "\n".join(parts[end + 1:]).lstrip("\n")


def md_to_html(md):
    """Minimal markdown → HTML. Headers, code fences, inline code, bold, links,
    unordered/ordered lists, GitHub-style pipe tables, and blockquotes."""
    if not md:
        return ""
    placeholders = {}

    def ph(s, idx):
        key = f"__PH{idx}_{len(placeholders)}__"
        placeholders[key] = s
        return key

    def replace_fence(m):
        lang, code = m.group(1), m.group(2)
        rendered = f'<pre><code>{html.escape(code)}</code></pre>'
        return ph(rendered, 0)

    md = MD_CODE_FENCE.sub(replace_fence, md)

    def replace_inline(m):
        return ph(f"<code>{html.escape(m.group(1))}</code>", 1)

    md = MD_INLINE_CODE.sub(replace_inline, md)

    md = html.escape(md)
    md = MD_BOLD.sub(r'<strong>\1</strong>', md)

    def link(m):
        # md is already html-escaped here, so url/text need no further escaping.
        # Only render safe schemes; otherwise drop the link, keep the text.
        # Guards against javascript:/data: links in operator-authored markdown.
        text, url = m.group(1), m.group(2)
        if url.strip().lower().startswith(('http://', 'https://', '/', '#', './', '../')):
            return f'<a href="{url}">{html.escape(text)}</a>'
        return text
    md = MD_LINK.sub(link, md)

    def hdr(m):
        n = len(m.group(1))
        return f"<h{n+1}>{m.group(2)}</h{n+1}>"
    md = MD_HEADERS.sub(hdr, md)

    # Block assembly. Headers + code blocks are already <...>/__PH placeholders;
    # here we recognise lists, pipe tables, blockquotes, and paragraphs. Inline
    # transforms (bold/code/links) already ran above, so cell/item text is ready.
    lines = md.split('\n')
    blocks = []
    i, n = 0, len(lines)

    def is_block_start(idx):
        s = lines[idx].strip()
        return (
            not s or s.startswith('<') or s.startswith('__PH')
            or MD_ULI.match(lines[idx]) or MD_OLI.match(lines[idx]) or MD_QUOTE.match(lines[idx])
            or ('|' in lines[idx] and idx + 1 < n and MD_TABLE_SEP.match(lines[idx + 1]))
        )

    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith('<') or stripped.startswith('__PH'):
            blocks.append(line)
            i += 1
        elif '|' in line and i + 1 < n and MD_TABLE_SEP.match(lines[i + 1]):
            header = _split_table_row(line)
            i += 2
            body = []
            while i < n and lines[i].strip() and '|' in lines[i]:
                body.append(_split_table_row(lines[i]))
                i += 1
            thead = ''.join(f'<th>{c}</th>' for c in header)
            tbody = ''.join('<tr>' + ''.join(f'<td>{c}</td>' for c in r) + '</tr>' for r in body)
            blocks.append(f'<table><tr>{thead}</tr>{tbody}</table>')
        elif MD_ULI.match(line):
            items = []
            while i < n and MD_ULI.match(lines[i]):
                items.append(MD_ULI.sub('', lines[i]))
                i += 1
            blocks.append('<ul>' + ''.join(f'<li>{it}</li>' for it in items) + '</ul>')
        elif MD_OLI.match(line):
            items = []
            while i < n and MD_OLI.match(lines[i]):
                items.append(MD_OLI.sub('', lines[i]))
                i += 1
            blocks.append('<ol>' + ''.join(f'<li>{it}</li>' for it in items) + '</ol>')
        elif MD_QUOTE.match(line):
            quote = []
            while i < n and MD_QUOTE.match(lines[i]):
                quote.append(MD_QUOTE.sub('', lines[i]))
                i += 1
            blocks.append('<blockquote>' + '<br>'.join(quote) + '</blockquote>')
        else:
            para = [line]
            i += 1
            while i < n and not is_block_start(i):
                para.append(lines[i])
                i += 1
            blocks.append('<p>' + '<br>'.join(para) + '</p>')
    out = '\n'.join(blocks)

    for k, v in placeholders.items():
        out = out.replace(k, v)
    return out


STATUS_BUTTONS = [
    ("reviewed", "mark reviewed"),
    ("repro-ok", "mark repro-ok"),
    ("reported", "mark reported"),
    ("dup", "mark dup"),
    ("ignore", "mark ignore"),
    ("new", "reset to new"),
]


def render_status_form(target, h, current):
    if READ_ONLY:
        return '<span class="muted">read-only dashboard; status changes disabled</span>'
    btns = []
    for state, label in STATUS_BUTTONS:
        if state == current:
            continue
        cls = "danger" if state in ("dup", "ignore") else ""
        btns.append(
            f'<form class="statusform" method="POST" action="/api/status/{html.escape(target)}/{html.escape(h)}">'
            f'<input type="hidden" name="new_status" value="{state}">'
            f'<button type="submit" class="{cls}">{html.escape(label)}</button>'
            f'</form>'
        )
    return "".join(btns)


def render_crash(target, h, flash=None):
    if not re.match(r'^[a-zA-Z0-9_-]+$', target) or not re.match(r'^[0-9a-f]{12}$', h):
        return page("err", "<p>bad path</p>")
    # read_crash_file dispatches host (local fs) vs VM (orb); cache keys unchanged.
    meta_raw = CACHE.get(f"meta:{target}:{h}", 60, lambda: read_crash_file(target, h, "meta.json"))
    trace = CACHE.get(f"trace:{target}:{h}", 60, lambda: read_crash_file(target, h, "trace.txt"))
    notes = CACHE.get(f"notes:{target}:{h}", 60, lambda: read_crash_file(target, h, "NOTES.md"))
    review_raw = CACHE.get(f"review:{target}:{h}", 60, lambda: read_crash_file(target, h, "REVIEW.md"))
    report_raw = CACHE.get(f"report:{target}:{h}", 60, lambda: read_crash_file(target, h, "REPORT.md"))
    repro_raw = CACHE.get(f"repro:{target}:{h}", 60, lambda: read_crash_file(target, h, "REPRO.md"))
    poc_md_raw = CACHE.get(f"pocmd:{target}:{h}", 60, lambda: read_crash_file(target, h, "POC.md"))
    status_raw = CACHE.get(f"status:{target}:{h}", 30, lambda: read_crash_file(target, h, ".status"))
    status = normalize_status(status_raw)

    # Extract hits + top_frame from meta for the next-step recommendation
    meta = {}
    if meta_raw:
        try: meta = json.loads(meta_raw)
        except Exception: pass
    hits = str(meta.get("hit_count", "?"))
    top_frame = meta.get("top_frame") or meta.get("signature") or "?"
    has_notes = notes is not None
    report_meta, report_body = parse_review_frontmatter(report_raw)

    next_label, next_hint = recommend_next_step(status, hits, has_notes)
    vbucket, vscore, vreason = viability(
        top_frame, hits, has_notes, status, report_meta.get("report_priority"),
        report_meta.get("issue_class"), report_meta.get("impact"),
        report_meta.get("confidence"), report_meta.get("severity"),
    )

    meta_pretty = "(missing)"
    if meta_raw:
        try:
            meta_pretty = json.dumps(meta, indent=2) if meta else meta_raw
        except Exception:
            meta_pretty = meta_raw

    notes_html = md_to_html(notes) if notes else '<p class="muted">no NOTES.md yet</p>'
    report_html = md_to_html(report_body) if report_raw else '<p class="muted">no REPORT.md yet; run shared/crash-digest/promote-repros.py</p>'
    repro_html = md_to_html(parse_review_frontmatter(repro_raw)[1]) if repro_raw else '<p class="muted">no REPRO.md yet</p>'
    poc_md_html = md_to_html(parse_review_frontmatter(poc_md_raw)[1]) if poc_md_raw else '<p class="muted">no POC.md yet</p>'

    if review_raw:
        rmeta, rbody = parse_review_frontmatter(review_raw)
        badge = ""
        if rmeta.get("cost_usd") or rmeta.get("seconds"):
            badge = (f' <span class="tag viab-high">reviewed · ${html.escape(rmeta.get("cost_usd","?"))}'
                     f' · {html.escape(rmeta.get("seconds","?"))}s</span>')
        review_section = f'<h2>automated review{badge}</h2><div class="box">{md_to_html(rbody)}</div>'
        request_btn = ""
    else:
        review_section = ""
        if READ_ONLY:
            request_btn = ""
        elif not has_notes:
            request_btn = (
                f'<form class="statusform" method="POST" action="/api/status/{html.escape(target)}/{html.escape(h)}">'
                f'<input type="hidden" name="new_status" value="review-requested">'
                f'<button type="submit" title="Queue this crash for agentic review; run review-drain.sh to process the queue.">request review</button>'
                f'</form>')
        else:
            request_btn = ""

    # PoC previews — both logical copies. Poppler stores PDFs; byte-oriented
    # targets store .bin inputs. Always show a hexdump, and only inline-render
    # artifacts the browser can handle without corrupting the dashboard page.
    poc_blocks = []
    for which in ("original", "mut"):
        resolved = resolve_poc_for(target, h, which)
        if not resolved:
            names = ", ".join(fname for fname, _, _ in POC_CANDIDATES[which])
            poc_blocks.append(f'<details><summary>{html.escape(which)} PoC — not found ({html.escape(names)})</summary></details>')
            continue
        fname = resolved["fname"]
        info = poc_preview_for(target, h, fname)
        if not info:
            poc_blocks.append(f'<details><summary>{html.escape(fname)} — not found</summary></details>')
            continue
        size_str = f"{info['size']:,} B" if info['size'] is not None else "?"
        embed = ""
        pocurl = f'/poc/{html.escape(target)}/{html.escape(h)}/{which}'
        if resolved["content_type"] == "application/pdf" and (info.get("size") or 0) < 1_500_000:
            # Lazy-load: these are malformed, parser-crashing PDFs. Handing one to
            # the browser's PDF engine can hang it for many seconds, and an <object>
            # with a live data= fetches+renders even inside a collapsed <details>.
            # So we stash the URL in data-src and only wire up data= when the
            # operator actually expands the panel.
            embed = (f'<details ontoggle="if(this.open&&!this.dataset.loaded){{this.dataset.loaded=1;'
                     f'var o=this.querySelector(\'object\');o.data=o.dataset.src;}}">'
                     f'<summary>inline PDF view — loads on demand (crash input; may be slow or blank)</summary>'
                     f'<object data-src="{pocurl}" type="application/pdf" width="100%" height="500">'
                     f'<p class="muted">browser can\'t embed; <a href="{pocurl}">download</a></p>'
                     f'</object></details>')
        poc_blocks.append(f"""
<h3>{html.escape(fname)} <span class="tag">{html.escape(resolved["label"])}</span></h3>
<p><b>size:</b> {size_str} · <b>sha256:</b> <code>{html.escape(info.get('sha') or '?')}…</code> ·
   <a href="{pocurl}">download</a></p>
<pre class="poc-hex">{html.escape(info.get('hexdump') or '')}</pre>
{embed}""")

    flash_html = ""
    if flash:
        cls = "err" if flash.get("err") else ""
        flash_html = f'<div class="flash {cls}">{html.escape(flash.get("msg", ""))}</div>'

    body = f"""
{flash_html}
<h1>{html.escape(h)} <span class="muted">[{html.escape(target)}]</span> {render_status_tag(status)}</h1>
<div class="kpis" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));">
  <div class="kpi"><div class="label">top frame</div><div class="value" style="font-size:1em;word-break:break-all">{html.escape(top_frame)}</div></div>
  <div class="kpi"><div class="label">hits</div><div class="value">{html.escape(hits)}</div></div>
  <div class="kpi"><div class="label">priority</div><div class="value"><span class="tag viab-{vbucket}">{vbucket} · {vscore}</span></div><div class="sub">{html.escape(vreason)}</div></div>
  <div class="kpi"><div class="label">first seen</div><div class="value" style="font-size:0.95em">{html.escape(str(meta.get('first_seen', '?')))}</div></div>
  <div class="kpi {'warn' if 'NOW' in next_label else ''}"><div class="label">next step</div><div class="value" style="font-size:1.1em">{html.escape(next_label)}</div><div class="sub">{html.escape(next_hint)}</div></div>
</div>

<h2>change status</h2>
<p>{render_status_form(target, h, status)} {request_btn}</p>

{review_section}

<h2>crash report</h2>
<div class="box">{report_html}</div>

<h2>PoC / reproducer code</h2>
<div class="box">{poc_md_html}</div>

<h2>repro output</h2>
<div class="box">{repro_html}</div>

<h2>NOTES.md</h2>
<div class="box">{notes_html}</div>

<h2>PoC files</h2>
{''.join(poc_blocks)}

<h2>trace.txt</h2>
<pre>{html.escape(trace or '(missing)')}</pre>

<h2>meta.json</h2>
<pre>{html.escape(meta_pretty)}</pre>
"""
    crumbs = [
        f'<a href="/t/{html.escape(target)}/">{html.escape(target)}</a>',
        f'crash {html.escape(h)}',
    ]
    return page(f"{target}/{h}", body, crumbs=crumbs)


def render_family(target, fam):
    if not re.match(r'^[a-zA-Z0-9_-]+$', target) or not re.match(r'^[a-zA-Z0-9_-]+$', fam):
        return page("err", "<p>bad path</p>")
    base = f"~/fuzzing/targets/{target}/crashes-triaged/_families/{fam}"
    ctx = CACHE.get(f"ctx:{target}:{fam}", 60, lambda: read_vm_file(f"{base}/CONTEXT.md"))
    listing, _, _ = run_on_host(f'ls -1 {vm_path(base)} 2>/dev/null')
    files = [f.strip() for f in listing.splitlines() if f.strip()]
    file_links = "".join(
        f'<li>{html.escape(f)}</li>' for f in files
    )
    body = f"""
<h1>family: {html.escape(fam)} <span class="muted">[{html.escape(target)}]</span></h1>
<h2>CONTEXT.md</h2>
<div class="box">{md_to_html(ctx) if ctx else '<p class="muted">no CONTEXT.md</p>'}</div>
<h2>files in dir</h2>
<ul>{file_links}</ul>
"""
    crumbs = [
        f'<a href="/t/{html.escape(target)}/">{html.escape(target)}</a>',
        f'families/{html.escape(fam)}',
    ]
    return page(f"{target}/_families/{fam}", body, crumbs=crumbs)


def serve_poc(target, h, which):
    if not re.match(r'^[a-zA-Z0-9_-]+$', target) or not re.match(r'^[0-9a-f]{12}$', h):
        return None
    resolved = resolve_poc(target, h, which)
    if not resolved:
        return None
    fname = resolved["fname"]
    path = f"~/fuzzing/targets/{target}/crashes-triaged/{h}/{fname}"
    data = read_vm_binary(path)
    if data is None:
        return None
    return data, fname, resolved["content_type"]


# ---------- HTTP plumbing ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "fuhq-dashboard/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}\n")

    def _send(self, body, content_type="text/html; charset=utf-8", status=200, extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = unquote(self.path.split('?', 1)[0])
        query = self.path.split('?', 1)[1] if '?' in self.path else ''
        try:
            self.route(path, query)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            self._send(page("error", f"<h1>error</h1><pre>{html.escape(tb)}</pre>"), status=500)

    def do_POST(self):
        path = unquote(self.path.split('?', 1)[0])
        length = int(self.headers.get('Content-Length', '0') or '0')
        raw = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
        from urllib.parse import parse_qs
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        try:
            self.route_post(path, form)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            self._send(page("error", f"<h1>error</h1><pre>{html.escape(tb)}</pre>"), status=500)

    def route_post(self, path, form):
        if READ_ONLY:
            self._send(page("read-only", "<h1>read-only</h1><p>status changes are disabled on this dashboard.</p>"), status=403)
            return
        m = re.match(r'^/api/status/([^/]+)/([^/]+)/?$', path)
        if m:
            target, h = m.group(1), m.group(2)
            new_state = form.get('new_status', '')
            ok, msg = apply_status_change(target, h, new_state)
            # 303 See Other → re-GET as crash page with flash
            flash_qs = f"?flash={'ok' if ok else 'err'}&msg={html.escape(msg, quote=True)}&state={html.escape(new_state, quote=True)}"
            self.send_response(303)
            self.send_header('Location', f'/c/{target}/{h}{flash_qs}')
            self.end_headers()
            return
        self._send(page("404", "<h1>404</h1><p>no such POST route</p>"), status=404)

    def route(self, path, query=""):
        if path in ("/", "/index", "/index.html"):
            self._send(render_index()); return
        m = re.match(r'^/t/([^/]+)/?$', path)
        if m: self._send(render_target(m.group(1))); return
        m = re.match(r'^/c/([^/]+)/([^/]+)/?$', path)
        if m:
            flash = None
            if query:
                from urllib.parse import parse_qs
                q = parse_qs(query)
                if 'flash' in q:
                    is_err = q['flash'][0] == 'err'
                    msg = q.get('msg', [''])[0]
                    state = q.get('state', [''])[0]
                    if is_err:
                        flash = {"err": True, "msg": f"status change failed: {msg}"}
                    else:
                        flash = {"err": False, "msg": f"status set to {state!r}"}
            self._send(render_crash(m.group(1), m.group(2), flash=flash)); return
        m = re.match(r'^/families/([^/]+)/([^/]+)/?$', path)
        if m: self._send(render_family(m.group(1), m.group(2))); return
        m = re.match(r'^/poc/([^/]+)/([^/]+)/(original|mut)/?$', path)
        if m:
            result = serve_poc_dispatch(m.group(1), m.group(2), m.group(3))
            if result is None or result[0] is None:
                self._send("not found", "text/plain", 404); return
            data, fname, content_type = result
            self._send(data, content_type, 200,
                       extra_headers={"Content-Disposition": f'inline; filename="{fname}"'})
            return
        if path == "/invalidate":
            CACHE.invalidate()
            self._send("ok", "text/plain"); return
        self._send(page("404", "<h1>404</h1><p>no such route</p>"), status=404)


def main():
    p = argparse.ArgumentParser(description="fuhq browser dashboard")
    p.add_argument("--port", type=int, default=8765, help="bind port (default 8765)")
    p.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    args = p.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"fuhq dashboard listening on {url}")
    print(f"  SSH-forward from your laptop:  ssh -L {args.port}:localhost:{args.port} <user>@<this-mac>")
    print(f"  then open {url} in Safari")
    print(f"  Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
        server.shutdown()


if __name__ == "__main__":
    main()
