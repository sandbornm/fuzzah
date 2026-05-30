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


VALID_STATES = {"new", "reviewed", "repro-ok", "reported", "dup", "ignore"}


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
    return ("?", "")


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


def target_crashes(target):
    """List entries under crashes-triaged/<hash>/. Returns list of dicts."""
    cmd = (
        f'cd ~/fuzzing/targets/{shlex.quote(target)}/crashes-triaged 2>/dev/null && '
        'for h in $(ls -1 | grep -E "^[0-9a-f]{12}$"); do '
        '  meta="$h/meta.json"; status="new"; tf="?"; hits="?"; first="?"; '
        '  [ -f "$h/.status" ] && status=$(tr -d "[:space:]" < "$h/.status"); '
        '  if [ -f "$meta" ]; then '
        '    tf=$(python3 -c "import json,sys; d=json.load(open(\\"$meta\\"));print(d.get(\\"top_frame\\") or d.get(\\"signature\\") or \\"?\\")" 2>/dev/null); '
        '    hits=$(python3 -c "import json,sys; d=json.load(open(\\"$meta\\"));print(d.get(\\"hit_count\\", \\"?\\"))" 2>/dev/null); '
        '    first=$(python3 -c "import json,sys; d=json.load(open(\\"$meta\\"));print(d.get(\\"first_seen\\", \\"?\\"))" 2>/dev/null); '
        '  fi; '
        '  notes="N"; [ -f "$h/NOTES.md" ] && notes="Y"; '
        '  echo "$h|$status|$tf|$hits|$first|$notes"; '
        'done'
    )
    out, _, _ = run_on_host(cmd, timeout=30)
    rows = []
    for line in out.strip().splitlines():
        parts = line.split('|', 5)
        if len(parts) != 6:
            continue
        h, status, tf, hits, first, notes = parts
        rows.append({
            'hash': h,
            'status': status or 'new',
            'top_frame': tf,
            'hits': hits,
            'first_seen': first,
            'has_notes': notes == 'Y',
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
.tag.dup, .tag.ignore { background: #30363d; color: #6e7681; }
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
        roles = CACHE.get(f"roles:{t}", 10, lambda t=t: target_roles(t))
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
    cal_html = f'<div class="kpi warn"><div class="label">calibrating</div><div class="value">{kpis["calibrating"]}</div><div class="sub">roles</div></div>' if kpis["calibrating"] else ""
    lf = kpis["min_last_find_s"]
    lf_html = fmt_age(lf) if lf is not None else "—"
    lf_cls = "warn" if (lf is not None and lf > 3600) else ""
    cards = [
        f'<div class="kpi {live_cls}"><div class="label">live roles</div><div class="value">{kpis["live_roles"]}</div><div class="sub">across {kpis["targets"]} target{"s" if kpis["targets"] != 1 else ""}</div></div>',
        cal_html,
        f'<div class="kpi"><div class="label">execs/s</div><div class="value">{kpis["execs_per_sec"]:.0f}</div><div class="sub">aggregate</div></div>',
        f'<div class="kpi"><div class="label">execs total</div><div class="value">{fmt_int(kpis["execs_done"])}</div><div class="sub">since rig start</div></div>',
        f'<div class="kpi"><div class="label">coverage</div><div class="value">{kpis["max_cov"]:.1f}<span style="font-size:0.6em">%</span></div><div class="sub">best role bitmap</div></div>',
        f'<div class="kpi"><div class="label">corpus</div><div class="value">{fmt_int(kpis["corpus_count"])}</div><div class="sub">{fmt_int(kpis["pending_favs"])} favs / {fmt_int(kpis["pending_total"])} pending</div></div>',
        f'<div class="kpi"><div class="label">saved crashes</div><div class="value">{kpis["saved_crashes"]}</div><div class="sub">{kpis["saved_hangs"]} hangs</div></div>',
        f'<div class="kpi {lf_cls}"><div class="label">last new path</div><div class="value">{lf_html}</div><div class="sub">across all roles</div></div>',
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
    roles = CACHE.get(f"roles:{target}", 10, lambda: target_roles(target))
    crashes = CACHE.get(f"crashes:{target}", 30, lambda: target_crashes(target))
    families = CACHE.get(f"families:{target}", 60, lambda: target_families(target))

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

    # Crash list with next-step column + status buttons
    bucket = {}
    crash_rows = []
    for c in crashes:
        bucket[c['status']] = bucket.get(c['status'], 0) + 1
        notes_marker = ' <span class="muted">[N]</span>' if c['has_notes'] else ''
        label, _hint = recommend_next_step(c['status'], c['hits'], c['has_notes'])
        cls = "done" if c['status'] in ('dup', 'ignore', 'reported') else \
              ("urgent" if "NOW" in label else "todo")
        crash_rows.append(
            f'<tr data-status="{html.escape(c["status"])}" data-frame="{html.escape(c["top_frame"].lower())}">'
            f'<td><a href="/c/{html.escape(target)}/{html.escape(c["hash"])}">{html.escape(c["hash"])}</a>{notes_marker}</td>'
            f'<td>{render_status_tag(c["status"])}</td>'
            f'<td>{html.escape(c["top_frame"])}</td>'
            f'<td>{html.escape(c["hits"])}</td>'
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
<tr><th>role</th><th>state</th><th>execs/s</th><th>execs</th><th>cvg</th><th>corpus</th><th>pending</th><th>crashes</th><th>last find</th><th>stats age</th></tr>
{''.join(role_rows) or '<tr><td colspan=10 class="muted">no roles</td></tr>'}
</table>
{fam_html}
<h2>crashes ({len(crashes)})</h2>
<p>{bucket_html}</p>
<div class="filter-bar">
  filter status: <select id="fstatus" onchange="filterCrashes()">
    <option value="">all</option>
    {' '.join(f'<option value="{s}">{s}</option>' for s in ('new','reviewed','repro-ok','reported','dup','ignore'))}
  </select>
  &nbsp; search frame: <input id="ffilter" oninput="filterCrashes()" placeholder="dblToCol, JBIG2…">
  &nbsp; <span class="muted" id="fcount">{len(crashes)} shown</span>
</div>
<table id="crashtab">
<tr><th>hash</th><th>status</th><th>top frame</th><th>hits</th><th>next step</th><th>first seen</th></tr>
{''.join(crash_rows) or '<tr><td colspan=6 class="muted">no triaged crashes</td></tr>'}
</table>
<script>
function filterCrashes() {{
  var s = document.getElementById('fstatus').value.toLowerCase();
  var q = document.getElementById('ffilter').value.toLowerCase();
  var rows = document.querySelectorAll('#crashtab tr[data-status]');
  var shown = 0;
  rows.forEach(function(r) {{
    var sm = !s || r.dataset.status === s;
    var qm = !q || r.dataset.frame.indexOf(q) !== -1;
    var on = sm && qm;
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


def md_to_html(md):
    """Minimal markdown → HTML. Headers, code fences, inline code, bold, links."""
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

    # blank-line paragraphs
    blocks = []
    for chunk in re.split(r'\n\n+', md):
        if chunk.strip().startswith('<') or chunk.strip().startswith('__PH'):
            blocks.append(chunk)
        else:
            blocks.append('<p>' + chunk.replace('\n', '<br>') + '</p>')
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
    base = f"~/fuzzing/targets/{target}/crashes-triaged/{h}"
    meta_raw = CACHE.get(f"meta:{target}:{h}", 60, lambda: read_vm_file(f"{base}/meta.json"))
    trace = CACHE.get(f"trace:{target}:{h}", 60, lambda: read_vm_file(f"{base}/trace.txt"))
    notes = CACHE.get(f"notes:{target}:{h}", 60, lambda: read_vm_file(f"{base}/NOTES.md"))
    status_raw = CACHE.get(f"status:{target}:{h}", 30, lambda: read_vm_file(f"{base}/.status"))
    status = (status_raw or "new").strip()

    # Extract hits + top_frame from meta for the next-step recommendation
    meta = {}
    if meta_raw:
        try: meta = json.loads(meta_raw)
        except Exception: pass
    hits = str(meta.get("hit_count", "?"))
    top_frame = meta.get("top_frame") or meta.get("signature") or "?"
    has_notes = notes is not None

    next_label, next_hint = recommend_next_step(status, hits, has_notes)

    meta_pretty = "(missing)"
    if meta_raw:
        try:
            meta_pretty = json.dumps(meta, indent=2) if meta else meta_raw
        except Exception:
            meta_pretty = meta_raw

    notes_html = md_to_html(notes) if notes else '<p class="muted">no NOTES.md yet</p>'

    # PoC previews — both copies (original = AFL input, mut = current crash file)
    poc_blocks = []
    for which, fname in [("original", "poc.original.pdf"), ("mut", "poc.pdf")]:
        info = poc_preview(target, h, fname)
        if not info:
            poc_blocks.append(f'<details><summary>{html.escape(fname)} — not found</summary></details>')
            continue
        size_str = f"{info['size']:,} B" if info['size'] is not None else "?"
        embed = ""
        if (info.get("size") or 0) < 1_500_000:
            embed = (f'<details><summary>inline PDF view (Safari)</summary>'
                     f'<object data="/poc/{html.escape(target)}/{html.escape(h)}/{which}" '
                     f'type="application/pdf" width="100%" height="500">'
                     f'<p class="muted">browser can\'t embed; <a href="/poc/{html.escape(target)}/{html.escape(h)}/{which}">download</a></p>'
                     f'</object></details>')
        poc_blocks.append(f"""
<h3>{html.escape(fname)}</h3>
<p><b>size:</b> {size_str} · <b>sha256:</b> <code>{html.escape(info.get('sha') or '?')}…</code> ·
   <a href="/poc/{html.escape(target)}/{html.escape(h)}/{which}">download</a></p>
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
  <div class="kpi"><div class="label">first seen</div><div class="value" style="font-size:0.95em">{html.escape(str(meta.get('first_seen', '?')))}</div></div>
  <div class="kpi {'warn' if 'NOW' in next_label else ''}"><div class="label">next step</div><div class="value" style="font-size:1.1em">{html.escape(next_label)}</div><div class="sub">{html.escape(next_hint)}</div></div>
</div>

<h2>change status</h2>
<p>{render_status_form(target, h, status)}</p>

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
    fname = "poc.original.pdf" if which == "original" else "poc.pdf"
    path = f"~/fuzzing/targets/{target}/crashes-triaged/{h}/{fname}"
    data = read_vm_binary(path)
    return data, fname


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
        m = re.match(r'^/api/status/([^/]+)/([^/]+)/?$', path)
        if m:
            target, h = m.group(1), m.group(2)
            new_state = form.get('new_status', '')
            ok, msg = set_status_on_host(target, h, new_state)
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
            result = serve_poc(m.group(1), m.group(2), m.group(3))
            if result is None or result[0] is None:
                self._send("not found", "text/plain", 404); return
            data, fname = result
            self._send(data, "application/pdf", 200,
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
