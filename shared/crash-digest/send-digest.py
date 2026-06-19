#!/usr/bin/env python3
"""Send a six-hour fuzz crash digest via Resend.

This runs on the control host. It uses run-on-fuzz-host.sh for VM work:
1. bounded triage drain
2. JSON state collection
3. local ranking/rendering/email send
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SHARED_DIR = SCRIPT_DIR.parent
RUN_ON_HOST = SHARED_DIR / "run-on-fuzz-host.sh"
TRIAGE_DRAIN = SCRIPT_DIR / "triage-drain.sh"
PROMOTE_REPROS = SCRIPT_DIR / "promote-repros.py"
COLLECT = SCRIPT_DIR / "collect.py"
CONTROL_ROOT = SCRIPT_DIR.parents[2] if len(SCRIPT_DIR.parents) >= 3 else Path.cwd()
RESEND_ENDPOINT = "https://api.resend.com/emails"

NOISE_RE = re.compile(r"(memlimit|timeout|unknown-js-crash|unknown-sig|no-frames|killed|rc=124|rc=137)", re.I)
ACTIONABLE_STATES = {"new", "review-requested", "reviewed", "repro-ok"}
DONE_STATES = {"ignore", "dup", "reported"}
DEFAULT_MIN_REPORT_PRIORITY = 80
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
MEMORY_ISSUE_RE = re.compile(
    r"(?:^|[-_])(?:heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
    r"heap-use-after-free|stack-use-after-return|stack-use-after-scope|"
    r"use-after-poison|container-overflow|double-free|bad-free|alloc-dealloc-mismatch)(?:$|[-_])|"
    r"memory-bug|memory-corruption|memory-safety|"
    r"(?:^|[-_])segv(?:$|[-_])|sigsegv|exc_bad_access",
    re.I,
)
MEMORY_TEXT_RE = re.compile(
    r"AddressSanitizer: (?:heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
    r"heap-use-after-free|stack-use-after-return|stack-use-after-scope|"
    r"use-after-poison|container-overflow|double-free|bad-free|alloc-dealloc-mismatch|deadlysignal)|"
    r"\bSIGSEGV\b|segmentation fault|EXC_BAD_ACCESS|SEGV on unknown address",
    re.I,
)
LOW_VALUE_RE = re.compile(
    r"assertion|ubsan|timeout|js-exception|parser-dos|harness-amplified|"
    r"stack-exhaustion-dos|input-validation|robustness|rangeerror|typeerror",
    re.I,
)


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def default_state_path() -> Path:
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "fuzzah" / "crash-digest-state.json"
    return Path.home() / ".local" / "state" / "fuzzah" / "crash-digest-state.json"


def default_log_dir() -> Path:
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Logs" / "fuzzah"
    return Path.home() / ".local" / "state" / "fuzzah" / "logs"


def env_file_candidates(extra: str | None) -> list[Path]:
    out = []
    if extra:
        out.append(Path(extra).expanduser())
    if os.environ.get("FUZZ_DIGEST_ENV"):
        out.append(Path(os.environ["FUZZ_DIGEST_ENV"]).expanduser())
    out.extend(
        [
            CONTROL_ROOT / ".secrets" / "fuzz-crash-digest.env",
            Path.home() / ".config" / "fuzzah" / "crash-digest.env",
        ]
    )
    deduped = []
    seen = set()
    for p in out:
        key = str(p)
        if key not in seen:
            deduped.append(p)
            seen.add(key)
    return deduped


def load_env_files(extra: str | None) -> list[Path]:
    loaded = []
    for path in env_file_candidates(extra):
        if not path.is_file():
            continue
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key and key not in os.environ:
                os.environ[key] = value
        loaded.append(path)
    return loaded


def run_on_host(cmd: str, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(RUN_ON_HOST), cmd], text=True, capture_output=True, timeout=timeout)


def env_exports(names: list[str]) -> str:
    parts = []
    for name in names:
        value = os.environ.get(name)
        if value:
            parts.append(f"{name}={sh_quote(value)}")
    return " ".join(parts)


def drain_triage(timeout: int) -> str:
    exports = env_exports(
        [
            "FUZZ_DIGEST_MAX_TRIAGE_PER_TARGET",
            "FUZZ_DIGEST_MAX_TRIAGE_TOTAL",
            "FUZZ_DIGEST_TRIAGE_TIMEOUT",
        ]
    )
    cmd = f"{exports} bash {sh_quote(str(TRIAGE_DRAIN))}".strip()
    r = run_on_host(cmd, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"triage drain failed rc={r.returncode}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")
    return (r.stdout + r.stderr).strip()


def promote_repros(timeout: int) -> str:
    exports = env_exports(
        [
            "FUZZ_DIGEST_REPRO_LIMIT",
            "FUZZ_DIGEST_REPRO_TIMEOUT",
        ]
    )
    cmd = f"{exports} python3 {sh_quote(str(PROMOTE_REPROS))}".strip()
    r = run_on_host(cmd, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"repro promotion failed rc={r.returncode}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")
    return (r.stdout + r.stderr).strip()


def collect_snapshot(timeout: int) -> dict:
    # Run collect.py *locally* on the control host. It self-proxies the AFL/VM
    # lane into the VM via run-on-fuzz-host.sh and merges the macOS host
    # (jackalope) lane from the local filesystem. Running it through the proxy
    # instead would hide the host lane, which only exists on this machine.
    python_exe = sys.executable or "python3"
    r = subprocess.run([python_exe, str(COLLECT)], text=True, capture_output=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"collector failed rc={r.returncode}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}")
    text = r.stdout.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise RuntimeError(f"collector did not emit JSON:\n{text}\nSTDERR:\n{r.stderr}")
    return json.loads(text[start : end + 1])


def load_state(path: Path) -> dict:
    try:
        with path.open() as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def save_state(path: Path, snapshot: dict, crashes: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sent = {}
    for c in crashes:
        sent[c["key"]] = {
            "last_seen": c.get("last_seen"),
            "hit_count": c.get("hit_count", 0),
            "status": c.get("status"),
        }
    data = {
        "last_sent_at": now_utc().isoformat(),
        "snapshot_generated_at": snapshot.get("generated_at"),
        "sent": sent,
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def dashboard_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def is_noise(frame: str) -> bool:
    return bool(NOISE_RE.search(frame or ""))


def env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    return default


def digest_min_report_priority() -> int:
    try:
        value = int(os.environ.get("FUZZ_DIGEST_MIN_REPORT_PRIORITY", str(DEFAULT_MIN_REPORT_PRIORITY)))
    except ValueError:
        value = DEFAULT_MIN_REPORT_PRIORITY
    return max(0, min(100, value))


def excluded_targets() -> set[str]:
    raw = os.environ.get("FUZZ_DIGEST_EXCLUDE_TARGETS", "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def filter_snapshot_targets(snapshot: dict, excluded: set[str]) -> dict:
    if not excluded:
        return snapshot
    filtered = dict(snapshot)
    filtered["targets"] = [
        target for target in snapshot.get("targets", [])
        if str(target.get("name") or "") not in excluded
    ]
    return filtered


def high_value_signal(c: dict) -> bool:
    """Return true only for crash metadata that looks like memory corruption.

    This is intentionally stricter than "actionable": assertions, UBSan-only
    reports, JavaScript exceptions, and parser DoS can remain in the dashboard,
    but they should not page the operator unless native memory-safety evidence
    is present.
    """
    fields = [
        c.get("issue_class"),
        c.get("impact"),
        c.get("assessed_severity"),
        c.get("severity"),
        c.get("top_frame"),
        c.get("signature"),
    ]
    blob = "\n".join(str(x) for x in fields if x)
    if MEMORY_ISSUE_RE.search(blob) or MEMORY_TEXT_RE.search(blob):
        return True
    if LOW_VALUE_RE.search(blob):
        return False
    return False


def score_crash(c: dict, previous: dict | None) -> tuple[int, list[str], bool]:
    status = c.get("status") or "new"
    frame = c.get("top_frame") or "?"
    hits = int(c.get("hit_count") or 0)
    report_priority = c.get("report_priority")
    changed = False
    reasons = []

    if previous is None:
        changed = True
        reasons.append("new cluster")
    else:
        old_hits = int(previous.get("hit_count") or 0)
        if hits > old_hits:
            changed = True
            reasons.append(f"+{hits - old_hits} hits")
        if status != previous.get("status"):
            changed = True
            reasons.append(f"status {previous.get('status')} -> {status}")

    if status in DONE_STATES:
        return 0, reasons or ["done"], changed

    report_scored = isinstance(report_priority, int)
    if report_scored:
        score = report_priority
        reasons.append(f"priority={report_priority}")
        if c.get("impact"):
            reasons.append(f"impact={c.get('impact')}")
        if c.get("confidence"):
            reasons.append(f"confidence={c.get('confidence')}")
        if c.get("issue_class"):
            reasons.append(str(c.get("issue_class")))
    else:
        score = {"repro-ok": 78, "reviewed": 68, "review-requested": 60, "new": 50}.get(status, 35)
    if not is_noise(frame):
        reasons.append("symbolized")
    else:
        if not report_scored:
            score -= 35
        reasons.append("noise-shaped")
    if hits >= 20:
        if not report_scored:
            score += 6
        reasons.append(f"{hits} hits")
    elif hits >= 5:
        if not report_scored:
            score += 4
        reasons.append(f"{hits} hits")
    elif hits >= 2:
        if not report_scored:
            score += 2
    if c.get("has_review"):
        if not report_scored:
            score += 12
        reasons.append("has review")
    if c.get("has_report"):
        reasons.append("has report")
    if c.get("has_poc"):
        reasons.append("has PoC")
    if c.get("has_notes"):
        if not report_scored:
            score += 6
        reasons.append("has notes")
    if changed and not report_scored:
        score += 8
    return max(0, min(100, score)), reasons, changed


def flatten_rank(snapshot: dict, state: dict) -> tuple[list[dict], list[dict]]:
    previous = state.get("sent", {}) if isinstance(state.get("sent"), dict) else {}
    ranked = []
    all_crashes = []
    min_priority = digest_min_report_priority()
    only_high_value = env_flag("FUZZ_DIGEST_ONLY_HIGH_VALUE", True)
    for target in snapshot.get("targets", []):
        for crash in target.get("crashes", []):
            c = dict(crash)
            c["target"] = target.get("name", "?")
            c["key"] = f"{c['target']}/{c.get('hash')}"
            prev = previous.get(c["key"])
            score, reasons, changed = score_crash(c, prev)
            c["score"] = score
            c["reasons"] = reasons
            c["changed"] = changed
            c["dashboard_path"] = crash.get("dashboard_path") or f"/c/{c['target']}/{c.get('hash')}"
            c["high_value"] = high_value_signal(c)
            all_crashes.append(c)
            if (
                c.get("status") in ACTIONABLE_STATES
                and score >= min_priority
                and (not only_high_value or c["high_value"])
            ):
                if only_high_value:
                    c["reasons"].append("memory-corruption signal")
                ranked.append(c)
    ranked.sort(key=lambda c: (c["changed"], c["score"], int(c.get("hit_count") or 0)), reverse=True)
    return ranked, all_crashes


def totals(snapshot: dict) -> dict:
    targets = snapshot.get("targets", [])
    alive = sum(int(t.get("alive_roles") or 0) for t in targets)
    eps = sum(float(t.get("execs_per_sec") or 0.0) for t in targets)
    triaged = sum(len(t.get("crashes", [])) for t in targets)
    unseen = sum(int((t.get("raw_crashes") or {}).get("unseen") or 0) for t in targets)
    return {"targets": len(targets), "alive": alive, "execs_per_sec": eps, "triaged": triaged, "unseen": unseen}


def target_engine(t: dict) -> str:
    return str(t.get("engine") or "afl")


def render_target_rows(snapshot: dict, base_url: str) -> str:
    rows = []
    for t in snapshot.get("targets", []):
        counts = t.get("state_counts") or {}
        state_bits = " ".join(f"{html.escape(k)}={int(v)}" for k, v in sorted(counts.items())) or "none"
        url = dashboard_url(base_url, t.get("dashboard_path") or f"/t/{t.get('name')}")
        raw = t.get("raw_crashes") or {}
        rows.append(
            "<tr>"
            f"<td><a href=\"{html.escape(url)}\">{html.escape(t.get('name', '?'))}</a></td>"
            f"<td>{html.escape(target_engine(t))}</td>"
            f"<td>{int(t.get('alive_roles') or 0)}</td>"
            f"<td>{float(t.get('execs_per_sec') or 0):.0f}</td>"
            f"<td>{len(t.get('crashes', []))}</td>"
            f"<td>{int(raw.get('unseen') or 0)}</td>"
            f"<td>{state_bits}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_crash_rows(crashes: list[dict], base_url: str, limit: int) -> str:
    rows = []
    for c in crashes[:limit]:
        url = dashboard_url(base_url, c["dashboard_path"])
        changed = "yes" if c.get("changed") else "no"
        reason = ", ".join(c.get("reasons") or [])
        report_ready = ' <br><span class="muted">REPORT.md + POC.md ready</span>' if c.get("has_report") and c.get("has_poc") else ""
        assessment = ""
        if c.get("impact") or c.get("confidence") or c.get("issue_class"):
            bits = [str(x) for x in (c.get("impact"), c.get("confidence"), c.get("issue_class")) if x]
            assessment = f'<br><span class="muted">{html.escape(" · ".join(bits))}</span>'
        # Host (jackalope) crashes have no AFL-replay enrichment; degrade to the
        # base meta.json info plus the trace.txt artifact instead of an empty
        # REPORT/POC note.
        artifact = ""
        if not (c.get("has_report") and c.get("has_poc")) and c.get("engine") == "jackalope":
            note = ["jackalope"]
            if c.get("signature"):
                note.append(html.escape(str(c.get("signature"))))
            if c.get("has_trace"):
                note.append("trace.txt")
            artifact = f'<br><span class="muted">{" · ".join(note)}</span>'
        rows.append(
            "<tr>"
            f"<td>{html.escape(c['target'])}</td>"
            f"<td><a href=\"{html.escape(url)}\"><code>{html.escape(c.get('hash', '?'))}</code></a></td>"
            f"<td>{html.escape(c.get('status') or 'new')}</td>"
            f"<td>{int(c.get('hit_count') or 0)}</td>"
            f"<td>{int(c.get('score') or 0)}</td>"
            f"<td>{changed}</td>"
            f"<td>{html.escape(reason)}</td>"
            f"<td><code>{html.escape(c.get('top_frame') or '?')}</code>"
            f"{assessment}{report_ready}{artifact}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def grouped_highlights(crashes: list[dict], per_target: int = 4) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for crash in crashes:
        target = str(crash.get("target") or "?")
        groups.setdefault(target, [])
        if len(groups[target]) < per_target:
            groups[target].append(crash)
    return groups


def render_target_highlights_html(crashes: list[dict], base_url: str) -> str:
    rows = []
    for target, items in sorted(grouped_highlights(crashes).items()):
        links = []
        for c in items:
            url = dashboard_url(base_url, c["dashboard_path"])
            label = c.get("issue_class") or c.get("top_frame") or c.get("hash")
            detail = c.get("impact") or c.get("status") or ""
            links.append(
                f'<li><a href="{html.escape(url)}"><code>{html.escape(c.get("hash", "?"))}</code></a> '
                f'{html.escape(str(label))} '
                f'<span class="muted">priority {int(c.get("score") or 0)} {html.escape(str(detail))}</span></li>'
            )
        rows.append(f"<tr><td>{html.escape(target)}</td><td><ul>{''.join(links)}</ul></td></tr>")
    return "\n".join(rows)


def render_html(snapshot: dict, crashes: list[dict], base_url: str, limit: int, triage_log: str, repro_log: str) -> str:
    t = totals(snapshot)
    rows = render_crash_rows(crashes, base_url, limit)
    if not rows:
        rows = '<tr><td colspan="8">No crash clusters met the high-value memory-corruption gate.</td></tr>'
    target_rows = render_target_rows(snapshot, base_url)
    highlight_rows = render_target_highlights_html(crashes, base_url)
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light">
<style>
html, body {{ color-scheme: light only; }}
body {{ margin:0; padding:18px; background:#f8fafc; color:#111827; font:14px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; }}
a {{ color:#0645ad; text-decoration:none; font-weight:600; }}
h1 {{ margin:0 0 8px; font-size:22px; color:#0f172a; }}
h2 {{ margin:22px 0 8px; font-size:16px; color:#0f172a; }}
.muted {{ color:#334155; }}
.kpis {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; margin:16px 0; }}
.kpi {{ border:1px solid #cbd5e1; border-radius:6px; padding:10px; background:#ffffff; }}
.label {{ color:#475569; font-size:12px; text-transform:uppercase; }}
.value {{ font-size:22px; color:#0f172a; font-weight:650; }}
table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
th, td {{ border-bottom:1px solid #cbd5e1; padding:7px; text-align:left; vertical-align:top; }}
th {{ color:#0f172a; background:#e2e8f0; font-size:12px; text-transform:uppercase; }}
code {{ color:#111827; background:#e2e8f0; border-radius:3px; padding:1px 3px; font-family:SFMono-Regular,Menlo,monospace; font-size:12px; word-break:break-all; }}
pre {{ color:#111827; white-space:pre-wrap; background:#f1f5f9; border-left:3px solid #2563eb; padding:10px; overflow:auto; }}
li {{ margin:4px 0; }}
@media (prefers-color-scheme: dark) {{
  body {{ background:#f8fafc !important; color:#111827 !important; }}
  a {{ color:#0645ad !important; }}
  h1, h2, .value {{ color:#0f172a !important; }}
  .muted {{ color:#334155 !important; }}
  .kpi {{ background:#ffffff !important; border-color:#cbd5e1 !important; }}
  th {{ background:#e2e8f0 !important; color:#0f172a !important; }}
  td {{ border-color:#cbd5e1 !important; }}
  code {{ background:#e2e8f0 !important; color:#111827 !important; }}
  pre {{ background:#f1f5f9 !important; color:#111827 !important; }}
}}
@media (max-width: 760px) {{
  body {{ padding:12px; }}
  .kpis {{ grid-template-columns:1fr; }}
  table, thead, tbody, th, td, tr {{ display:block; }}
  thead {{ display:none; }}
  td {{ border-bottom:0; padding:5px 0; }}
  tr {{ border-bottom:1px solid #cbd5e1; padding:8px 0; }}
}}
</style>
</head>
<body>
<h1>Fuzzah crash digest</h1>
<p class="muted">Generated {html.escape(snapshot.get('generated_at', '?'))}. Dashboard: <a href="{html.escape(base_url)}">{html.escape(base_url)}</a></p>
<div class="kpis">
  <div class="kpi"><div class="label">targets</div><div class="value">{t['targets']}</div></div>
  <div class="kpi"><div class="label">alive fuzzers</div><div class="value">{t['alive']}</div></div>
  <div class="kpi"><div class="label">execs/sec</div><div class="value">{t['execs_per_sec']:.0f}</div></div>
  <div class="kpi"><div class="label">untriaged raw crashes</div><div class="value">{t['unseen']}</div></div>
</div>
<h2>High-value crash clusters</h2>
<table>
<thead><tr><th>target</th><th>crash</th><th>status</th><th>hits</th><th>priority</th><th>changed</th><th>why</th><th>top frame</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<h2>Per-target highlights</h2>
<table>
<thead><tr><th>target</th><th>top high-value clusters</th></tr></thead>
<tbody>{highlight_rows}</tbody>
</table>
<h2>Target summary</h2>
<table>
<thead><tr><th>target</th><th>engine</th><th>alive</th><th>exec/s</th><th>triaged</th><th>raw backlog</th><th>states</th></tr></thead>
<tbody>{target_rows}</tbody>
</table>
<h2>Triage drain</h2>
<pre>{html.escape(triage_log or '(skipped)')}</pre>
<h2>Repro promotion</h2>
<pre>{html.escape(repro_log or '(skipped)')}</pre>
</body>
</html>
"""


def render_text(snapshot: dict, crashes: list[dict], base_url: str, limit: int, triage_log: str, repro_log: str) -> str:
    t = totals(snapshot)
    lines = [
        "Fuzzah crash digest",
        f"Generated: {snapshot.get('generated_at', '?')}",
        f"Dashboard: {base_url}",
        "",
        f"Targets: {t['targets']}  Alive fuzzers: {t['alive']}  Execs/sec: {t['execs_per_sec']:.0f}  Raw backlog: {t['unseen']}",
        "",
        "High-value crash clusters:",
    ]
    if not crashes:
        lines.append("  none above the memory-corruption gate")
    for c in crashes[:limit]:
        url = dashboard_url(base_url, c["dashboard_path"])
        reasons = ", ".join(c.get("reasons") or [])
        lines.append(
            f"  {c['target']} {c.get('hash')} status={c.get('status')} hits={c.get('hit_count')} "
            f"priority={c.get('score')} changed={'yes' if c.get('changed') else 'no'} why={reasons}"
        )
        lines.append(f"    {url}")
        lines.append(f"    frame: {c.get('top_frame') or '?'}")
        if c.get("has_report") and c.get("has_poc"):
            lines.append("    report: REPORT.md and POC.md ready on crash page")
        elif c.get("engine") == "jackalope":
            note = ["jackalope"]
            if c.get("signature"):
                note.append(str(c.get("signature")))
            if c.get("has_trace"):
                note.append("trace.txt")
            lines.append("    artifacts: " + " · ".join(note))
    lines.extend(["", "Per-target highlights:"])
    groups = grouped_highlights(crashes)
    if not groups:
        lines.append("  none")
    for target, items in sorted(groups.items()):
        lines.append(f"  {target}:")
        for c in items:
            url = dashboard_url(base_url, c["dashboard_path"])
            label = c.get("issue_class") or c.get("top_frame") or c.get("hash")
            detail = c.get("impact") or c.get("status") or ""
            lines.append(f"    {c.get('hash')} priority={c.get('score')} {label} {detail}")
            lines.append(f"      {url}")
    lines.extend(["", "Target summary:"])
    for target in snapshot.get("targets", []):
        raw = target.get("raw_crashes") or {}
        counts = target.get("state_counts") or {}
        states = " ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        lines.append(
            f"  {target.get('name')}: engine={target_engine(target)} alive={target.get('alive_roles')} "
            f"exec/s={float(target.get('execs_per_sec') or 0):.0f} "
            f"triaged={len(target.get('crashes', []))} raw_backlog={raw.get('unseen', 0)} states={states}"
        )
    lines.extend(["", "Triage drain:", triage_log or "(skipped)", "", "Repro promotion:", repro_log or "(skipped)"])
    return "\n".join(lines) + "\n"


def subject_for(snapshot: dict, crashes: list[dict], limit: int) -> str:
    t = totals(snapshot)
    changed = sum(1 for c in crashes if c.get("changed"))
    if changed:
        shown = min(limit, len(crashes))
        if changed > shown:
            return f"[fuzzah] top {shown} of {changed} changed crash cluster(s)"
        return f"[fuzzah] {changed} changed crash cluster(s)"
    if crashes:
        return f"[fuzzah] {len(crashes)} high-value crash cluster(s), no new changes"
    return f"[fuzzah] no high-value memory-corruption crashes ({t['alive']} fuzzers, {t['execs_per_sec']:.0f} exec/s)"


def write_artifacts(log_dir: Path, snapshot: dict, html_body: str, text_body: str) -> tuple[Path, Path, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    html_path = log_dir / f"crash-digest-{stamp}.html"
    text_path = log_dir / f"crash-digest-{stamp}.txt"
    json_path = log_dir / f"crash-digest-{stamp}.json"
    html_path.write_text(html_body)
    text_path.write_text(text_body)
    json_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    return html_path, text_path, json_path


def resend(api_key: str, sender: str, recipients: list[str], subject: str, html_body: str, text_body: str) -> dict:
    now = now_utc()
    bucket_hour = (now.hour // 6) * 6
    bucket = now.replace(hour=bucket_hour, minute=0, second=0, microsecond=0)
    idem_material = f"{bucket.isoformat()}|{subject}|{','.join(recipients)}"
    idem = "fuzzah-" + hashlib.sha256(idem_material.encode()).hexdigest()[:32]
    payload = {
        "from": sender,
        "to": recipients,
        "subject": subject,
        "html": html_body,
        "text": text_body,
    }
    req = urllib.request.Request(
        RESEND_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Idempotency-Key": idem,
            "User-Agent": "fuzzah-crash-digest/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend HTTP {e.code}: {body}") from e


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="send fuzzah crash digest via Resend")
    p.add_argument("--dry-run", action="store_true", help="render artifacts but do not call Resend or update state")
    p.add_argument("--skip-triage", action="store_true", help="skip bounded triage drain before collecting state")
    p.add_argument("--skip-repro", action="store_true", help="skip deterministic repro/report promotion before collecting state")
    p.add_argument("--env-file", help="extra env file with RESEND_API_KEY and digest settings")
    p.add_argument("--base-url", help="dashboard base URL, e.g. https://host.tailnet.ts.net")
    p.add_argument("--state", type=Path, default=None, help="state JSON path")
    p.add_argument("--log-dir", type=Path, default=None, help="where to write rendered digest artifacts")
    p.add_argument("--limit", type=int, default=int(os.environ.get("FUZZ_DIGEST_MAX_CRASHES", "12")))
    p.add_argument("--triage-timeout", type=int, default=int(os.environ.get("FUZZ_DIGEST_DRAIN_TIMEOUT", "900")))
    p.add_argument("--repro-timeout", type=int, default=int(os.environ.get("FUZZ_DIGEST_PROMOTE_TIMEOUT", "600")))
    p.add_argument("--collect-timeout", type=int, default=int(os.environ.get("FUZZ_DIGEST_COLLECT_TIMEOUT", "90")))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    loaded_env = load_env_files(args.env_file)
    base_url = args.base_url or os.environ.get("FUZZ_DASHBOARD_BASE_URL") or "http://localhost:8765"
    state_path = args.state or (Path(os.environ["FUZZ_DIGEST_STATE"]) if os.environ.get("FUZZ_DIGEST_STATE") else default_state_path())
    log_dir = args.log_dir or (Path(os.environ["FUZZ_DIGEST_LOG_DIR"]) if os.environ.get("FUZZ_DIGEST_LOG_DIR") else default_log_dir())
    state_path = Path(state_path).expanduser()
    log_dir = Path(log_dir).expanduser()

    triage_log = "(skipped)"
    if not args.skip_triage:
        triage_log = drain_triage(args.triage_timeout)
    repro_log = "(skipped)"
    if not args.skip_repro:
        repro_log = promote_repros(args.repro_timeout)
    snapshot = filter_snapshot_targets(collect_snapshot(args.collect_timeout), excluded_targets())
    state = load_state(state_path)
    ranked, all_crashes = flatten_rank(snapshot, state)
    html_body = render_html(snapshot, ranked, base_url, args.limit, triage_log, repro_log)
    text_body = render_text(snapshot, ranked, base_url, args.limit, triage_log, repro_log)
    subject = subject_for(snapshot, ranked, args.limit)
    html_path, text_path, json_path = write_artifacts(log_dir, snapshot, html_body, text_body)

    print(f"subject: {subject}")
    print(f"artifacts: {html_path} {text_path} {json_path}")
    if loaded_env:
        print("loaded env files: " + ", ".join(str(p) for p in loaded_env))

    if args.dry_run:
        print("dry-run: not sending and not updating state")
        return 0

    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        raise RuntimeError("RESEND_API_KEY is not set; create a private env file or export it before sending")
    sender = os.environ.get("FUZZ_DIGEST_FROM", "Fuzzah <michael@msandborn.dev>")
    recipients = [x.strip() for x in os.environ.get("FUZZ_DIGEST_TO", "michael@msandborn.dev").split(",") if x.strip()]
    result = resend(api_key, sender, recipients, subject, html_body, text_body)
    save_state(state_path, snapshot, all_crashes)
    print(f"sent: status={result.get('status')} body={result.get('body')}")
    print(f"state: {state_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        raise SystemExit(1)
