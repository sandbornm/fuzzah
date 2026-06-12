---
name: fuzz-dashboard
description: Launch the fuhq browser dashboard for live fuzz state, per-target views, and per-crash drill-down. Use when the operator asks for the dashboard, browser UI, fuhq, or invokes $fuzz-dashboard. Equivalent of /fuzz-dashboard in Claude Code.
---

Starts the fuhq dashboard server in the foreground on this host. It binds to
`127.0.0.1:8765` by default and queries the fuzz host through
`shared/run-on-fuzz-host.sh`, so the same command works from a Mac host via Orb
or directly on a Linux fuzz host.

```bash
bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/fuzz-dashboard/run.sh" ${ARGUMENTS:-}
```

The server is foreground-only by default; Ctrl-C stops it. If the operator asks
for a detached server, start it explicitly in the background and report the log
path:

```bash
nohup bash "$(git rev-parse --show-toplevel 2>/dev/null || echo .)/shared/fuzz-dashboard/run.sh" ${ARGUMENTS:-} > /tmp/fuhq-dash.log 2>&1 &
```

After launch, report the URL:

- default: `http://127.0.0.1:8765`
- with `--port N`: `http://127.0.0.1:N`

Do not restart fuzzers or modify crash state from this skill. The dashboard is
a viewer unless the operator uses its explicit review-request controls.
