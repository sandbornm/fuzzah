---
description: Launch the fuhq browser dashboard — live fuzz state, per-target view, per-crash drill-down. Foreground server; Ctrl-C to stop.
argument-hint: "[--port N] [--host H]"
allowed-tools: Bash(bash:*), Bash(python3:*)
---

Starts the fuhq dashboard server in the foreground on this host. Binds to
`127.0.0.1:8765` by default (configurable via `--port`). The server queries
the fuzz host via `shared/run-on-fuzz-host.sh` so the same code path works on
the Mac (proxies through orb) or on the bare-Linux fuzz host itself.

To view from a different machine, SSH-forward the port and open the URL:

```sh
ssh -L 8765:localhost:8765 <user>@<host-running-dashboard>
# then open http://localhost:8765
```

Routes:

- `/` — health banner (alive / calibrating / idle / host-unreachable / no-targets), target list, raw check-in
- `/t/<target>` — per-role live stats (execs/s, pending queue, stats age), crash list grouped by status, family index
- `/c/<target>/<hash>` — per-crash `NOTES.md`, `meta.json`, `trace.txt`, PoC download
- `/families/<target>/<family>` — family-level `CONTEXT.md` and file listing
- `/invalidate` — clear the in-memory TTL cache (useful right after writing new NOTES.md)

```bash
bash shared/fuzz-dashboard/run.sh $ARGUMENTS
```

The server is foreground only; Ctrl-C stops it. Cache TTLs are short (10–60s)
so the dashboard is "live enough" without hammering the fuzz host. PoCs
stream as base64 through the host wrapper so downloads are safe even for
crashes that hard-trap the parser.

If you want it running detached (so you can keep using the shell), start it
in the background yourself: `nohup bash shared/fuzz-dashboard/run.sh > /tmp/fuhq-dash.log 2>&1 &`.
