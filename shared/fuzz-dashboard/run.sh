#!/usr/bin/env bash
# Thin wrapper — invoked by the /fuzz-dashboard slash command.
# Forwards args to server.py. Foreground by default; Ctrl-C to stop.
# Prefers `uv run python3` when uv is available (honours per-env Python
# policies); falls back to system python3 on hosts without uv.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v uv >/dev/null 2>&1; then
  exec uv run --no-project python3 "$DIR/server.py" "$@"
else
  exec python3 "$DIR/server.py" "$@"
fi
