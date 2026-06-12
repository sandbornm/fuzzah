#!/usr/bin/env bash
# Stable entry point for launchd/cron. The Python script loads the private env
# file itself, but this wrapper keeps WorkingDirectory and interpreter behavior
# predictable.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
cd "$ROOT"

exec python3 "$DIR/send-digest.py" "$@"
