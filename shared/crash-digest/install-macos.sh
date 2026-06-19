#!/usr/bin/env bash
# Install the Mac-side dashboard + six-hour crash digest launchd jobs.
#
# This writes outside the repo:
#   ~/Library/LaunchAgents/dev.msandborn.fuzzah.dashboard.plist
#   ~/Library/LaunchAgents/dev.msandborn.fuzzah.crash-digest.plist
#   ~/Library/Logs/fuzzah/
#   /Users/minimo/fuzzig/.secrets/fuzz-crash-digest.env
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
CONTROL_ROOT="$(cd "$ROOT/.." && pwd)"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
LOG_DIR="$HOME/Library/Logs/fuzzah"
ENV_FILE="${FUZZ_DIGEST_ENV:-$CONTROL_ROOT/.secrets/fuzz-crash-digest.env}"
DASHBOARD_PLIST="$LAUNCH_AGENTS/dev.msandborn.fuzzah.dashboard.plist"
DIGEST_PLIST="$LAUNCH_AGENTS/dev.msandborn.fuzzah.crash-digest.plist"
PORT="${FUZZ_DASHBOARD_PORT:-8765}"
DRY_RUN=0
LOAD=1
TAILSCALE_SERVE=0

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --no-load) LOAD=0 ;;
    --tailscale-serve) TAILSCALE_SERVE=1 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

run() {
  if (( DRY_RUN )); then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

detect_base_url() {
  if [[ -n "${FUZZ_DASHBOARD_BASE_URL:-}" ]]; then
    printf '%s\n' "$FUZZ_DASHBOARD_BASE_URL"
    return
  fi
  if command -v tailscale >/dev/null 2>&1; then
    local domain=""
    domain="$(tailscale status --self --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("Self") or d).get("DNSName") or ((d.get("Self") or d).get("CertDomains") or [""])[0])' 2>/dev/null || true)"
    domain="${domain%.}"
    if [[ -n "$domain" ]]; then
      printf 'https://%s\n' "$domain"
      return
    fi
  fi
  printf 'http://localhost:%s\n' "$PORT"
}

existing_key() {
  if [[ -n "${RESEND_API_KEY:-}" ]]; then
    printf '%s\n' "$RESEND_API_KEY"
    return
  fi
  if [[ -f "$ENV_FILE" ]]; then
    awk -F= '/^RESEND_API_KEY=/ {print substr($0, index($0,$2)); exit}' "$ENV_FILE"
  fi
}

write_env_file() {
  local base_url="$1"
  local key
  key="$(existing_key || true)"
  run mkdir -p "$(dirname "$ENV_FILE")"
  if (( DRY_RUN )); then
    echo "[dry-run] would write $ENV_FILE (RESEND_API_KEY redacted)"
    return
  fi
  umask 077
  {
    echo "# Private config for fuzzah crash digest. chmod 600."
    echo "FUZZ_DASHBOARD_BASE_URL=$base_url"
    echo "FUZZ_DIGEST_FROM=Fuzzah <michael@msandborn.dev>"
    echo "FUZZ_DIGEST_TO=michael@msandborn.dev"
    echo "FUZZ_DIGEST_MAX_TRIAGE_PER_TARGET=25"
    echo "FUZZ_DIGEST_MAX_TRIAGE_TOTAL=75"
    echo "FUZZ_DIGEST_REPRO_LIMIT=6"
    echo "FUZZ_DIGEST_REPRO_TIMEOUT=45"
    echo "FUZZ_DIGEST_MIN_REPORT_PRIORITY=80"
    echo "FUZZ_DIGEST_ONLY_HIGH_VALUE=1"
    echo "FUZZ_DIGEST_EXCLUDE_TARGETS=poppler,libvpx"
    if [[ -n "$key" && "$key" != "REPLACE_ME" ]]; then
      echo "RESEND_API_KEY=$key"
    else
      echo "RESEND_API_KEY=REPLACE_ME"
    fi
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

write_plists() {
  run mkdir -p "$LAUNCH_AGENTS" "$LOG_DIR"
  if (( DRY_RUN )); then
    echo "[dry-run] would write $DASHBOARD_PLIST"
    echo "[dry-run] would write $DIGEST_PLIST"
    return
  fi
  cat > "$DASHBOARD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.msandborn.fuzzah.dashboard</string>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>FUZZ_DASHBOARD_READ_ONLY</key><string>1</string>
  </dict>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT/shared/fuzz-dashboard/run.sh</string>
    <string>--host</string><string>127.0.0.1</string>
    <string>--port</string><string>$PORT</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/dashboard.out.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/dashboard.err.log</string>
</dict>
</plist>
EOF

  cat > "$DIGEST_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.msandborn.fuzzah.crash-digest</string>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT/shared/crash-digest/send-digest.sh</string>
    <string>--env-file</string><string>$ENV_FILE</string>
  </array>
  <key>StartInterval</key><integer>21600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/crash-digest.out.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/crash-digest.err.log</string>
</dict>
</plist>
EOF
}

load_jobs() {
  (( LOAD )) || return 0
  run launchctl unload "$DASHBOARD_PLIST" 2>/dev/null || true
  run launchctl unload "$DIGEST_PLIST" 2>/dev/null || true
  run launchctl load "$DASHBOARD_PLIST"
  run launchctl load "$DIGEST_PLIST"
}

configure_tailscale() {
  (( TAILSCALE_SERVE )) || return 0
  if ! command -v tailscale >/dev/null 2>&1; then
    echo "[!] tailscale not found; skipping Serve config" >&2
    return 0
  fi
  run tailscale serve --bg "$PORT"
}

base_url="$(detect_base_url)"
write_env_file "$base_url"
write_plists
load_jobs
configure_tailscale

cat <<EOF
[+] crash digest install complete
env:       $ENV_FILE
dashboard: http://localhost:$PORT
email URL: $base_url
logs:      $LOG_DIR

Dry-run an email:
  bash "$ROOT/shared/crash-digest/send-digest.sh" --env-file "$ENV_FILE" --dry-run
EOF
