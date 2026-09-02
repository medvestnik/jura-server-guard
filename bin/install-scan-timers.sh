#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${JURA_APP_DIR:-/opt/jura-server-guard}"
ENV_FILE="$APP_DIR/.env"
UNIT_DIR="${JURA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

env_value() {
  local key="$1"
  local fallback="$2"
  local value=""
  if [[ -f "$ENV_FILE" ]]; then
    value=$(sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n 1)
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
  fi
  printf '%s' "${value:-$fallback}"
}

PHP_BIN="${JURA_PHP_BIN:-$(env_value JURA_PHP_BIN /usr/bin/php)}"
SCAN_PROFILE="${JURA_TIMER_SCAN_PROFILE:-$(env_value JURA_TIMER_SCAN_PROFILE fast)}"
SCAN_INTERVAL="${JURA_SCAN_INTERVAL_MINUTES:-$(env_value JURA_SCAN_INTERVAL_MINUTES 30)}"
LOG_INTERVAL="${JURA_LOG_SCAN_INTERVAL_MINUTES:-$(env_value JURA_LOG_SCAN_INTERVAL_MINUTES 5)}"
SYSTEMCTL_CMD="${JURA_SYSTEMCTL_CMD:-$(env_value JURA_SYSTEMCTL_CMD /usr/bin/systemctl)}"

if [[ ! -x "$PHP_BIN" ]]; then
  echo "PHP binary is not executable: $PHP_BIN" >&2
  exit 1
fi
if [[ ! -f "$APP_DIR/artisan" ]]; then
  echo "Jura Server Guard is not installed in $APP_DIR" >&2
  exit 1
fi
if [[ ! -x "$SYSTEMCTL_CMD" ]]; then
  echo "systemctl command is not executable: $SYSTEMCTL_CMD" >&2
  exit 1
fi
if [[ ! "$SCAN_PROFILE" =~ ^(fast|standard|deep)$ ]]; then
  echo "Invalid JURA_TIMER_SCAN_PROFILE: $SCAN_PROFILE" >&2
  exit 1
fi
if [[ ! "$SCAN_INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
  echo "JURA_SCAN_INTERVAL_MINUTES must be a positive integer." >&2
  exit 1
fi
if [[ ! "$LOG_INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
  echo "JURA_LOG_SCAN_INTERVAL_MINUTES must be a positive integer." >&2
  exit 1
fi

mkdir -p "$UNIT_DIR"

cat >"$UNIT_DIR/jura-server-guard-scan.service" <<EOF
[Unit]
Description=Jura Server Guard scheduled file scan

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/artisan guard:scan --profile=$SCAN_PROFILE --skip-logs
EOF

cat >"$UNIT_DIR/jura-server-guard-scan.timer" <<EOF
[Unit]
Description=Run Jura Server Guard file scan every $SCAN_INTERVAL minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${SCAN_INTERVAL}min
Unit=jura-server-guard-scan.service

[Install]
WantedBy=timers.target
EOF

cat >"$UNIT_DIR/jura-server-guard-logs.service" <<EOF
[Unit]
Description=Jura Server Guard suspicious log analysis

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/artisan guard:logs
EOF

cat >"$UNIT_DIR/jura-server-guard-logs.timer" <<EOF
[Unit]
Description=Analyze suspicious logs every $LOG_INTERVAL minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=${LOG_INTERVAL}min
Unit=jura-server-guard-logs.service

[Install]
WantedBy=timers.target
EOF

"$SYSTEMCTL_CMD" daemon-reload
"$SYSTEMCTL_CMD" enable jura-server-guard-scan.timer jura-server-guard-logs.timer
"$SYSTEMCTL_CMD" restart jura-server-guard-scan.timer jura-server-guard-logs.timer

echo "Installed file-scan timer (${SCAN_INTERVAL}m, profile ${SCAN_PROFILE}) and log-analysis timer (${LOG_INTERVAL}m)."
