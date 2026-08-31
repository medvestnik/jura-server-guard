#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${JURA_APP_DIR:-/opt/jura-server-guard}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if [[ ! -d "$APP_DIR" ]]; then
  echo "Application directory not found: $APP_DIR" >&2
  echo "Set JURA_APP_DIR=/path/to/jura-server-guard if installed elsewhere." >&2
  exit 1
fi

cd "$APP_DIR"

read_env_value() {
  local key="$1"
  if [[ -f .env ]]; then
    grep -E "^${key}=" .env | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" || true
  fi
}

append_env_default() {
  local key="$1"
  local value="$2"
  if [[ ! -f .env ]]; then
    cp .env.example .env
  fi
  if ! grep -q "^${key}=" .env; then
    echo "${key}=${value}" >> .env
  fi
}

PHP_BIN="${JURA_PHP_BIN:-$(read_env_value JURA_PHP_BIN)}"
if [[ -z "$PHP_BIN" || ! -x "$PHP_BIN" ]]; then
  PHP_BIN="$(command -v php || true)"
fi
if [[ -z "$PHP_BIN" || ! -x "$PHP_BIN" ]]; then
  echo "PHP binary not found. Set JURA_PHP_BIN=/opt/php83/bin/php." >&2
  exit 1
fi

mkdir -p storage/ssh-key-monitor storage/user-cron-monitor storage/process-monitor
chmod 700 storage/ssh-key-monitor storage/user-cron-monitor storage/process-monitor

append_env_default JURA_SSH_KEY_MONITOR_FILES "/root/.ssh/authorized_keys,/var/www/*/data/.ssh/authorized_keys"
append_env_default JURA_SSH_KEY_MONITOR_STATE "$APP_DIR/storage/ssh-key-monitor/authorized_keys_state.json"
append_env_default JURA_USER_CRON_MONITOR_FILES "/var/spool/cron/*,/var/spool/cron/crontabs/*,/etc/crontab,/etc/cron.d/*,/etc/cron.hourly/*,/etc/cron.daily/*,/etc/cron.weekly/*,/etc/cron.monthly/*"
append_env_default JURA_USER_CRON_MONITOR_STATE "$APP_DIR/storage/user-cron-monitor/state.json"
append_env_default JURA_PROCESS_MONITOR_STATE "$APP_DIR/storage/process-monitor/state.json"
append_env_default JURA_PROCESS_MONITOR_INCLUDE_INFO "false"
append_env_default JURA_PROCESS_MONITOR_IGNORE_REGEX ""

# First run creates baselines without Telegram noise.
"$PHP_BIN" "$APP_DIR/bin/ssh-key-monitor.php" || true
"$PHP_BIN" "$APP_DIR/bin/user-cron-monitor.php" || true
"$PHP_BIN" "$APP_DIR/bin/process-monitor.php" || true

cat >/etc/systemd/system/jura-server-guard-ssh-keys.service <<EOF
[Unit]
Description=Jura Server Guard SSH authorized_keys monitor

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/bin/ssh-key-monitor.php
EOF

cat >/etc/systemd/system/jura-server-guard-ssh-keys.path <<'EOF'
[Unit]
Description=Watch root authorized_keys for new SSH keys

[Path]
PathChanged=/root/.ssh/authorized_keys
Unit=jura-server-guard-ssh-keys.service

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/jura-server-guard-user-cron.service <<EOF
[Unit]
Description=Jura Server Guard user/system cron monitor

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/bin/user-cron-monitor.php
EOF

cat >/etc/systemd/system/jura-server-guard-user-cron.timer <<'EOF'
[Unit]
Description=Run Jura Server Guard cron monitor every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=jura-server-guard-user-cron.service

[Install]
WantedBy=timers.target
EOF

cat >/etc/systemd/system/jura-server-guard-processes.service <<EOF
[Unit]
Description=Jura Server Guard suspicious process monitor

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=$PHP_BIN $APP_DIR/bin/process-monitor.php
EOF

cat >/etc/systemd/system/jura-server-guard-processes.timer <<'EOF'
[Unit]
Description=Run Jura Server Guard process monitor every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=jura-server-guard-processes.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now jura-server-guard-ssh-keys.path
systemctl enable --now jura-server-guard-user-cron.timer
systemctl enable --now jura-server-guard-processes.timer

cat <<EOF
Jura Server Guard security monitors installed.

Enabled units:
- jura-server-guard-ssh-keys.path     immediate authorized_keys change detection
- jura-server-guard-user-cron.timer   user/system cron check every minute
- jura-server-guard-processes.timer   suspicious process check every minute

PHP: $PHP_BIN
App: $APP_DIR

Check status:
  systemctl status jura-server-guard-ssh-keys.path --no-pager
  systemctl list-timers | grep jura-server-guard
EOF
