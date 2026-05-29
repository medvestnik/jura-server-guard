#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/jura-server-guard"
PORT="8765"
ADMIN_EMAIL="${JURA_ADMIN_EMAIL:-admin@example.com}"
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
if ! command -v php >/dev/null; then echo "PHP 8.2+ is required." >&2; exit 1; fi
PHP_OK=$(php -r 'echo version_compare(PHP_VERSION, "8.2.0", ">=") ? "yes" : "no";')
if [[ "$PHP_OK" != "yes" ]]; then echo "PHP 8.2+ is required. Found: $(php -r 'echo PHP_VERSION;')" >&2; exit 1; fi
if ! command -v composer >/dev/null; then echo "Composer is required." >&2; exit 1; fi
mkdir -p "$APP_DIR"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$SRC_DIR" != "$APP_DIR" ]]; then
  rsync -a --delete --exclude='.git' --exclude='.env' --exclude='storage/database.sqlite' "$SRC_DIR/" "$APP_DIR/"
fi
cd "$APP_DIR"
if [[ ! -f .env ]]; then cp .env.example .env; fi
mkdir -p storage/logs storage/framework/cache storage/framework/sessions storage/framework/views
if ! grep -q '^DB_DATABASE=' .env; then echo "DB_DATABASE=$APP_DIR/storage/database.sqlite" >> .env; else sed -i "s#^DB_DATABASE=.*#DB_DATABASE=$APP_DIR/storage/database.sqlite#" .env; fi
touch "$APP_DIR/storage/database.sqlite"
composer install --no-dev --optimize-autoloader
php artisan key:generate
php artisan migrate --force
ADMIN_PASSWORD="$(tr -dc 'A-Za-z0-9_@%+=' </dev/urandom | head -c 24)"
php artisan guard:create-admin "$ADMIN_EMAIL" "$ADMIN_PASSWORD" >/dev/null
php artisan config:cache
cat >/etc/systemd/system/jura-server-guard.service <<EOF
[Unit]
Description=Jura Server Guard Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/env php artisan serve --host=0.0.0.0 --port=$PORT
Restart=always
RestartSec=5
Environment=APP_ENV=production

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/jura-server-guard-scan.service <<EOF
[Unit]
Description=Jura Server Guard scheduled scan

[Service]
Type=oneshot
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/env php $APP_DIR/artisan guard:scan
EOF
cat >/etc/systemd/system/jura-server-guard-scan.timer <<EOF
[Unit]
Description=Run Jura Server Guard scan every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Unit=jura-server-guard-scan.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now jura-server-guard.service
systemctl enable --now jura-server-guard-scan.timer
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
SERVER_IP=${SERVER_IP:-SERVER_IP}
cat <<EOF
Jura Server Guard installed.
Panel: http://$SERVER_IP:$PORT
Default login: $ADMIN_EMAIL
Default password: $ADMIN_PASSWORD
Config: $APP_DIR/.env
EOF
