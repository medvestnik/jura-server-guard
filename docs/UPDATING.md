# Updating an existing installation

This assumes the layout used by `bin/install-almalinux.sh`: a working git checkout
(for example `/root/jura-server-guard`) that gets reviewed and then synced into the
deployed copy at `/opt/jura-server-guard`, running under systemd units
`jura-server-guard.service` (panel) and `jura-server-guard-scan.timer`/`.service`
(scheduled scans). Adjust paths and the PHP binary (`JURA_PHP_BIN`, e.g.
`/opt/php83/bin/php`) to match your install.

## 1. Confirm no scan is currently running

```bash
cd /opt/jura-server-guard
JURA_PHP_BIN=/opt/php83/bin/php
$JURA_PHP_BIN artisan guard:scan-active
ps aux | grep -E '[a]rtisan guard:scan|[p]hp.*jura-server-guard'
```

Proceed only if it reports `Scan running: no`.

## 2. Stop the timer and the panel

```bash
systemctl disable --now jura-server-guard-scan.timer 2>/dev/null || true
systemctl stop jura-server-guard
```

## 3. Back up `.env` and the database before touching anything

```bash
TS="$(date +%F-%H%M%S)"
BACKUP_DIR="/root/jsg-before-update-$TS"
mkdir -p "$BACKUP_DIR"

cp -a /opt/jura-server-guard/.env "$BACKUP_DIR/env.backup"

DBPASS="$(grep '^DB_PASSWORD=' /opt/jura-server-guard/.env | cut -d= -f2-)"
mysqldump -u jsg -p"$DBPASS" jura_server_guard > "$BACKUP_DIR/jura_server_guard.sql"

echo "$BACKUP_DIR"; ls -lah "$BACKUP_DIR"
```

(For a SQLite install, back up `storage/database.sqlite` instead of running `mysqldump`.)

## 4. Pull the new code into the staging checkout

```bash
cd /root/jura-server-guard
git fetch --all --prune
git pull --ff-only

git log --oneline -8
git diff --name-status HEAD~1..HEAD
```

Check whether Composer dependencies changed — this determines whether step 6 needs
a Composer run:

```bash
git diff --name-only HEAD~1..HEAD | grep -E '^composer\.(json|lock)$' \
  && echo "Composer files changed" || echo "Composer files not changed"
```

## 5. Syntax-check every PHP file before deploying

Changed files first:

```bash
cd /root/jura-server-guard
git diff --name-only HEAD~1..HEAD | grep '\.php$' | xargs -r -n1 "$JURA_PHP_BIN" -l
```

Then the full application (covers `resources/lang`, `config`, `routes`, and `rules`
in addition to views — a narrower `resources/views app public` scan will silently
skip newly added directories):

```bash
find resources app public config routes rules -name '*.php' -print0 \
  | xargs -0 -n1 "$JURA_PHP_BIN" -l
```

If anything reports `Parse error`, stop here — do not rsync.

## 6. Sync into the deployed copy

```bash
rsync -a --delete \
  --exclude='.env' \
  --exclude='storage/' \
  --exclude='vendor/' \
  /root/jura-server-guard/ /opt/jura-server-guard/

chown -R root:root /opt/jura-server-guard
chown -R root:root /opt/jura-server-guard/storage
chmod -R u+rwX,go-rwx /opt/jura-server-guard/storage
```

If step 4 reported that Composer files changed, update `vendor/` in place (rsync
excludes it, so it is never refreshed automatically):

```bash
cd /opt/jura-server-guard
if [ -x bin/composer.phar ] || command -v composer >/dev/null; then
  "$JURA_PHP_BIN" "$(command -v composer || echo bin/composer.phar)" install --no-dev --optimize-autoloader
fi
```

## 7. Run migrations

```bash
cd /opt/jura-server-guard
"$JURA_PHP_BIN" artisan migrate
```

Spot-check schema changes relevant to the release you're deploying, e.g.:

```bash
DBPASS="$(grep '^DB_PASSWORD=' /opt/jura-server-guard/.env | cut -d= -f2-)"
mysql -u jsg -p"$DBPASS" jura_server_guard -e "SHOW COLUMNS FROM scan_runs;"
mysql -u jsg -p"$DBPASS" jura_server_guard -e "SHOW COLUMNS FROM log_events;"
```

## 8. Restart the panel and re-enable the scan timer

Both services were stopped in step 2 — **the timer must be explicitly re-enabled**,
otherwise scheduled scans silently stay off after the update:

```bash
systemctl daemon-reload
systemctl start jura-server-guard
systemctl enable --now jura-server-guard-scan.timer

systemctl status jura-server-guard --no-pager -l
systemctl status jura-server-guard-scan.timer --no-pager -l
ss -lntp | grep 8765
```

## 9. Smoke test

```bash
curl -m 10 -I http://127.0.0.1:8765/
curl -m 10 -I http://127.0.0.1:8765/login
"$JURA_PHP_BIN" artisan guard:status
```

Log in through the panel and check the dashboard renders without errors. If the
release changed `JURA_DEFAULT_LOCALE` behavior (see `README.md` → "Web panel
language"), confirm the default language shown to a fresh browser session matches
what you expect, and set `JURA_DEFAULT_LOCALE` explicitly in `.env` if not.
