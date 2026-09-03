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

## 2. Stop the timers and the panel

```bash
systemctl stop jura-server-guard-scan.timer jura-server-guard-logs.timer 2>/dev/null || true
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

## 8. Install the timers and restart the panel

If `.env.example` gained new options, first list keys that are still missing from the live
`.env` (this prints key names only, not passwords or tokens), add the settings you need, and
rebuild the cached configuration:

```bash
cd /opt/jura-server-guard
comm -23 \
  <(sed -n 's/^\([A-Z][A-Z0-9_]*\)=.*/\1/p' .env.example | sort -u) \
  <(sed -n 's/^\([A-Z][A-Z0-9_]*\)=.*/\1/p' .env | sort -u)

# After reviewing/editing .env:
"$JURA_PHP_BIN" artisan config:cache
```

Refresh the systemd units, restart both timers even if they were already active, and restart
the panel. `install-scan-timers.sh` performs `daemon-reload`, enables both timers for boot,
restarts them so new intervals/profile values from `.env` take effect, and then restarts
and enables `jura-server-guard.service` when that unit is installed. After this block the
panel and both scheduled tasks must be running:

```bash
cd /opt/jura-server-guard
sudo bash bin/install-scan-timers.sh

# Explicitly restore autostart and start the panel and both scheduled scanners.
# Keep these commands in the update block even though the installer does the same:
# they also recover units that were stopped manually before the update.
systemctl daemon-reload
systemctl enable --now jura-server-guard.service
systemctl enable --now jura-server-guard-scan.timer jura-server-guard-logs.timer
systemctl restart jura-server-guard.service \
  jura-server-guard-scan.timer \
  jura-server-guard-logs.timer

systemctl is-active jura-server-guard.service
systemctl is-active jura-server-guard-scan.timer
systemctl is-active jura-server-guard-logs.timer
systemctl status jura-server-guard --no-pager -l
systemctl status jura-server-guard-scan.timer --no-pager -l
systemctl status jura-server-guard-logs.timer --no-pager -l
systemctl list-timers 'jura-server-guard-*' --all --no-pager
ss -ltnp | grep ':8765' || true
curl -m 10 -I http://127.0.0.1:8765/
```

All three `systemctl is-active` commands must print `active`. The log-analysis timer
runs its first job about one minute after activation and the file-scan timer about two
minutes after activation. They use the same application lock, so do not start both
`.service` units manually at the same time.

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

## 10. If the panel does not open after the update

An SSH tunnel error such as `open failed: connect failed: Connection refused` means the
SSH connection itself is working, but nothing is listening on `127.0.0.1:8765` on the
server. Start the panel, verify its status, and check the listening socket:

```bash
systemctl enable --now jura-server-guard.service
systemctl status jura-server-guard.service --no-pager -l
ss -ltnp | grep ':8765' || true
```

The expected socket is `127.0.0.1:8765`. If the service is not active or the socket is
missing, inspect the service journal and the installed unit:

```bash
journalctl -u jura-server-guard.service -n 100 --no-pager
systemctl cat jura-server-guard.service
```

Test the application directly to separate an application startup error from a systemd
problem:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php artisan serve --host=127.0.0.1 --port=8765
```

If the direct server starts successfully, stop it with `Ctrl+C`, then return control to
systemd and verify the port again:

```bash
systemctl restart jura-server-guard.service
systemctl status jura-server-guard.service --no-pager -l
ss -ltnp | grep ':8765' || true
```
