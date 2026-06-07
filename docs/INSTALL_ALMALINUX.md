# Installing Jura Server Guard on AlmaLinux 8/9

## Requirements

- AlmaLinux 8 or 9 with root shell and systemd.
- PHP 8.2+ with `PDO` and the extension for the selected DB backend:
  - production MariaDB/MySQL: `pdo_mysql`;
  - small/local SQLite: `pdo_sqlite`.
- Composer in `PATH`, or `curl`/`wget` so the installer can download a bundled Composer PHAR.

## Recommended production database

MariaDB/MySQL is recommended for real ISPmanager/shared-hosting servers. SQLite remains available for local development and very small installations only.

Manual DB creation example:

```sql
CREATE DATABASE jura_server_guard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'jsg'@'localhost' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON jura_server_guard.* TO 'jsg'@'localhost';
FLUSH PRIVILEGES;
```

Non-interactive install example:

```bash
sudo JURA_PHP_BIN=/opt/php83/bin/php \
  JURA_DB_CONNECTION=mysql \
  JURA_DB_HOST=127.0.0.1 \
  JURA_DB_PORT=3306 \
  JURA_DB_DATABASE=jura_server_guard \
  JURA_DB_USERNAME=jsg \
  JURA_DB_PASSWORD='STRONG_PASSWORD' \
  bin/install-almalinux.sh
```

Interactive installation asks:

```text
Select database backend:
[1] MariaDB/MySQL recommended for production
[2] SQLite only for small/local installations
```

The default is MySQL. The installer writes DB settings to `.env`, checks the selected PHP extension, verifies MySQL connectivity, runs migrations, creates the admin user, creates systemd service/timer units, prints the generated password, and starts services. It does not drop or destroy existing databases.

## PHP on ISPmanager/AlmaLinux

ISPmanager often keeps `/usr/bin/php` at 8.0 while alternative PHP versions live under `/opt/php82/bin/php`, `/opt/php83/bin/php`, `/opt/php84/bin/php`, etc. Do not change native system PHP for Jura Server Guard. Set or select `JURA_PHP_BIN=/opt/php83/bin/php` (or newer). The installer writes it to `.env`, systemd uses it directly, and `artisan serve` also uses `JURA_PHP_BIN` for the child `php -S` process so the panel does not fall back to `/usr/bin/php`.

## Safe production defaults

The installer uses:

```env
JURA_WEB_ACTIONS_ENABLED=false
JURA_BIND_HOST=127.0.0.1
JURA_PORT=8765
JURA_SCAN_INTERVAL_MINUTES=30
JURA_SCAN_OLD_DUBL_BY_DEFAULT=false
JURA_SCAN_STORAGE_BY_DEFAULT=false
JURA_HASH_ALL_FILES=false
```

The panel is bound to localhost by default. Use SSH tunnel, VPN, or a restricted TLS reverse proxy for remote access.

## Scan lock and scope controls

All heavy scanner/log commands use `storage/locks/scan.lock`. If another scan is active, a new scan exits with a message showing start time and PID. Use `--force` only to remove a stale lock whose PID is dead, and `--no-lock` only for debugging.

```bash
/opt/php83/bin/php artisan guard:scan
/opt/php83/bin/php artisan guard:scan-user USER --include-old --include-backups
/opt/php83/bin/php artisan guard:scan-unlock --force
/opt/php83/bin/php artisan guard:cleanup-running-scans --hours=2
```

By default `guard:scan-user` scans only active/normal site directories from `/var/www/*/data/www/*` and excludes old, dubl, backup, storage, cache, temp, vendor, and node_modules paths. Use `--include-old`, `--include-storage`, or `--include-backups` when you intentionally want those trees.

## Maintenance commands

```bash
/opt/php83/bin/php artisan guard:db-stats
/opt/php83/bin/php artisan guard:prune --days=30
/opt/php83/bin/php artisan guard:optimize-db
```

SQLite optimization runs `VACUUM`/`ANALYZE`; MySQL optimization shows table statistics and runs `OPTIMIZE TABLE`.

## CSV export

The web panel provides CSV export links on Findings and Suspicious logs. Current filters are included in the export query: risk, user/site, status/type, path or URI contains, IP, and date range.

## SQLite to MySQL migration note

For large production servers, create a fresh MySQL database, set `DB_CONNECTION=mysql` and credentials in `.env`, run `php artisan migrate`, and rescan. Existing SQLite findings can be exported from the web panel as CSV before switching. Direct automated SQLite-to-MySQL import is intentionally not performed by the installer to avoid destructive surprises.
