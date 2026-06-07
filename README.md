# Jura Server Guard
Open-source server security monitoring panel for hosting servers and PHP websites.

**Jura AV Monitor is the built-in malware detection module of Jura Server Guard.**

License: **GNU AGPL-3.0-or-later**. Target OS for the first MVP: **AlmaLinux 8/9** with ISPmanager-style websites in `/var/www/*/data/www/*`.

## Features

- Local web panel on a separate port (`http://127.0.0.1:8765` by default; use a VPN, SSH tunnel, or reverse proxy if remote access is needed).
- Required admin login for the panel.
- MariaDB/MySQL production backend by default; SQLite remains available for local development and very small installations.
- Lock-aware CLI scanner for all sites, a single server user, or a single site path, with old/dubl/backup/storage exclusions and progress output.
- Inventory of `/var/www/{user}/data/www/{site}` users and websites.
- File snapshot history with SHA-256, size, mtime, owner, group, permissions, missing-file tracking, and important-file change findings.
- Built-in Jura AV Monitor malware rules for webshell markers, suspicious PHP functions, risky upload/cache paths, suspicious filenames, and 32-character hex PHP names.
- Built-in allowlist for common CMS/plugin false positives such as Twig `Environment.php`, Joomla/OpenCart loaders, Joomla/Akeeba restore/extract scripts, Freemius updater files, Regular Labs URI classes, OpenCart normal `home.php` controllers, WordPress plugin `index.php`, and WordPress block asset files.
- Suspicious access/error log analyzer with false-positive exclusions for normal delivery URLs/images.
- Safe CLI quarantine and restore workflow.
- Web quarantine buttons are disabled by default unless `JURA_WEB_ACTIONS_ENABLED=true`.
- OpenAI analysis service interface is prepared, but AI is disabled by default in the MVP.

## AlmaLinux installation

```bash
git clone https://example.com/jura-server-guard.git
cd jura-server-guard
sudo bin/install-almalinux.sh
```

The installer checks root privileges, asks for the database backend (MariaDB/MySQL recommended for production; SQLite for small/local installs), detects a PHP 8.2+ binary with the matching PDO extension, prepares `/opt/jura-server-guard`, creates `.env`, verifies MySQL connectivity when selected, installs Composer dependencies with the selected PHP binary, runs migrations, seeds rules, creates a random admin password, installs a localhost-only web-panel systemd service, and installs a 30-minute lock-aware scan timer. If Composer is not available in `PATH`, the installer downloads a local bundled `composer.phar` into `/opt/jura-server-guard/bin/composer.phar` and runs it through the selected PHP binary.

Final output includes:

```text
Jura Server Guard installed.
Panel: http://127.0.0.1:8765
Default login: admin@example.com
Default password: generated-password
Config: /opt/jura-server-guard/.env
```

The password is shown once. Save it in a password manager.

### PHP selection on ISPmanager/AlmaLinux

ISPmanager servers can keep native system PHP at 8.0 for panel compatibility while alternative PHP versions are installed under `/opt/php82/bin/php`, `/opt/php83/bin/php`, `/opt/php84/bin/php`, and newer paths. The installer does not change system PHP, does not reset DNF PHP modules, and does not break ISPmanager native PHP.

During installation, `bin/install-almalinux.sh` searches for a usable PHP binary in this order: `JURA_PHP_BIN`, `php` from `PATH`, `/opt/php85/bin/php`, `/opt/php84/bin/php`, `/opt/php83/bin/php`, `/opt/php82/bin/php`, `/usr/bin/php`, and `/usr/local/bin/php`. Each candidate must be executable, PHP 8.2 or newer, and have `PDO` plus the selected DB extension loaded (`pdo_mysql` for MySQL or `pdo_sqlite` for SQLite). The `sqlite3` extension is recommended; if it is missing but `pdo_sqlite` is present, the installer prints a warning and continues.

If several suitable PHP binaries are found in an interactive shell, the installer asks which one to use and recommends `/opt/php83/bin/php` when available. In non-interactive mode, it uses a valid `JURA_PHP_BIN` first, then `/opt/php83/bin/php`, then the highest suitable PHP it found. The selected path is written to `.env` as `JURA_PHP_BIN` and used directly in systemd services instead of `/usr/bin/env php`. The web panel also reads `JURA_PHP_BIN` when `artisan serve` starts the PHP built-in development server, so the child server continues to run with the selected PHP binary instead of falling back to `php` from `PATH`.

To force a specific alternative PHP binary, run:

```bash
sudo JURA_PHP_BIN=/opt/php83/bin/php bin/install-almalinux.sh
```

## Web panel

Default service command, using the PHP binary selected by the installer and binding only to localhost for security:

```bash
/opt/php83/bin/php artisan serve --host=127.0.0.1 --port=8765
```

`artisan serve` reads `JURA_PHP_BIN` from `.env` and starts the built-in server with that same binary, for example `/opt/php83/bin/php -S 127.0.0.1:8765 -t public public/index.php`. If `JURA_PHP_BIN` is unset or not executable, it falls back to `PHP_BINARY`.

Panel pages:

- Dashboard
- Users
- Sites
- Findings
- Suspicious logs
- Quarantine
- Rules and allowlist
- Settings

## CLI commands

```bash
php artisan guard:scan [--force] [--no-lock] [--include-old] [--include-storage] [--include-backups] [--max-files=200000] [--max-seconds=300] [--dry-run]
php artisan guard:scan-user USERNAME
php artisan guard:scan-site /var/www/user/data/www/example.com
php artisan guard:logs
php artisan guard:scan-unlock [--force]
php artisan guard:cleanup-running-scans [--hours=2]
php artisan guard:prune --days=30
php artisan guard:db-stats
php artisan guard:optimize-db
php artisan guard:quarantine FINDING_ID
php artisan guard:restore QUARANTINE_ID
php artisan guard:status
```

Scanner and log commands use a global lock at `storage/locks/scan.lock` so timer and manual scans cannot overlap. If a scan is already running, the second command exits with the lock start time and PID. `--force` removes a stale lock; `--no-lock` is only for debugging.

By default scan-user scans active/normal sites only and excludes old/dubl/backup/storage/cache/temp/vendor/node_modules paths. Use `--include-old`, `--include-storage`, or `--include-backups` for explicit expanded scope.

## Scanner rules

Rules live in `rules/default-rules.php` and are seeded into SQLite. The scanner reads only the first configured bytes of PHP files (`JURA_MAX_FILE_READ_BYTES`, default `262144`) and combines file path, filename, string indicators, and suspicious PHP function combinations.

A single `base64_decode(` match is not treated as critical by itself. It becomes more important when combined with other suspicious functions, risky paths, or known malware indicators.

## Quarantine

Quarantine is safest through CLI:

```bash
php artisan guard:quarantine 123
php artisan guard:restore 45
```

Files are moved to:

```text
/root/jura-server-guard/quarantine/{original_path}
```

For example:

```text
/root/jura-server-guard/quarantine/var/www/zao/data/www/zaodessu.com.ua/mah.php
```

The original SHA-256, owner, group, permissions, mtime, original path, and quarantine path are stored in `quarantine_items`.

## Allowlist

Built-in allowlist patterns reduce false positives for known CMS and commercial module files. Allowlisted files can still appear as low-risk findings when they change recently or match suspicious indicators, but the MVP never auto-quarantines them.

## Cron/systemd timer

The installer creates:

```text
/etc/systemd/system/jura-server-guard-scan.service
/etc/systemd/system/jura-server-guard-scan.timer
```

Timer period: every 30 minutes by default. The app-level scan lock prevents overlapping timer/manual scans.

Manual cron alternative:

```cron
*/10 * * * * cd /opt/jura-server-guard && /opt/php83/bin/php artisan guard:scan >> /var/log/jura-server-guard-scan.log 2>&1
```

## Security notes

- Keep the panel behind a firewall or VPN where possible.
- The panel requires admin authentication.
- Web actions are disabled by default: `JURA_WEB_ACTIONS_ENABLED=false`.
- The panel previews only a limited prefix of suspicious files.
- Do not download quarantined malware to workstations without proper isolation.
- Review findings before quarantine; Jura AV Monitor is an MVP monitor, not a perfect antivirus.

## License

GNU AGPL-3.0-or-later. See `LICENSE`.


## Database backend

Production AlmaLinux/ISPmanager servers should use MariaDB/MySQL:

```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=jura_server_guard
DB_USERNAME=jsg
DB_PASSWORD=...
DB_CHARSET=utf8mb4
DB_COLLATION=utf8mb4_unicode_ci
```

SQLite remains supported for development or very small installs:

```env
DB_CONNECTION=sqlite
DB_DATABASE=/opt/jura-server-guard/storage/database.sqlite
```

Manual MySQL creation example:

```sql
CREATE DATABASE jura_server_guard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'jsg'@'localhost' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON jura_server_guard.* TO 'jsg'@'localhost';
FLUSH PRIVILEGES;
```

## CSV export and false-positive controls

Findings and Suspicious logs pages include CSV export buttons that preserve current filters. Findings are deduplicated by path/type/rule fingerprint, ignored findings are not recreated unless the file hash changes, and known Joomla/Akeeba/Freemius/Jetpack/SuiteCRM/Regular Labs/OpenCart paths are allowlisted so normal CMS/plugin files are not high/critical by filename alone. High/critical risk is reserved for known IOC strings, webshell callbacks, ALFA_DATA/alfacgiapi, malware-like filenames, risky upload/cache PHP with execution indicators, and suspicious HTTP events linked to the exact file.
