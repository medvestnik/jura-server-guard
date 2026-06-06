# Installing Jura Server Guard on AlmaLinux 8/9

## Requirements

- AlmaLinux 8 or 9
- root shell
- PHP 8.2 or newer with `PDO` and `pdo_sqlite`
- Composer in `PATH`, or `curl`/`wget` so the installer can download a bundled Composer PHAR
- systemd

## Install

```bash
git clone https://example.com/jura-server-guard.git
cd jura-server-guard
sudo bin/install-almalinux.sh
```

The installer copies the project to `/opt/jura-server-guard`, detects a PHP 8.2+ binary, creates `/opt/jura-server-guard/storage/database.sqlite`, installs dependencies with Composer, runs migrations, creates a random admin password, starts the web panel on port `8765`, and enables a scan timer every 10 minutes. If Composer is missing from `PATH`, the installer downloads `https://getcomposer.org/download/latest-stable/composer.phar` to `/opt/jura-server-guard/bin/composer.phar` and runs it with the selected PHP binary.


## PHP on ISPmanager/AlmaLinux

ISPmanager installations often keep native PHP at `/usr/bin/php` version 8.0. Do not change that native PHP just for Jura Server Guard: the installer supports ISPmanager-style alternative PHP binaries such as `/opt/php82/bin/php`, `/opt/php83/bin/php`, `/opt/php84/bin/php`, and `/opt/php85/bin/php`. It does not run `dnf module reset php` and does not alter the system PHP used by ISPmanager.

`bin/install-almalinux.sh` checks candidates in this order:

1. `JURA_PHP_BIN` if set
2. `php` from `PATH`
3. `/opt/php85/bin/php`
4. `/opt/php84/bin/php`
5. `/opt/php83/bin/php`
6. `/opt/php82/bin/php`
7. `/usr/bin/php`
8. `/usr/local/bin/php`

A candidate must be executable, report `PHP_VERSION >= 8.2.0`, and load both `PDO` and `pdo_sqlite`. The `sqlite3` extension is recommended; the installer warns if it is missing but continues when `pdo_sqlite` is available.

When several suitable PHP binaries are available in an interactive shell, the installer displays a numbered list and recommends `/opt/php83/bin/php` when it is suitable. In non-interactive mode, it selects a valid `JURA_PHP_BIN` first, then `/opt/php83/bin/php`, then the highest suitable PHP binary found.

To force a specific alternative PHP binary:

```bash
sudo JURA_PHP_BIN=/opt/php83/bin/php bin/install-almalinux.sh
```

The selected binary is written to `.env` as `JURA_PHP_BIN` and is used directly in the generated systemd units, for example:

```ini
ExecStart=/opt/php83/bin/php artisan serve --host=0.0.0.0 --port=8765
ExecStart=/opt/php83/bin/php /opt/jura-server-guard/artisan guard:scan
```

## Services

```bash
systemctl status jura-server-guard.service
systemctl status jura-server-guard-scan.timer
journalctl -u jura-server-guard.service -f
journalctl -u jura-server-guard-scan.service -n 100
```

## Firewall

If the panel should be reachable remotely:

```bash
firewall-cmd --add-port=8765/tcp --permanent
firewall-cmd --reload
```

For production, prefer binding through a private interface, VPN, or reverse proxy with TLS and access restrictions.

## Manual scan

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php artisan guard:scan
/opt/php83/bin/php artisan guard:status
```
