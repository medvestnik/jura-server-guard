# Installing Jura Server Guard on AlmaLinux 8/9

## Requirements

- AlmaLinux 8 or 9
- root shell
- PHP 8.2 or newer with `pdo_sqlite`
- Composer
- systemd

## Install

```bash
git clone https://example.com/jura-server-guard.git
cd jura-server-guard
sudo bin/install-almalinux.sh
```

The installer copies the project to `/opt/jura-server-guard`, creates `/opt/jura-server-guard/storage/database.sqlite`, runs migrations, creates a random admin password, starts the web panel on port `8765`, and enables a scan timer every 10 minutes.

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
php artisan guard:scan
php artisan guard:status
```
