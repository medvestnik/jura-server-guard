# SSH authorized_keys monitor

`bin/ssh-key-monitor.php` watches one or more `authorized_keys` files and sends a Telegram alert when a new SSH public key appears.

It was added for incidents where an attacker restores a root key after cleanup.

## Environment

Add or update these values in `.env`:

```env
JURA_TELEGRAM_ENABLED=true
JURA_TELEGRAM_BOT_TOKEN=123456:telegram-bot-token
JURA_TELEGRAM_CHAT_ID=123456789

JURA_SSH_KEY_MONITOR_FILES=/root/.ssh/authorized_keys
JURA_SSH_KEY_MONITOR_STATE=/opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
```

`JURA_SSH_KEY_MONITOR_FILES` accepts a comma-separated list and glob patterns, for example:

```env
JURA_SSH_KEY_MONITOR_FILES=/root/.ssh/authorized_keys,/var/www/*/data/.ssh/authorized_keys
```

## First run

The first run creates a baseline and does not send an alert by default:

```bash
cd /opt/jura-server-guard
php bin/ssh-key-monitor.php
```

To send Telegram messages for all initially observed keys:

```bash
php bin/ssh-key-monitor.php --notify-initial
```

## Cron every minute

Recommended root cron entry:

```cron
* * * * * cd /opt/jura-server-guard && /usr/bin/php bin/ssh-key-monitor.php >> /var/log/jura-server-guard-ssh-keys.log 2>&1
```

## Manual test

After the baseline exists, add a temporary test key to a monitored file, run the monitor, and then remove it. The notification text includes:

- hostname;
- monitored file path;
- file owner;
- line number;
- key type;
- SHA256 fingerprint;
- key comment;
- monitored file mtime.

## Useful options

```bash
php bin/ssh-key-monitor.php --dry-run
php bin/ssh-key-monitor.php --files=/root/.ssh/authorized_keys
php bin/ssh-key-monitor.php --state=/root/jsg-authorized-keys-state.json
php bin/ssh-key-monitor.php --fail-on-new
```

`--fail-on-new` exits with code `2` when new keys are detected. For cron notifications, the default exit code `0` is usually better to avoid extra cron email noise.

## Reset baseline

Remove the state file and run the monitor again:

```bash
rm -f /opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
php bin/ssh-key-monitor.php
```
