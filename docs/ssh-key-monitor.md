# SSH authorized_keys monitor

`bin/ssh-key-monitor.php` watches one or more `authorized_keys` files and sends a Telegram alert when a new SSH public key appears.

It was added for incidents where an attacker restores a root key after cleanup. The recommended production setup is **systemd path monitoring**, not cron: the monitor runs immediately when `/root/.ssh/authorized_keys` changes.

For the full host-security setup, including user cron and suspicious process monitoring, see [`SECURITY_MONITORS.md`](SECURITY_MONITORS.md).

## Telegram setup

1. In Telegram, open `@BotFather`.
2. Run `/newbot`, choose a bot name and username.
3. Copy the bot token into `.env`:

```env
JURA_TELEGRAM_ENABLED=true
JURA_TELEGRAM_BOT_TOKEN=123456:telegram-bot-token
```

4. Send any message to the new bot from the Telegram account or group that should receive alerts.
5. Open this URL in a browser, replacing `<TOKEN>` with the bot token:

```text
https://api.telegram.org/bot<TOKEN>/getUpdates
```

6. Find `message.chat.id` in the JSON response and put it into `.env`:

```env
JURA_TELEGRAM_CHAT_ID=123456789
```

For a group chat, the ID is usually negative, for example `-1001234567890`. If `getUpdates` returns an empty result, send another message to the bot and refresh the URL.

Test Telegram delivery:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php artisan guard:telegram-test --message="Jura Server Guard Telegram test"
```

## Environment

Add or update these values in `.env`:

```env
JURA_TELEGRAM_ENABLED=true
JURA_TELEGRAM_BOT_TOKEN=123456:telegram-bot-token
JURA_TELEGRAM_CHAT_ID=123456789

JURA_SSH_KEY_MONITOR_FILES=/root/.ssh/authorized_keys,/var/www/*/data/.ssh/authorized_keys
JURA_SSH_KEY_MONITOR_STATE=/opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
```

`JURA_SSH_KEY_MONITOR_FILES` accepts a comma-separated list and glob patterns, for example:

```env
JURA_SSH_KEY_MONITOR_FILES=/root/.ssh/authorized_keys,/var/www/*/data/.ssh/authorized_keys
```

## Recommended installation with systemd

The easiest way is to install all host-security monitors:

```bash
cd /opt/jura-server-guard
sudo bash bin/install-security-monitors.sh
```

This creates an initial baseline and installs:

```text
jura-server-guard-ssh-keys.path
jura-server-guard-ssh-keys.service
```

The path unit watches `/root/.ssh/authorized_keys` and launches the monitor immediately after the file changes.

Manual systemd status check:

```bash
systemctl status jura-server-guard-ssh-keys.path --no-pager
journalctl -u jura-server-guard-ssh-keys.service -n 50 --no-pager
```

## First run

The first run creates a baseline and does not send an alert by default:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php bin/ssh-key-monitor.php
```

To send Telegram messages for all initially observed keys:

```bash
/opt/php83/bin/php bin/ssh-key-monitor.php --notify-initial
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
/opt/php83/bin/php bin/ssh-key-monitor.php --dry-run
/opt/php83/bin/php bin/ssh-key-monitor.php --files=/root/.ssh/authorized_keys
/opt/php83/bin/php bin/ssh-key-monitor.php --state=/root/jsg-authorized-keys-state.json
/opt/php83/bin/php bin/ssh-key-monitor.php --fail-on-new
```

`--fail-on-new` exits with code `2` when new keys are detected. For systemd notification runs, the default exit code `0` is usually better to avoid repeated failure noise.

## Reset baseline

Remove the state file and run the monitor again:

```bash
rm -f /opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
/opt/php83/bin/php bin/ssh-key-monitor.php
```
