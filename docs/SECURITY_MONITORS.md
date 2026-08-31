# Host security monitors

Jura Server Guard can also watch host-level persistence points that are commonly abused during server incidents:

- new SSH public keys in `authorized_keys`;
- new or changed user/system cron jobs;
- suspicious running processes.

These checks are intentionally separate from the web malware scanner. They run as root through systemd and send Telegram alerts when something new appears.

## Telegram alerts

Telegram is shared by the scanner, cron monitor, SSH-key monitor, and process monitor.

### 1. Create a bot

Open `@BotFather` in Telegram and run:

```text
/newbot
```

Choose a name and username. BotFather returns a token like:

```text
123456789:AAExampleTokenExampleTokenExampleToken
```

Put it into `/opt/jura-server-guard/.env`:

```env
JURA_TELEGRAM_ENABLED=true
JURA_TELEGRAM_BOT_TOKEN=123456789:AAExampleTokenExampleTokenExampleToken
```

### 2. Get the chat id

Send any message to the bot from the account or group that should receive alerts.

Open this URL in a browser, replacing `<TOKEN>` with the real token:

```text
https://api.telegram.org/bot<TOKEN>/getUpdates
```

Find `message.chat.id` in the JSON response and add it to `.env`:

```env
JURA_TELEGRAM_CHAT_ID=123456789
```

For groups, the chat id is often negative, for example:

```env
JURA_TELEGRAM_CHAT_ID=-1001234567890
```

If `getUpdates` returns an empty result, send another message to the bot and refresh the URL. If the bot is used in a group, make sure the bot was added to that group before checking `getUpdates`.

### 3. Test delivery

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php artisan guard:telegram-test --message="Jura Server Guard Telegram test"
```

## Install all host monitors

```bash
cd /opt/jura-server-guard
sudo git pull
sudo bin/install-security-monitors.sh
```

The installer creates initial baselines without Telegram noise and enables these systemd units:

```text
jura-server-guard-ssh-keys.path      watches authorized_keys changes immediately
jura-server-guard-user-cron.timer    checks cron files every minute
jura-server-guard-processes.timer    checks suspicious processes every minute
```

Check status:

```bash
systemctl status jura-server-guard-ssh-keys.path --no-pager
systemctl list-timers | grep jura-server-guard
journalctl -u jura-server-guard-user-cron.service -n 50 --no-pager
journalctl -u jura-server-guard-processes.service -n 50 --no-pager
```

## SSH key monitor

Script:

```text
bin/ssh-key-monitor.php
```

Default files:

```env
JURA_SSH_KEY_MONITOR_FILES=/root/.ssh/authorized_keys,/var/www/*/data/.ssh/authorized_keys
JURA_SSH_KEY_MONITOR_STATE=/opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
```

The first run creates a baseline and does not notify about existing keys. Later, any new fingerprint triggers a Telegram message with:

- hostname;
- file path;
- owner;
- line number;
- key type;
- SHA256 fingerprint;
- key comment;
- file mtime.

Manual check:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php bin/ssh-key-monitor.php
```

## User and system cron monitor

Script:

```text
bin/user-cron-monitor.php
```

Default files:

```env
JURA_USER_CRON_MONITOR_FILES=/var/spool/cron/*,/var/spool/cron/crontabs/*,/etc/crontab,/etc/cron.d/*,/etc/cron.hourly/*,/etc/cron.daily/*,/etc/cron.weekly/*,/etc/cron.monthly/*
JURA_USER_CRON_MONITOR_STATE=/opt/jura-server-guard/storage/user-cron-monitor/state.json
```

It alerts about:

- a new cron file;
- a changed cron file hash;
- a new non-comment cron line.

This catches both direct user crontab persistence and system cron persistence such as `/etc/cron.d/*`.

Manual check:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php bin/user-cron-monitor.php
```

Force notification for current baseline entries:

```bash
/opt/php83/bin/php bin/user-cron-monitor.php --notify-initial
```

## Suspicious process monitor

Script:

```text
bin/process-monitor.php
```

Default state:

```env
JURA_PROCESS_MONITOR_STATE=/opt/jura-server-guard/storage/process-monitor/state.json
JURA_PROCESS_MONITOR_INCLUDE_INFO=false
JURA_PROCESS_MONITOR_IGNORE_REGEX=
```

The monitor scans `/proc` and alerts when a new suspicious process signature appears. It focuses on high-signal indicators to avoid flooding Telegram.

Current detection examples:

- executable path is deleted on disk;
- executable runs from `/tmp`, `/var/tmp`, or `/dev/shm`;
- executable runs from hosting temporary directories such as `/var/www/*/data/bin-tmp/`, `/var/www/*/data/mod-tmp/`, or `/var/www/*/data/tmp/`;
- interpreter runs a script from hosting temporary directories;
- process or command line contains known malware markers such as `gs-dbus`, `defunct-kernel`, `kdevtmpfsi`, `kinsing`, `xmrig`, `pnscan`, `watchbog`;
- command downloads a remote script and pipes it to `sh`/`bash`;
- command contains encoded/eval shell execution patterns.

Manual check:

```bash
cd /opt/jura-server-guard
/opt/php83/bin/php bin/process-monitor.php
```

Dry run:

```bash
/opt/php83/bin/php bin/process-monitor.php --dry-run
```

If a legitimate local process is noisy, suppress it with a PCRE in `.env`:

```env
JURA_PROCESS_MONITOR_IGNORE_REGEX=#backup-agent|node_exporter|known-local-script#
```

## Reset baselines

Use this only after you have verified the current state is clean.

```bash
rm -f /opt/jura-server-guard/storage/ssh-key-monitor/authorized_keys_state.json
rm -f /opt/jura-server-guard/storage/user-cron-monitor/state.json
rm -f /opt/jura-server-guard/storage/process-monitor/state.json

cd /opt/jura-server-guard
/opt/php83/bin/php bin/ssh-key-monitor.php
/opt/php83/bin/php bin/user-cron-monitor.php
/opt/php83/bin/php bin/process-monitor.php
```

## Disable monitors

```bash
systemctl disable --now jura-server-guard-ssh-keys.path
systemctl disable --now jura-server-guard-user-cron.timer
systemctl disable --now jura-server-guard-processes.timer
```

The scanner and web panel continue to work independently.
