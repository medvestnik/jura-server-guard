# Jura Server Guard
Open-source server security monitoring panel for hosting servers and PHP websites.

Documentation: https://medvestnik.github.io/jura-server-guard/

Local documentation site: `/docs/index.html`

GitHub Pages source must be set to `GitHub Actions` in repository settings.

## Documentation deployment

The static documentation website is located in `/docs`.
It is automatically deployed to GitHub Pages after every push to `main` through `.github/workflows/deploy-docs.yml`.

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

To update an existing installation to a new release, see [`docs/UPDATING.md`](docs/UPDATING.md).

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
- Threat IPs
- Incidents
- Trusted IPs
- Rules and allowlist
- Settings

## Web panel language

The panel UI is available in Russian, Ukrainian, and English. Default language is controlled by `JURA_DEFAULT_LOCALE` in `.env` (`ru`, `uk`, or `en`; defaults to `ru`). Each browser can switch language independently with the RU/UK/EN links in the top navigation bar; the choice is stored in a `jura_lang` cookie. Translation strings live in `resources/lang/ru.php` and `resources/lang/uk.php`; English is the built-in fallback and needs no translation file.

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
php artisan guard:find-hash SHA256
php artisan guard:incident-import incident.json [--dry-run]
php artisan guard:incident-list
php artisan guard:trust-ip IP [--label=TEXT] [--notes=TEXT]
php artisan guard:untrust-ip IP
php artisan guard:trusted-ips
php artisan guard:cron-scan
php artisan guard:telegram-test [--message=TEXT]
php artisan guard:ip-list
php artisan guard:ip-add IP [--classification=...] [--risk=...] [--notes=...]
php artisan guard:ip-remove IP
```

Scanner and log commands use a global lock at `storage/locks/scan.lock` so timer and manual scans cannot overlap. If a scan is already running, the second command exits with the lock start time and PID. `--force` removes a stale lock; `--no-lock` is only for debugging.

By default scan-user scans active/normal sites only and excludes old/dubl/backup/storage/cache/temp/vendor/node_modules paths. Use `--include-old`, `--include-storage`, or `--include-backups` for explicit expanded scope.

## Scanner rules

Rules live in `rules/default-rules.php` and are seeded into SQLite. The scanner reads only the first configured bytes of PHP files (`JURA_MAX_FILE_READ_BYTES`, default `262144`) and combines file path, filename, string indicators, and suspicious PHP function combinations.

A single `base64_decode(` match is not treated as critical by itself. It becomes more important when combined with other suspicious functions, risky paths, or known malware indicators.

## Scan performance and order

`node_modules/`, `storage/logs/`, and old/duplicate/backup copies (`OLD/`, `DUBL/`,
`*backup*`, `__MACOSX`) are excluded from scans unconditionally — pure noise with no
detection value (build-time JS tooling, plain-text logs, stale duplicates). `vendor/` is
excluded by default too, but through its own toggle rather than unconditionally: it's live
PHP code the webserver *can* execute, so a thorough/incident-response scan may want to
include it — pass `--include-vendor` (or set `JURA_SCAN_VENDOR_BY_DEFAULT=true` to make it
the default) to scan it anyway, e.g. after a confirmed compromise, to check whether an
attacker hid a file inside a package directory to blend in with legitimate code. On a typical
Laravel/Composer site `vendor/` alone is often tens of thousands of files, so skipping it by
default is usually the single biggest scan speed-up available.

`tmp/`, `temp/`, `cache/`, `uploads/`, `images/`, `media/`, and similarly-named directories
are **not** excluded — these are exactly where an attacker's upload usually lands, since
they're typically the writable, less-watched parts of a site. Instead, they're scanned
**first**: a site's root-level files are checked, then every directory whose name matches one
of these patterns (recursively), and only after that does the scanner move on to a CMS's own
library/admin/module/plugin code — code that's both much larger in file count and much less
commonly the thing an attacker actually modifies. A fresh shell dropped in an upload directory
surfaces within the first few seconds of a scan instead of after the scanner has worked
through the rest of the site.

**Is the first scan always slow, and do repeat scans just check hashes?** Yes to both. A
site's very first scan has to walk and hash everything not excluded, since there is no prior
baseline to diff against — but with the exclusions above, "everything" no longer includes
your dependencies. Every scan after that is `differential` by default (no flag needed): a
file is only re-hashed and re-analyzed if its size, mtime, permissions, or owner changed since
last time; unchanged files reuse their previously recorded hash. For an even lighter repeat
check (e.g. a very frequent timer), `--changed-only` skips media files entirely and does the
minimum analysis needed. `--full-rescan` forces every file to be re-hashed regardless of
metadata (useful occasionally to catch a change that fakes its mtime, but not something you'd
want on every run).

**Running the first (slow) scan in the background:** starting a scan from the web panel
already runs it as a detached background process — closing the browser tab does not stop it,
and the scan-in-progress banner reflects its live status. From the CLI over SSH, a synchronous
`php artisan guard:scan-user <user>` blocks your terminal for as long as the scan takes; run it
detached instead:

```bash
nohup php artisan guard:scan-user <user> --profile=fast > /root/first-scan.log 2>&1 &
disown
# check on it without blocking:
php artisan guard:scan-active
tail -f /root/first-scan.log
```

For ongoing scans you don't need cron at all: the installer's systemd timer
(`jura-server-guard-scan.timer`, see below) already runs `guard:scan` automatically in the
background every `JURA_SCAN_INTERVAL_MINUTES` (default 30). Cron is only useful here if you
want a first baseline scan to kick off once at a specific unattended time (e.g. overnight)
before the recurring timer takes over:

```bash
# crontab -e
0 3 * * * /opt/php83/bin/php /opt/jura-server-guard/artisan guard:scan-user someuser --profile=fast >> /var/log/jura-first-scan.log 2>&1
```

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

### Bulk quarantine and delete from the Findings page

When `JURA_WEB_ACTIONS_ENABLED=true`, the **Findings** page shows a checkbox per row plus
"Quarantine selected" and "Delete selected" buttons, so a mass-infection incident (dozens or
hundreds of matched webshells from one signature) can be cleaned up in one action instead of
one file at a time. If more findings match the current filter than are shown on the page (the
list is capped at 500 rows), a **Select all N matching current filter** checkbox applies the
action to every matching finding server-side, not just the visible ones.

**Quarantine** moves the file into the quarantine directory as before (reversible via
**Restore**). **Delete** is new and permanent: the file is captured into `quarantine_items`
(SHA-256, owner, permissions, path, reason) for the audit trail exactly like quarantine, then
immediately removed from disk with no way to restore it — the finding and quarantine item are
both marked `deleted`. Both actions require an explicit confirmation dialog showing how many
files will be affected, and both are always disabled unless `JURA_WEB_ACTIONS_ENABLED=true`
(same gate as the existing single-file quarantine action).

The **User** filter field on the Findings page also autocompletes from every known account
name as you type, so you don't need to remember or retype the exact ISPmanager username.

## Turning a finding into a signature, and cross-site search

On a finding page, **Create signature from this finding** now pre-fills a ready-to-save
`hash` signature (`{"sha256":["..."]}`) from the finding's SHA-256 — saving it immediately
makes future scans flag byte-identical copies of that exact file anywhere on the server,
under any filename. The source file's safe preview is shown alongside the form so you can
also write a broader `combo` pattern (distinctive strings/regexes) to catch renamed or
lightly modified variants, not just exact copies.

Every finding page also shows a **Same file elsewhere** section: an immediate lookup
against already-scanned `file_snapshots` by SHA-256, so you can tell right away whether a
webshell you just found also exists on another site — without waiting for the next scan.
The same lookup is available from the CLI:

```bash
php artisan guard:find-hash <sha256>
```

`guard:find-hash`/**Same file elsewhere** only look at what a *previous* scan already
recorded, though — they can't tell you about a copy sitting somewhere that hasn't been
scanned since it was dropped. For "we just found a shell, check the whole server for this
exact one right now," a signature page has a **Sweep whole server for this signature now**
button (`php artisan guard:signature-sweep <signature_id>` from the CLI). It reads every
already-inventoried site's files live and checks them against that one signature only —
skipping every other signature, all the heuristic rules, and log correlation — so it's much
faster than waiting for or triggering a full re-scan. This is also how you catch a copy an
attacker deliberately hid somewhere a heuristic scan wouldn't flag it (e.g. renamed to blend
into a CMS's own library folder instead of an obviously-writable upload directory) — the
sweep only cares whether the file matches the signature, not where it's sitting.

### Exporting findings for analysis (including by another AI)

The Findings page's **Export JSON (for AI analysis)** link (next to **Export CSV**, same
active filters) downloads the currently filtered findings as a single structured JSON file —
path, risk, title/description, matched signature and rule details, and a lightweight incident
context — ready to paste into an AI chat (this panel's own, or an external one) or attach to
a support ticket for a second opinion, without having to manually copy details out of the UI
finding by finding.

### Auto-created signatures from critical findings

Every time a scan records a new **critical**-risk finding that wasn't already matched by an
existing signature, the panel automatically writes a `hash` signature for that file's
SHA-256 into `malware_signatures` (named `Auto: <filename>`, `source = auto_finding`,
linked back to the finding via `source_finding_id`). Future scans then flag byte-identical
copies of that file anywhere on the server immediately, without waiting for anyone to
manually turn the finding into a signature. Creation is deduplicated by SHA-256 (repeated
scans of the same file never create duplicate signatures) and can be disabled with
`JURA_AUTO_SIGNATURE_ON_CRITICAL_FINDINGS=false` in `.env`.

### Analyzing an uploaded file or pasted content

The **Signatures → Analyze file** page (`/signatures/analyze`) lets you check a suspicious
file against every enabled signature without waiting for the next scan: upload a file
(up to 5 MB) or paste its content directly, and the panel computes its SHA-256, reports any
matching signatures (with a link to each), and shows whether the same SHA-256 has already
been seen anywhere on the server via `file_snapshots`. If nothing matches, a
**Create signature from this file** button pre-fills a `hash` signature the same way the
finding page does.

## Global search

The **Search** box in the top navigation (`/search`) looks a query up across the whole
panel at once: scanned files, findings, quarantine items, suspicious log lines, signatures,
incidents, and incident file IOCs. The query is interpreted automatically:

- a 64-character hex string is treated as an exact SHA-256 and matched against file
  hashes, findings, quarantine items, signature patterns, and incident file IOCs;
- an IPv4 address is matched against the threat IP database, trusted IP list, and
  suspicious log entries;
- anything else is matched as a substring against file paths, finding titles, signature
  names/descriptions/patterns, and incident titles/summaries.

This answers questions like "where else has `filefuns.php` shown up" or "is this hash
already known as a signature" in one search instead of checking each section by hand.

## Threat IPs

The **Threat IPs** panel page stores attacker IP addresses with a classification (`scanner`,
`bruteforce`, `webshell_access`, `bot`, `direct_login`, `manual`, `unknown`), a risk level,
and optional free-text notes. **Flag IP** links from Suspicious logs also pass the exact log
event, so the site, requested URI/file, log path, and detection date are shown before saving
and recorded automatically in `threat_ip_evidence`. If the IP is already present, the page
says so explicitly and updates the existing record instead of creating a duplicate.

Optional firewalld blocking from the local panel is disabled by default and is separate from
ordinary web quarantine actions:

```env
JURA_FIREWALL_ACTIONS_ENABLED=true
JURA_FIREWALL_CMD=/usr/bin/firewall-cmd
JURA_FIREWALL_BLOCK_ZONE=drop
```

The **Block** action adds the public IP as a source to the configured firewalld drop zone in
both runtime and permanent configurations. It reports an already-existing rule without
duplicating it. Trusted IPs and private, loopback, link-local, or reserved ranges are refused
to reduce the chance of locking out legitimate management access. The installed panel runs
as root; if a custom deployment runs it as another user, that process must be granted only
the narrowly required firewalld permission.

CLI equivalents:

```bash
php artisan guard:ip-list
php artisan guard:ip-add 1.2.3.4 --classification=webshell_access --risk=critical --notes="..."
php artisan guard:ip-remove 1.2.3.4
```

### Abuse report drafts

Each Threat IP has an **Abuse report** action (`/threat-ips/abuse-report?ip=...`) that looks
up the IP's network registration via RDAP (the modern successor to WHOIS, queried over plain
HTTPS — no port-43 access needed) and drafts a report: who the network belongs to, the
IP's classification/notes from Threat IPs, and up to the 20 most recent log lines from that
IP as supporting evidence. If RDAP publishes an abuse contact email, it's pre-filled in the
draft's To: field; if not (or if the lookup fails), the draft still generates with a clear
note that you'll need to find the contact yourself — nothing is silently skipped.

**Nothing is ever sent automatically.** The draft is shown for you to review, edit, and copy
into your own mail client — this deliberately avoids needing outbound SMTP credentials
configured on the server and avoids any risk of an automated system sending mail on your
behalf without a human reading it first.

## Trusted IPs and Telegram alerts

**Trusted IPs** (`/trusted-ips`) is a short allow-list of IP addresses known to be safe
(admins, deploy tools, trusted maintainers) — separate from **Threat IPs**, which tracks
attackers. It exists to cut alert noise: a new file appearing in a site's web root whose
source IP (resolved from the closest matching access-log line) is in this list does not
trigger a notification.

**Telegram alerts** are configured entirely through `.env` (not the Settings page, which
only writes to the DB `settings` table for the MVP and is not authoritative — see below):

```env
JURA_TELEGRAM_ENABLED=true
JURA_TELEGRAM_BOT_TOKEN=123456:AA...        # from @BotFather
JURA_TELEGRAM_CHAT_ID=123456789             # message your bot, then check https://api.telegram.org/bot<token>/getUpdates
JURA_NOTIFY_NEW_CRITICAL_HIGH_FINDINGS=true
JURA_NOTIFY_UNTRUSTED_WEBROOT_FILES=true
JURA_NOTIFY_CRON_CHANGES=true
JURA_CRON_MONITOR_ENABLED=true
```

After every non-dry-run scan, Jura checks for and sends one Telegram message per:

* a **new** `critical`/`high` finding (a signature match, a webshell indicator, etc.) —
  this already covers "a file matching a known signature";
* a **new file created at a site's web root** (top-level, not inside a subdirectory) whose
  most recent matching access-log IP is not in Trusted IPs;
* a **new crontab entry** for any inventoried server user, checked every scan when
  `JURA_CRON_MONITOR_ENABLED=true` (read-only `crontab -l -u <user>`; nothing is ever
  written to any user's crontab).

Each attempt (sent or failed, e.g. a wrong bot token) is logged in `notifications_log` and
never repeated for the same finding/file/cron line. Test your configuration with:

```bash
php artisan guard:telegram-test --message="hello from Jura"
php artisan guard:trust-ip 1.2.3.4 --label="office VPN"
php artisan guard:trusted-ips
php artisan guard:cron-scan
```

Note on timing: Jura detects changes on its normal scan cadence (every 30 minutes by
default via the systemd timer), not via real-time filesystem watching — "immediately" in
practice means "on the next scan." Lower `JURA_SCAN_INTERVAL_MINUTES` (and the systemd timer
interval) if you need tighter detection latency.

## AI provider and AI-assisted signatures

Jura can call an AI provider — OpenAI or Anthropic (Claude) — for two things: generating a
signature suggestion from a finding, and (a real request is only made when this is what you
asked for, never silently) auto-quarantining obvious shells. Configure the provider in
`.env`:

```env
JURA_AI_PROVIDER=openai            # or anthropic
JURA_AI_MODEL=gpt-4o-mini          # or e.g. claude-sonnet-4-5 for Anthropic
JURA_OPENAI_ENABLED=true
JURA_OPENAI_API_KEY=sk-...
# For Anthropic instead:
JURA_ANTHROPIC_ENABLED=true
JURA_ANTHROPIC_API_KEY=sk-ant-...
JURA_AI_SIGNATURES_ENABLED=true    # turn on real AI calls for signature suggestions
```

**Generate signature with AI** (on a finding page) sends the finding's metadata and a
truncated (max 8 KB) read of the file to the configured provider and asks it to propose a
`hash` or `combo` signature. The result is stored as a **suggestion**
(`/signatures/suggestions`, also shown inline on the finding page) — nothing is ever written
to the real `malware_signatures` table automatically. Review the suggestion and click
**Create signature** to save it as a real, enabled signature through the normal manual-save
form. If `JURA_AI_SIGNATURES_ENABLED` is off, no provider is configured, or the AI request
fails, a draft placeholder is created instead so the action never silently does nothing or
errors out; a malformed (non-JSON) AI response is kept as a `needs_review` suggestion with
the raw text preserved rather than being discarded.

### Automatic quarantine of obvious shells

```env
JURA_AUTO_QUARANTINE_OBVIOUS_SHELLS=true   # default: false
```

When enabled, right after each scan Jura automatically quarantines a **new, critical-risk**
finding if either:

* it **matched a known signature** (built-in or custom, in `malware_signatures`) — a positive
  identification, not just a heuristic score; or
* the file's upload could be traced to a **specific IP address via recent access logs, and
  that IP is not in Trusted IPs** — i.e. it was very likely dropped by an attacker, not
  deployed by an admin.

A critical finding that matches neither condition (no signature, and either no IP could be
correlated from the logs, or the IP is trusted) is left as `new` for manual review — this is
deliberately conservative because heuristic-only detections without a positive signal can be
false positives. Quarantine (not permanent deletion) is used, so an auto-quarantined file can
always be restored from `/quarantine` if it turns out to be a false positive. Every
auto-quarantine action is also sent as a Telegram alert (independent of the other notification
toggles above) if Telegram is configured, and the reason (matched signature name, or the
untrusted IP) is recorded in the quarantine item for the audit trail.

### AI chat

```env
JURA_AI_CHAT_ENABLED=true   # default: false
```

Adds an **AI chat** link to the nav bar. The assistant can search findings, look up one
finding's details, and — only ever with an explicit confirmation step, never immediately —
quarantine a finding, permanently delete a finding, or add an IP to the trusted list. When it
proposes one of those three actions, the conversation shows a **Confirm** / **Cancel** card
with the exact action and arguments; nothing runs until you click Confirm, and Cancel leaves
the finding/IP untouched. Read-only lookups (search, inspect) run immediately without a
confirmation step since they can't change anything. Conversation history is kept per admin
account and can be cleared from the chat page at any time.

## Incident import

Canonical incident-file authoring contract: [`docs/INCIDENT_IMPORT_FORMAT.md`](docs/INCIDENT_IMPORT_FORMAT.md).  
Copyable v1 example: [`docs/examples/incident-v1.example.json`](docs/examples/incident-v1.example.json).

> When creating incident JSON manually or with an AI assistant, use the canonical documentation and example above rather than inferring the format only from the runtime validator.

The **Incidents** panel page imports incident reports in the `jura-server-guard-incident`
JSON format (see `format_version: "1.x"`): incident metadata, attacker `threat_ips`
(classification/risk/confidence/notes), ready-to-use `malware_signatures` (`hash`, `combo`,
`regex`, `substring`, `structural` pattern types — the same engine the scanner already
uses), `file_iocs` (SHA-256 indicators with names/role/risk), `excluded_ips` (infrastructure
that should **not** be flagged, kept for reference only), `path_indicators`, affected
site/user assets, and response-action notes.

Import is available both from the panel (**Incidents → Import incident file**, file
upload, dry run checked by default) and from the CLI:

```bash
php artisan guard:incident-import incident.json --dry-run
php artisan guard:incident-import incident.json
php artisan guard:incident-list
```

Threat IPs are upserted by `ip`, signatures by `slug`, file IOCs by `sha256` when known —
importing the same file again updates existing records instead of duplicating them. Each
incident's detail page shows its threat IPs, signatures, and file IOCs, cross-references each
file IOC against already-scanned `file_snapshots` by SHA-256 (so you immediately see whether
a known-bad file is present anywhere on the server), and resolves the incident's affected
site names against the current inventory with a link to that site's findings.

A `file_ioc` doesn't strictly need a `sha256` — it's common to write up an incident before a
file's hash has actually been collected (e.g. investigation notes captured its filename,
size, and role, but the sample wasn't hashed yet). In that case, set `"sha256": null` and
provide `name` (or `names`) instead; the entry is upserted by name+size+role until a later
import fills in the real hash. Only when a `sha256` value **is** present must it be a valid
64-character hex string.

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
- Firewall actions are independently disabled by default: `JURA_FIREWALL_ACTIONS_ENABLED=false`.
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

### MySQL long path indexes

MySQL/MariaDB installs use `utf8mb4` and store long filesystem paths in full for display and exact value storage, but migrations do not index long path columns directly. Instead, `file_snapshots`, `findings`, `quarantine_items`, and suspicious log URI lookups use deterministic SHA-256 hex hash columns such as `path_hash`, `finding_hash`, `original_path_hash`, and `uri_hash`. Optional prefix indexes use only the first 191 characters and are never used for uniqueness. To verify a MySQL/MariaDB host, run `bin/acceptance-mysql-migrate.sh`; it creates a temporary utf8mb4 database, runs `php artisan migrate --force`, then runs `php artisan guard:db-stats`.

## CSV export and false-positive controls

Findings and Suspicious logs pages include CSV export buttons that preserve current filters. Findings are deduplicated by path/type/rule fingerprint, ignored findings are not recreated unless the file hash changes, and known Joomla/Akeeba/Freemius/Jetpack/SuiteCRM/Regular Labs/OpenCart paths are allowlisted so normal CMS/plugin files are not high/critical by filename alone. High/critical risk is reserved for known IOC strings, webshell callbacks, ALFA_DATA/alfacgiapi, malware-like filenames, risky upload/cache PHP with execution indicators, and suspicious HTTP events linked to the exact file.

## Production incident-response improvements

### Scan performance

Rules, allowlist entries, and malware signatures are loaded from the database once per scan run and cached in memory for the rest of that run, instead of being re-queried for every file. Repeated lookups of files with existing active findings are batched into a single query per scan instead of one query per file. On a 4,000-file site this cut a from-scratch scan from ~9s to ~2s and a routine "nothing changed" timer scan from ~7s to ~1.2s in local testing. Detection logic itself is unchanged by these optimizations.

### Dashboard log details

The dashboard `Recent suspicious log events` table now separates `Date/Time`, `IP`, `Method`, `URI`, and `Raw / Actions`. Long URIs and raw log lines are shortened in the table to preserve layout, but each event can be expanded with **Details** and copied from the browser. Nginx error-log style lines such as `client: 172.70.142.128` and `request: POST ...` are parsed so the IP column contains the real client IP instead of a date fragment.

### Scan profiles

Jura Server Guard supports three scan profiles:

* `fast` — default for dashboard/timer scans. Prioritizes PHP-like files, web config files, root critical files, `.well-known`, fake `well-known`, `pki-validation`, `acme-challenge`, uploads PHP, plugins, themes, and recently relevant high-risk locations. Ordinary media and generated WordPress thumbnails are skipped and not broadly hashed.
* `standard` — balanced manual investigation. Adds JS/HTML, suspicious uploads, executable files, extension/content mismatches, PHP markers in non-PHP files, and suspicious recently modified media while still avoiding normal media churn.
* `deep` — manual full audit. Includes all files including media, archives, and binary/polyglot candidates. Do not use this as the default timer profile on large production sites.

Environment defaults:

```env
JURA_SCAN_PROFILE=fast
JURA_TIMER_SCAN_PROFILE=fast
```

CLI examples:

```bash
php artisan guard:scan --profile=fast
php artisan guard:scan-user zao --profile=fast
php artisan guard:scan-site /var/www/zao/data/www/example.com --profile=fast
php artisan guard:scan-site /var/www/zao/data/www/example.com --profile=standard
php artisan guard:scan-site /var/www/zao/data/www/example.com --profile=deep
```

The dashboard, sites page, and users page provide scan controls with `fast`, `standard`, and `deep` profile selection. Scan history displays profile, scope, status, scanned files, skipped media, skipped directories, findings, and elapsed time.

### Stronger malware rules

Fast and standard scans now flag PHP-like files and suspicious `.htaccess`/handler config under validation paths:

* `/.well-known/`
* `/well-known/` (fake directory without leading dot)
* `/pki-validation/`
* `/acme-challenge/`

The scanner also detects self-reading packed loaders that combine `eval`, `gzuncompress`/`gzinflate`, `file_get_contents(__FILE__)`-style obfuscation, negative `substr()` offsets, or appended compressed/binary payloads.

### ISPmanager and custom backup browser

Backup settings are available under **Settings → Backups**:

```env
JURA_BACKUP_INTEGRATION_ENABLED=true
JURA_BACKUP_PROVIDER=ispmanager
JURA_ISPMANAGER_DETECTED=true
JURA_BACKUP_ROOT=/var/backup
JURA_BACKUP_BROWSER_ENABLED=true
JURA_BACKUP_RESTORE_ENABLED=false
JURA_RESTORE_CURRENT_FILE_TO_QUARANTINE=true
```

Providers:

* `ISPmanager` — defaults to `/var/backup`, detects `/usr/local/mgr5` and executable ISPmanager-related tools when present.
* `Custom backup folder` — uses the configured backup root path for manual backup trees.
* `Disabled` — hides operational use until enabled.

Web restore is disabled by default. When restore is disabled, the backup page shows the exact CLI command instead of replacing files from the web UI.

Backup CLI examples:

```bash
php artisan guard:backup-detect
php artisan guard:backups:list-users
php artisan guard:backups:list --user=zao
php artisan guard:backups:find-file --path=/var/www/zao/data/www/zaodessu.com.ua/index.php
php artisan guard:backups:preview --path=/var/www/zao/data/www/zaodessu.com.ua/index.php --date=2026-05-30
php artisan guard:backups:diff --path=/var/www/zao/data/www/zaodessu.com.ua/index.php --date=2026-05-30
php artisan guard:backups:restore-file --path=/var/www/zao/data/www/zaodessu.com.ua/index.php --date=2026-05-30
```

Restore safety rules in the first version are intentionally conservative: only a selected file can be restored; paths must stay under `/var/www/{user}/data/www/...`; `..` paths and unsafe symlink targets are rejected; current files are copied to Jura quarantine before replacement; restored permissions are set to `0644`; ownership is restored to the ISPmanager user where possible; and every restore is logged in `restore_actions`.

Differential, incremental, and multipart backups are surfaced from `.info` metadata and directory/archive naming where available. Native ISPmanager tooling should be preferred for large archives and complete differential-chain resolution; the fallback browser performs safe selective browsing and avoids whole-site extraction.
