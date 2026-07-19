# Security notes

Jura Server Guard is security software and should be deployed conservatively.

- Keep the web panel restricted by firewall, VPN, or localhost tunnel.
- Web quarantine/restore actions are disabled by default via `JURA_WEB_ACTIONS_ENABLED=false`.
- Prefer CLI quarantine on the server: `php artisan guard:quarantine FINDING_ID`.
- The panel does not execute shell commands for scanner actions.
- File previews are intentionally limited and escaped in HTML.
- Quarantined malware should not be downloaded or opened outside an isolated analysis environment.
- The OpenAI integration is prepared architecturally but disabled by default; avoid sending secrets or full files to any external provider.
- Review allowlist entries periodically. Allowlist prevents noisy false positives but should not hide suspicious recent changes.
- Treat `JURA_TELEGRAM_BOT_TOKEN` like any other credential in `.env`: anyone who has it can post to your alert chat as the bot. Do not commit `.env` or paste the token into issues/logs.
- Incident import (`guard:incident-import` / **Incidents → Import incident file**) writes `regex`/`combo` signature patterns straight into the scanner, which later runs them with `preg_match()` against scanned file content on every future scan. Only import incident files from sources you trust — a malicious or malformed pattern could be slow (PCRE catastrophic backtracking) or produce false positives across every site. Dry run first and review the pattern before confirming a real import from an unfamiliar source.
- `guard:cron-scan` (and the automatic post-scan check when `JURA_CRON_MONITOR_ENABLED=true`) reads other users' crontabs read-only (`crontab -l -u <user>`) and never writes to them; it requires the panel/scan process to run as root, same as the rest of the scanner.
