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
