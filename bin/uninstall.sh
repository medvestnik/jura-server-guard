#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
systemctl disable --now jura-server-guard.service 2>/dev/null || true
systemctl disable --now jura-server-guard-scan.timer 2>/dev/null || true
rm -f /etc/systemd/system/jura-server-guard.service /etc/systemd/system/jura-server-guard-scan.service /etc/systemd/system/jura-server-guard-scan.timer
systemctl daemon-reload
cat <<'EOF'
Jura Server Guard services removed. Application files remain in /opt/jura-server-guard and quarantine remains in /root/jura-server-guard/quarantine.
EOF
