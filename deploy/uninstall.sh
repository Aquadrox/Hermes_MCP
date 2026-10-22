#!/usr/bin/env bash
# Remove the hermes-ngrok-mcp service. Configuration, MFA state and the service user are kept
# unless --purge is given.
set -Eeuo pipefail

readonly APP=hermes-ngrok-mcp
readonly SERVICE_USER=hermes-ngrok
PURGE=0

case "${1:-}" in
    "") ;;
    --purge) PURGE=1 ;;
    -h | --help)
        echo "Usage: sudo $0 [--purge]"
        exit 0
        ;;
    *)
        echo "Usage: sudo $0 [--purge]" >&2
        exit 1
        ;;
esac

[[ $EUID -eq 0 ]] || {
    echo "run this script as root" >&2
    exit 1
}

if systemctl list-unit-files "$APP.service" >/dev/null 2>&1; then
    systemctl disable --now "$APP.service" 2>/dev/null || true
fi
rm -f "/etc/systemd/system/$APP.service" /usr/local/bin/hermes-ngrok-admin
systemctl daemon-reload
rm -rf /opt/hermes-ngrok-mcp
echo "Service and application removed."

if [[ $PURGE -eq 1 ]]; then
    rm -rf /etc/hermes-ngrok-mcp /var/lib/hermes-ngrok-mcp
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        userdel "$SERVICE_USER"
    fi
    echo "Configuration, MFA state and the $SERVICE_USER user removed."
    echo "Remember to remove the 'ngrok' entry from ~/.hermes/config.yaml and HERMES_NGROK_MCP_TOKEN from ~/.hermes/.env."
else
    echo "Kept /etc/hermes-ngrok-mcp and /var/lib/hermes-ngrok-mcp (use --purge to delete them)."
fi
