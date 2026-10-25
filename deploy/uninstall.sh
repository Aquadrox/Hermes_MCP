#!/usr/bin/env bash
# Remove the hermes-ngrok-mcp service (and the hermes-nas file manager, if installed).
# Configuration, MFA state, audit trails and the service users are kept unless --purge is given.
# The NAS folder itself and its content are NEVER deleted.
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
if [[ -f /etc/systemd/system/hermes-nas.socket || -f /etc/systemd/system/hermes-nas.service ]]; then
    systemctl disable --now hermes-nas.socket hermes-nas.service 2>/dev/null || true
    rm -f /etc/systemd/system/hermes-nas.socket /etc/systemd/system/hermes-nas.service
    echo "NAS file manager removed (the shared folder and its files are untouched)."
fi
systemctl daemon-reload
rm -rf /opt/hermes-ngrok-mcp
echo "Service and application removed."

if [[ $PURGE -eq 1 ]]; then
    rm -rf /etc/hermes-ngrok-mcp /var/lib/hermes-ngrok-mcp /etc/hermes-nas /var/lib/hermes-nas
    for user in "$SERVICE_USER" hermes-nas; do
        if id -u "$user" >/dev/null 2>&1; then
            userdel "$user"
        fi
    done
    echo "Configuration, MFA state, audit trails and the service users removed."
    echo "The NAS folder keeps its ACLs; remove them if you like with: sudo setfacl -R -b <folder>"
    echo "Remember to remove the 'ngrok' entry from ~/.hermes/config.yaml and HERMES_NGROK_MCP_TOKEN from ~/.hermes/.env."
else
    echo "Kept /etc/hermes-ngrok-mcp, /var/lib/hermes-ngrok-mcp, /etc/hermes-nas and /var/lib/hermes-nas (use --purge to delete them)."
fi
