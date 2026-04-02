#!/usr/bin/env bash
#
# Install a cron job for MTC certificate renewal.
#
# Usage:
#   ./install_cron.sh                    # defaults: daily at 3:00 AM
#   ./install_cron.sh --hour 6           # daily at 6:00 AM
#   ./install_cron.sh --schedule "0 */12 * * *"  # every 12 hours
#   ./install_cron.sh --remove           # remove the cron entry
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RENEW_PY="${SCRIPT_DIR}/renew.py"
CONF="${SCRIPT_DIR}/renew.conf"
CRON_TAG="# mtc-renew"
HOUR=3
MINUTE=0
SCHEDULE=""
REMOVE=false

usage() {
    echo "Usage: $0 [--hour H] [--schedule 'CRON_EXPR'] [--config PATH] [--remove]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hour)     HOUR="$2"; shift 2 ;;
        --schedule) SCHEDULE="$2"; shift 2 ;;
        --config)   CONF="$2"; shift 2 ;;
        --remove)   REMOVE=true; shift ;;
        -h|--help)  usage ;;
        *)          echo "Unknown option: $1"; usage ;;
    esac
done

# Remove existing entry
remove_entry() {
    crontab -l 2>/dev/null | grep -v "${CRON_TAG}" | crontab - 2>/dev/null || true
}

if [ "$REMOVE" = true ]; then
    remove_entry
    echo "Removed MTC renewal cron job."
    exit 0
fi

if [ ! -f "$RENEW_PY" ]; then
    echo "Error: ${RENEW_PY} not found"
    exit 1
fi

# Build the cron expression
if [ -n "$SCHEDULE" ]; then
    CRON_EXPR="$SCHEDULE"
else
    CRON_EXPR="${MINUTE} ${HOUR} * * *"
fi

CRON_CMD="${CRON_EXPR} $(command -v python3) ${RENEW_PY} --config ${CONF} ${CRON_TAG}"

# Replace any existing entry, then append
remove_entry
(crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -

echo "Installed MTC renewal cron job:"
echo "  ${CRON_CMD}"
echo ""
echo "Verify with: crontab -l"
echo "Remove with: $0 --remove"
