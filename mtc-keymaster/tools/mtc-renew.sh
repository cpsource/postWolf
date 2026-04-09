#!/bin/bash
#
# mtc-renew.sh — Manage the MTC certificate renewal service.
#
# Usage:
#   bash mtc-keymaster/tools/mtc-renew.sh install   # install systemd timer
#   bash mtc-keymaster/tools/mtc-renew.sh start      # enable and start timer
#   bash mtc-keymaster/tools/mtc-renew.sh stop        # stop and disable timer
#   bash mtc-keymaster/tools/mtc-renew.sh status      # show timer/service status
#   bash mtc-keymaster/tools/mtc-renew.sh run         # run renewal now (one-shot)
#   bash mtc-keymaster/tools/mtc-renew.sh dry-run     # preview what would renew
#   bash mtc-keymaster/tools/mtc-renew.sh logs        # follow journal

RENEW_TOOL="$(cd "$(dirname "$0")/../renew-tool" && pwd)/renew.py"
SERVICE=mtc-renew
SERVICE_FILE=/etc/systemd/system/${SERVICE}.service
TIMER_FILE=/etc/systemd/system/${SERVICE}.timer

install_service() {
    echo "Installing ${SERVICE}.service and ${SERVICE}.timer ..."

    sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=MTC Certificate Renewal
After=network.target

[Service]
Type=oneshot
User=$(whoami)
ExecStart=/usr/bin/python3 ${RENEW_TOOL} --neon
Environment=HOME=${HOME}
WorkingDirectory=$(dirname "$RENEW_TOOL")
EOF

    sudo tee "$TIMER_FILE" > /dev/null << EOF
[Unit]
Description=Run MTC renewal daily

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    echo "Installed. Use '$0 start' to enable."
}

case "$1" in
    install)
        install_service
        ;;
    start)
        if [ ! -f "$TIMER_FILE" ]; then
            install_service
        fi
        sudo systemctl enable "$SERVICE.timer"
        sudo systemctl start "$SERVICE.timer"
        echo "Timer started (hourly)"
        sudo systemctl list-timers "$SERVICE.timer" --no-pager
        ;;
    stop)
        sudo systemctl stop "$SERVICE.timer"
        sudo systemctl disable "$SERVICE.timer"
        echo "Timer stopped and disabled"
        ;;
    status)
        echo "=== Timer ==="
        sudo systemctl list-timers "$SERVICE.timer" --no-pager 2>/dev/null || echo "Timer not installed"
        echo ""
        echo "=== Last run ==="
        sudo systemctl status "$SERVICE.service" --no-pager 2>/dev/null || echo "Service not installed"
        ;;
    run)
        echo "Running renewal now..."
        python3 "$RENEW_TOOL" --neon
        ;;
    dry-run)
        python3 "$RENEW_TOOL" --dry-run
        ;;
    logs)
        journalctl -u "$SERVICE" -f
        ;;
    *)
        echo "Usage: $0 {install|start|stop|status|run|dry-run|logs}"
        exit 1
        ;;
esac
