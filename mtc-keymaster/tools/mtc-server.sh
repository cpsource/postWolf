#!/bin/bash
#
# mtc-server.sh — Start, stop, restart, and check status of the MTC CA server.
#
# Usage:
#   bash mtc-keymaster/tools/mtc-server.sh start
#   bash mtc-keymaster/tools/mtc-server.sh stop
#   bash mtc-keymaster/tools/mtc-server.sh restart
#   bash mtc-keymaster/tools/mtc-server.sh status
#   bash mtc-keymaster/tools/mtc-server.sh logs
#   bash mtc-keymaster/tools/mtc-server.sh rebuild

SERVICE=mtc-ca

case "$1" in
    start)
        sudo systemctl start "$SERVICE"
        sleep 1
        sudo systemctl status "$SERVICE" --no-pager
        ;;
    stop)
        sudo systemctl stop "$SERVICE"
        echo "Stopped $SERVICE"
        ;;
    restart)
        sudo systemctl restart "$SERVICE"
        sleep 1
        sudo systemctl status "$SERVICE" --no-pager
        ;;
    status)
        sudo systemctl status "$SERVICE" --no-pager
        ;;
    logs)
        journalctl -u "$SERVICE" -f
        ;;
    rebuild)
        echo "Stopping $SERVICE..."
        sudo systemctl stop "$SERVICE"
        echo "Rebuilding..."
        make -C "$(dirname "$0")/../server/c" clean
        make -C "$(dirname "$0")/../server/c"
        if [ $? -eq 0 ]; then
            echo "Starting $SERVICE..."
            sudo systemctl start "$SERVICE"
            sleep 1
            sudo systemctl status "$SERVICE" --no-pager
        else
            echo "Build failed. Server not started."
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|rebuild}"
        exit 1
        ;;
esac
