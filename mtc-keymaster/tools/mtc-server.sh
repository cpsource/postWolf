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
        REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
        echo "Stopping $SERVICE..."
        sudo systemctl stop "$SERVICE"
        echo "Rebuilding from $REPO_ROOT (Makefile.tools → server2/c + tools/c)..."
        make -C "$REPO_ROOT" -f Makefile.tools clean || exit 1
        make -C "$REPO_ROOT" -f Makefile.tools       || exit 1
        echo "Installing to /usr/local/bin..."
        sudo make -C "$REPO_ROOT" -f Makefile.tools install || {
            echo "Install failed. Server not started."
            exit 1
        }
        echo "Starting $SERVICE..."
        sudo systemctl start "$SERVICE"
        sleep 1
        sudo systemctl status "$SERVICE" --no-pager
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|rebuild}"
        exit 1
        ;;
esac
