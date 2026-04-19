#!/bin/sh
# setup-recert-crond.sh — install/remove the daily MTC cert-renewal cron job.
#
# The job runs /usr/local/bin/check-renewal-cert at 00:00 every day as user
# `ubuntu`, dropped into /etc/cron.d/ so removal is trivial and state is
# visible to config-management.
#
# Legacy renew.py cron entries (left by the old install_cron.sh in
# mtc-keymaster/renew-tool/) are removed on --start.

set -eu

CRON_FILE="/etc/cron.d/mtc-recert"
RUN_USER="${RUN_USER:-ubuntu}"
BIN="${BIN:-/usr/local/bin/check-renewal-cert}"

# Legacy markers from the previous renew.py-based auto-renew.
LEGACY_TAG="# MTC auto-renewal"
LEGACY_CMD="renew.py"

usage() {
    cat >&2 <<EOF
Usage: $0 --start | --stop | --status

  --start    Install /etc/cron.d/mtc-recert (00:00 daily as $RUN_USER)
             and clean up legacy renew.py user-crontab entries.
  --stop     Remove /etc/cron.d/mtc-recert.
  --status   Show whether the cron job is installed and its content.

Env overrides:
  RUN_USER=$RUN_USER
  BIN=$BIN
EOF
    exit 2
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: must run as root (use sudo)" >&2
        exit 1
    fi
}

reload_cron() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload cron 2>/dev/null \
            || systemctl reload crond 2>/dev/null \
            || :
    elif command -v service >/dev/null 2>&1; then
        service cron reload 2>/dev/null \
            || service crond reload 2>/dev/null \
            || :
    fi
}

remove_legacy_user_crontab() {
    # Best-effort cleanup: if the target user has a personal crontab with
    # the legacy renew.py entry, strip it. No-op otherwise.
    if ! id "$RUN_USER" >/dev/null 2>&1; then
        return 0
    fi
    existing="$(crontab -u "$RUN_USER" -l 2>/dev/null || true)"
    if [ -z "$existing" ]; then
        return 0
    fi
    if echo "$existing" | grep -Fq "$LEGACY_TAG" \
       || echo "$existing" | grep -Fq "$LEGACY_CMD"; then
        echo "$existing" \
            | grep -Fv "$LEGACY_TAG" \
            | grep -Fv "$LEGACY_CMD" \
            | crontab -u "$RUN_USER" -
        echo "removed legacy $RUN_USER crontab entry ($LEGACY_CMD)"
    fi
}

start() {
    require_root

    if [ ! -x "$BIN" ]; then
        echo "Warning: $BIN not installed yet; cron will fail until then" >&2
    fi

    remove_legacy_user_crontab

    cat > "$CRON_FILE" <<EOF
# /etc/cron.d/mtc-recert — MTC certificate auto-renewal
# Installed by setup-recert-crond.sh.  Remove with --stop.
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=$RUN_USER
0 0 * * * $RUN_USER $BIN 2>&1
EOF
    chmod 644 "$CRON_FILE"
    reload_cron
    echo "installed $CRON_FILE (runs 00:00 daily as $RUN_USER)"
}

stop() {
    require_root
    if [ -f "$CRON_FILE" ]; then
        rm -f "$CRON_FILE"
        reload_cron
        echo "removed $CRON_FILE"
    else
        echo "$CRON_FILE not installed"
    fi
}

status() {
    if [ -f "$CRON_FILE" ]; then
        echo "installed: $CRON_FILE"
        echo "---"
        cat "$CRON_FILE"
    else
        echo "not installed"
    fi
}

case "${1:-}" in
    --start)  start ;;
    --stop)   stop ;;
    --status) status ;;
    *)        usage ;;
esac
