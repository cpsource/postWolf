#!/bin/bash
# Wrapper for age-backups.py with the standard postWolf retention:
#   3 daily, 2 weekly, 1 monthly.
# Extra args pass through (--dry-run, --local, --remote, --todays-date, etc).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

python3 "$SCRIPT_DIR/age-backups.py" \
    --keep-daily-backups 3 \
    --keep-weekly-backups 2 \
    --keep-monthly-backups 1 \
    --list \
    "$@"
