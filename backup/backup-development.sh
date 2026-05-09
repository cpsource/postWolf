#!/bin/bash
#
# Single-shot pg_dump of the postWolf MTC Neon database to
# db/postwolf_backup_YYYYMMDD_HHMMSS.sql.
#
# Reads MERKLE_NEON (the same env var mtc_server uses, see
# mtc-keymaster/server2/c/mtc_db.c) from ~/.env.
#
# Uses the bundled pg_dump 17 from pg17/ rather than the system
# pg_dump — Neon currently runs PostgreSQL 17.x and the system
# pg_dump 16 refuses with "server version mismatch".  The bundle
# lives entirely under pg17/ (extracted by install-pg17.sh) and
# never touches /usr/lib system libpq.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/db"
PG17_DIR="$SCRIPT_DIR/pg17"
PG_DUMP="$PG17_DIR/usr/lib/postgresql/17/bin/pg_dump"
PG_LIBDIR="$PG17_DIR/usr/lib/x86_64-linux-gnu"

mkdir -p "$BACKUP_DIR"

if [ ! -x "$PG_DUMP" ]; then
    echo "Error: bundled pg_dump 17 not found at $PG_DUMP" >&2
    echo "Run $SCRIPT_DIR/install-pg17.sh first." >&2
    exit 1
fi

if [ -f "$HOME/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$HOME/.env"
    set +a
fi

if [ -z "${MERKLE_NEON:-}" ]; then
    echo "Error: MERKLE_NEON not set in $HOME/.env" >&2
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$BACKUP_DIR/postwolf_backup_${TIMESTAMP}.sql"

# -O drops object ownership, -x drops grant/revoke; both let the dump
# replay against any role on the restore side.  The grep filters out
# psql 17+ \unrestrict directives that older psql can't parse.
LD_LIBRARY_PATH="$PG_LIBDIR" \
    "$PG_DUMP" -O -x "$MERKLE_NEON" \
    | grep -v '^\\unrestrict' > "$OUT"

echo "Backup saved to $(basename "$OUT")"
