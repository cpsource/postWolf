#!/bin/bash
#
# Schema-only dump of the postWolf MTC Neon database.
# Writes schema-only.sql in this directory (overwriting any prior copy).
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PG17_DIR="$SCRIPT_DIR/pg17"
PG_DUMP="$PG17_DIR/usr/lib/postgresql/17/bin/pg_dump"
PG_LIBDIR="$PG17_DIR/usr/lib/x86_64-linux-gnu"

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

LD_LIBRARY_PATH="$PG_LIBDIR" \
    "$PG_DUMP" -O -x --schema-only "$MERKLE_NEON" \
    | grep -v '^\\unrestrict' > "$SCRIPT_DIR/schema-only.sql"

echo "Schema saved to $SCRIPT_DIR/schema-only.sql"
