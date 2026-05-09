#!/bin/bash
#
# install-pg17.sh — fetch PostgreSQL 17 client + libpq into ./pg17/
# without touching the system apt config or system libpq.
#
# Why bundled?  Neon currently runs PostgreSQL 17.x, but Ubuntu 24.04
# ships pg_dump 16, which refuses with "server version mismatch".
# Adding the pgdg apt repo would transitively upgrade /usr/lib's
# libpq5 to 18.x, which has triggered service restart cascades on this
# host before.  This script keeps everything self-contained under
# pg17/ so the system is untouched.
#
# Usage:
#   ./install-pg17.sh             # download + extract; idempotent
#   ./install-pg17.sh --clean     # rm -rf pg17/ first
#
# What it produces:
#   pg17/usr/lib/postgresql/17/bin/pg_dump
#   pg17/usr/lib/x86_64-linux-gnu/libpq.so.5  -> libpq.so.5.18
#
# How it's used by the other scripts:
#   LD_LIBRARY_PATH=$SCRIPT_DIR/pg17/usr/lib/x86_64-linux-gnu \
#       $SCRIPT_DIR/pg17/usr/lib/postgresql/17/bin/pg_dump ...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PG17_DIR="$SCRIPT_DIR/pg17"
TMP_DIR="$(mktemp -d /tmp/pg17-debs.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# pgdg pool URLs.  Pinned to known-working versions; bump as needed.
CLIENT_URL='https://apt.postgresql.org/pub/repos/apt/pool/main/p/postgresql-17/postgresql-client-17_17.9-1.pgdg24.04%2B1_amd64.deb'
LIBPQ_URL='https://apt.postgresql.org/pub/repos/apt/pool/main/p/postgresql-18/libpq5_18.3-1.pgdg24.04%2B1_amd64.deb'

CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's|^# \{0,1\}||'
            exit 0
            ;;
        *) echo "install-pg17: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

if [ "$CLEAN" = 1 ]; then
    rm -rf "$PG17_DIR"
fi

if [ -x "$PG17_DIR/usr/lib/postgresql/17/bin/pg_dump" ]; then
    echo "[install-pg17] already installed:"
    LD_LIBRARY_PATH="$PG17_DIR/usr/lib/x86_64-linux-gnu" \
        "$PG17_DIR/usr/lib/postgresql/17/bin/pg_dump" --version
    exit 0
fi

echo "[install-pg17] downloading .debs to $TMP_DIR"
curl -fsSL -o "$TMP_DIR/pgclient17.deb" "$CLIENT_URL"
curl -fsSL -o "$TMP_DIR/libpq5.deb"     "$LIBPQ_URL"

echo "[install-pg17] extracting into $PG17_DIR"
mkdir -p "$PG17_DIR"
dpkg -x "$TMP_DIR/pgclient17.deb" "$PG17_DIR"
dpkg -x "$TMP_DIR/libpq5.deb"     "$PG17_DIR"

echo "[install-pg17] verifying"
LD_LIBRARY_PATH="$PG17_DIR/usr/lib/x86_64-linux-gnu" \
    "$PG17_DIR/usr/lib/postgresql/17/bin/pg_dump" --version

echo "[install-pg17] done."
