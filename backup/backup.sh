#!/bin/bash
# postWolf MTC database backup orchestrator
#
# Five steps:
#   1. pg_dump → db/postwolf_backup_YYYYMMDD_HHMMSS.sql
#   2. aws s3 sync db/ → s3://postwolf-neon-backups
#   3. Apply retention (3 daily / 2 weekly / 1 monthly), local + S3
#   4. Sweep stray ~ temp files from S3
#   5. Print local + S3 listings
#
# Reads MERKLE_NEON from ~/.env.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/db"
S3_BUCKET="s3://postwolf-neon-backups"

mkdir -p "$BACKUP_DIR"
cd "$SCRIPT_DIR"

echo "=== postWolf MTC Database Backup ==="
echo "Backup directory: $BACKUP_DIR"
echo "S3 bucket:        $S3_BUCKET"
echo

echo "1. Creating backup..."
./backup-development.sh

echo
echo "2. Uploading to S3..."
./cp-to-s3.sh

echo
echo "3. Applying backup retention policy..."
python3 "$SCRIPT_DIR/age-backups.py" \
    --keep-daily-backups 3 \
    --keep-weekly-backups 2 \
    --keep-monthly-backups 1 \
    --list

echo
echo "4. Cleaning up ~ files from S3..."
aws s3 rm "$S3_BUCKET/" --recursive --exclude "*" --include "*~" 2>/dev/null || true

echo
echo "5. Current backups in db/:"
echo "----------------------------------------"
shopt -s nullglob
for f in "$BACKUP_DIR"/postwolf_backup_*.sql; do
    SIZE=$(stat -c %s "$f")
    NAME=$(basename "$f")
    printf "  %s  %'d bytes\n" "$NAME" "$SIZE"
done
shopt -u nullglob
echo "----------------------------------------"

echo
echo "6. Current backups in S3:"
echo "----------------------------------------"
aws s3 ls "$S3_BUCKET/" --human-readable
echo "----------------------------------------"

echo
echo "=== Backup complete ==="
