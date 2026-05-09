#!/bin/bash
#
# Sync local db/ directory to s3://postwolf-neon-backups.
# Idempotent — only changed/new files are uploaded.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
aws s3 sync "$SCRIPT_DIR/db/" s3://postwolf-neon-backups
