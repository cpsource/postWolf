#!/bin/bash
#
# clearout.sh — Delete all MTC state for cold-start testing.
#
# Removes:
#   ~/.TPM/           — client-side leaf keys, certs, ECH cache
#   ~/.mtc-ca-data/   — server-side CA key, entries, certs, landmarks
#   All rows in all MTC Neon tables (preserves table structure)
#
# Usage:
#   bash mtc-keymaster/tools/clearout.sh
#   bash mtc-keymaster/tools/clearout.sh --tokenpath /path/to/.env

set -e

# --- Confirmation ---

echo "WARNING: This will delete ALL MTC state:"
echo "  - ~/.TPM/ (leaf keys, certificates, ECH cache)"
echo "  - ~/.mtc-ca-data/ (CA key, entries, certificates, landmarks)"
echo "  - All rows in all Neon MTC tables"
echo ""
read -p "Are you sure? (yes/no): " answer

if [ "$answer" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

# --- Parse args ---

TOKENPATH=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tokenpath)
            TOKENPATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Remove local directories ---

echo ""

if [ -d "$HOME/.TPM" ]; then
    echo "Removing ~/.TPM/ ..."
    rm -rf "$HOME/.TPM"
    echo "  done"
else
    echo "~/.TPM/ does not exist, skipping"
fi

if [ -d "$HOME/.mtc-ca-data" ]; then
    echo "Removing ~/.mtc-ca-data/ ..."
    rm -rf "$HOME/.mtc-ca-data"
    echo "  done"
else
    echo "~/.mtc-ca-data/ does not exist, skipping"
fi

# --- Clear Neon tables ---

# Find MERKLE_NEON connection string
MERKLE_NEON="${MERKLE_NEON:-}"

if [ -z "$MERKLE_NEON" ] && [ -n "$TOKENPATH" ] && [ -f "$TOKENPATH" ]; then
    MERKLE_NEON=$(grep '^MERKLE_NEON=' "$TOKENPATH" | head -1 | cut -d= -f2-)
fi

if [ -z "$MERKLE_NEON" ] && [ -f "$HOME/.env" ]; then
    MERKLE_NEON=$(grep '^MERKLE_NEON=' "$HOME/.env" | head -1 | cut -d= -f2-)
fi

if [ -z "$MERKLE_NEON" ]; then
    echo ""
    echo "MERKLE_NEON not found (env, --tokenpath, or ~/.env)"
    echo "Skipping Neon table cleanup."
    echo ""
    echo "Done (local files only)."
    exit 0
fi

echo ""
echo "Clearing Neon tables ..."

psql "$MERKLE_NEON" -q <<'SQL'
-- Truncate all MTC tables (preserves structure, removes all rows)
TRUNCATE TABLE mtc_log_entries    CASCADE;
TRUNCATE TABLE mtc_checkpoints    CASCADE;
TRUNCATE TABLE mtc_landmarks      CASCADE;
TRUNCATE TABLE mtc_certificates   CASCADE;
TRUNCATE TABLE mtc_ca_config      CASCADE;
TRUNCATE TABLE mtc_revocations    CASCADE;

-- Optional tables (may not exist yet)
DO $$ BEGIN
    EXECUTE 'TRUNCATE TABLE abuseipdb CASCADE';
EXCEPTION WHEN undefined_table THEN NULL;
END $$;

DO $$ BEGIN
    EXECUTE 'TRUNCATE TABLE mtc_enrollment_nonces CASCADE';
EXCEPTION WHEN undefined_table THEN NULL;
END $$;

DO $$ BEGIN
    EXECUTE 'TRUNCATE TABLE mtc_fips_manifests CASCADE';
EXCEPTION WHEN undefined_table THEN NULL;
END $$;
SQL

echo "  done"

echo ""
echo "All MTC state cleared. Server will cold-start on next run."
