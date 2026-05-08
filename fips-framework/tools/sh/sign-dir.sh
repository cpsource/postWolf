#!/bin/bash
# sign-dir.sh — recursively sign all files under a directory with ML-DSA-87.
#
# Usage: sign-dir.sh [DIR]            (default: current dir)
#        FIPS_KEY_DIR=... sign-dir.sh [DIR]
#
# Produces DIR/MANIFEST.sha256 (one SHA-256 per regular file under DIR,
# paths relative to DIR; MANIFEST.* and private_key.pem excluded;
# symlinks are followed) and DIR/MANIFEST.sig (pure ML-DSA-87 signature
# over MANIFEST.sha256).  Verify with verify-dir.sh.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="${FIPS_KEY_DIR:-$HERE/../../fips-keys}"
PRIV="$KEY_DIR/private_key.pem"

DIR="${1:-.}"
DIR="$(cd "$DIR" && pwd)"

[ -r "$PRIV" ] || { echo "sign-dir: missing private key: $PRIV" >&2; exit 1; }

cd "$DIR"

mapfile -t FILES < <(
    find -L . -type f \
         ! -name MANIFEST.sha256 \
         ! -name MANIFEST.sig \
         ! -name private_key.pem \
         -printf '%P\n' | LC_ALL=C sort
)

if [ ${#FILES[@]} -eq 0 ]; then
    echo "sign-dir: no files to sign in $DIR" >&2
    exit 1
fi

sha256sum -- "${FILES[@]}" > MANIFEST.sha256

openssl40 pkeyutl -sign -rawin \
    -inkey "$PRIV" \
    -in MANIFEST.sha256 \
    -out MANIFEST.sig

echo "signed $DIR (${#FILES[@]} files)"
