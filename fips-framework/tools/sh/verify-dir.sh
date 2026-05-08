#!/bin/bash
# verify-dir.sh — verify a directory signed by sign-dir.sh.
#
# Usage: verify-dir.sh [DIR]          (default: current dir)
#        FIPS_KEY_DIR=... verify-dir.sh [DIR]
#
# Two-stage check:
#   1. MANIFEST.sig is a valid ML-DSA-87 signature over MANIFEST.sha256
#      under fips-keys/public_key.pem.
#   2. Every file listed in MANIFEST.sha256 still hashes to the recorded
#      value.
# Exits 0 only if both pass.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="${FIPS_KEY_DIR:-$HERE/../../fips-keys}"
PUB="$KEY_DIR/public_key.pem"

DIR="${1:-.}"
DIR="$(cd "$DIR" && pwd)"

[ -r "$PUB"                  ] || { echo "verify-dir: missing public key: $PUB" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sha256"  ] || { echo "verify-dir: missing $DIR/MANIFEST.sha256" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sig"     ] || { echo "verify-dir: missing $DIR/MANIFEST.sig" >&2; exit 1; }

cd "$DIR"

openssl40 pkeyutl -verify -rawin -pubin \
    -inkey "$PUB" \
    -in MANIFEST.sha256 \
    -sigfile MANIFEST.sig

sha256sum --quiet --strict --check MANIFEST.sha256

echo "verified $DIR ($(wc -l < MANIFEST.sha256) files)"
