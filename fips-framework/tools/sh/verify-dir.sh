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

# Surface any `# key: value` metadata recorded at sign time
# (e.g., `# git-commit: <hash>` from sign-dir.sh).
grep '^# ' MANIFEST.sha256 || true

# If the manifest recorded a git commit AND DIR is in a git repo,
# compare against current HEAD.  Mismatch is reported but does NOT
# fail the verify — the signature already proves integrity of the
# bytes on disk; this just surfaces replay-old-manifest scenarios.
RECORDED_COMMIT="$(awk '/^# git-commit:/ {print $3; exit}' MANIFEST.sha256)"
if [ -n "$RECORDED_COMMIT" ] && git rev-parse --verify HEAD >/dev/null 2>&1; then
    CURRENT_COMMIT="$(git rev-parse HEAD)"
    if ! git diff-index --quiet HEAD -- . 2>/dev/null; then
        CURRENT_COMMIT="${CURRENT_COMMIT}-dirty"
    fi
    if [ "$RECORDED_COMMIT" = "$CURRENT_COMMIT" ]; then
        echo "git HEAD match: $CURRENT_COMMIT"
    else
        echo "WARNING: recorded commit ($RECORDED_COMMIT) != current HEAD ($CURRENT_COMMIT)"
    fi
fi

FILES_COUNTED=$(grep -cv '^#' MANIFEST.sha256 || true)
echo "verified $DIR ($FILES_COUNTED files)"
