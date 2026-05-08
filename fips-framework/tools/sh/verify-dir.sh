#!/bin/bash
# verify-dir.sh — verify a directory signed by sign-dir.sh, using a
# publisher's public key from ~/.TPM/<DOMAIN>/.
#
# Usage: verify-dir.sh DOMAIN [DIR]
#
#   DOMAIN  publisher identity, e.g. `factsorlie.com-Alice`.
#           Resolves to ~/.TPM/<DOMAIN>/public_key.pem for the
#           ML-DSA-87 verification key.  The caller is asserting
#           which identity is supposed to have signed; verify
#           cross-checks the manifest's recorded `# publisher:`
#           against this argument.
#   DIR     directory containing MANIFEST.sha256 + MANIFEST.sig
#           (default: current dir).
#
# Three-stage check, in order:
#   1. MANIFEST.sig is a valid ML-DSA-87 signature over
#      MANIFEST.sha256 under DOMAIN's public key.
#   2. Every file listed in MANIFEST.sha256 hashes to the recorded
#      value (`sha256sum --strict --check`).
#   3. Forensic metadata in the signed header lines:
#        - `# publisher:` matches DOMAIN argument (FAIL on mismatch
#          — caller asserted DOMAIN, manifest claims otherwise).
#        - `# publisher-cert-index:` matches ~/.TPM/<DOMAIN>/index
#          (WARN on mismatch — current cert may have been re-issued
#          since the manifest was signed; signature is still valid).
#        - `# git-commit:` (if recorded and DIR is in a git repo)
#          exists as a commit object in the local repo (any branch,
#          any history).  WARN on mismatch.
#
# Exit 0 only if stages 1, 2, and the publisher equality check pass.
# Cert-index and git-commit mismatches are informational warnings.

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: verify-dir.sh DOMAIN [DIR]" >&2
    exit 1
fi

DOMAIN="$1"
DIR="${2:-.}"
DIR="$(cd "$DIR" && pwd)"

TPM_DIR="$HOME/.TPM/$DOMAIN"
PUB="$TPM_DIR/public_key.pem"
INDEX_FILE="$TPM_DIR/index"

[ -d "$TPM_DIR"             ] || { echo "verify-dir: no TPM identity at $TPM_DIR" >&2; exit 1; }
[ -r "$PUB"                 ] || { echo "verify-dir: missing public key: $PUB" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sha256" ] || { echo "verify-dir: missing $DIR/MANIFEST.sha256" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sig"    ] || { echo "verify-dir: missing $DIR/MANIFEST.sig" >&2; exit 1; }

cd "$DIR"

openssl40 pkeyutl -verify -rawin -pubin \
    -inkey "$PUB" \
    -in MANIFEST.sha256 \
    -sigfile MANIFEST.sig

sha256sum --quiet --strict --check MANIFEST.sha256

# Surface all signed metadata lines for the operator.
grep '^# ' MANIFEST.sha256 || true

# Stage 3a — publisher equality.  Caller asserted DOMAIN; if the
# manifest's `# publisher:` line says something else, fail closed
# (signed metadata mismatch is a real problem worth aborting on).
RECORDED_PUBLISHER="$(awk '/^# publisher:/ {print $3; exit}' MANIFEST.sha256)"
if [ -z "$RECORDED_PUBLISHER" ]; then
    echo "WARNING: manifest has no recorded publisher; expected $DOMAIN" >&2
elif [ "$RECORDED_PUBLISHER" != "$DOMAIN" ]; then
    echo "ERROR: publisher mismatch — manifest says $RECORDED_PUBLISHER, caller asserted $DOMAIN" >&2
    exit 1
fi

# Stage 3b — cert-index informational.  ~/.TPM/<DOMAIN>/index is
# the *current* cert index for this identity; the manifest may
# have been signed before a re-issue.  Warn but don't fail.
RECORDED_CERT_INDEX="$(awk '/^# publisher-cert-index:/ {print $3; exit}' MANIFEST.sha256)"
if [ -n "$RECORDED_CERT_INDEX" ]; then
    CURRENT_CERT_INDEX="$(cat "$INDEX_FILE")"
    if [ "$RECORDED_CERT_INDEX" != "$CURRENT_CERT_INDEX" ]; then
        echo "WARNING: recorded cert index $RECORDED_CERT_INDEX != current $CURRENT_CERT_INDEX (cert may have been re-issued)"
    fi
fi

# Stage 3c — git-commit existence (existing logic; permissive).
RECORDED_COMMIT="$(awk '/^# git-commit:/ {print $3; exit}' MANIFEST.sha256)"
if [ -n "$RECORDED_COMMIT" ] && git rev-parse --git-dir >/dev/null 2>&1; then
    BARE_HASH="${RECORDED_COMMIT%-dirty}"
    if git cat-file -e "${BARE_HASH}^{commit}" 2>/dev/null; then
        echo "git commit found: $RECORDED_COMMIT"
    else
        echo "WARNING: recorded commit $RECORDED_COMMIT not found in local repo"
    fi
fi

FILES_COUNTED=$(grep -cv '^#' MANIFEST.sha256 || true)
echo "verified $DIR as $DOMAIN ($FILES_COUNTED files)"
