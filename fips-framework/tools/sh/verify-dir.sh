#!/bin/bash
# verify-dir.sh — verify a directory signed by sign-dir.sh.
#
# Usage: verify-dir.sh DOMAIN [DIR]
#
#   DOMAIN  publisher identity, e.g. `factsorlie.com-Alice`.
#           The verification key is resolved in two steps, in order:
#             1. ~/.TPM/<DOMAIN>/public_key.pem   (local-identity case —
#                you have an enrolled identity for this DOMAIN here).
#             2. ~/.TPM/peers/<N>/public_key.pem  (peer-cache fallback —
#                you've previously talked to this DOMAIN over MQC and
#                its key is cached, but DOMAIN is not one of *your*
#                identities; N comes from the manifest's signed
#                `# publisher-cert-index:` header line).
#           The peer-cache copy is integrity-checked at MQC handshake
#           time against the cert's subject_public_key_hash, so the
#           trust property is the same.
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
#          (WARN on mismatch).  Only checked in the local-identity
#          case; the peer-cache fallback has no local notion of
#          "current" cert index for DOMAIN.
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

[ -r "$DIR/MANIFEST.sha256" ] || { echo "verify-dir: missing $DIR/MANIFEST.sha256" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sig"    ] || { echo "verify-dir: missing $DIR/MANIFEST.sig" >&2; exit 1; }

# Read the manifest's recorded cert index up front — we need it to
# resolve the peer-cache fallback if the local identity dir is absent.
RECORDED_CERT_INDEX="$(awk '/^# publisher-cert-index:/ {print $3; exit}' "$DIR/MANIFEST.sha256")"

TPM_DIR="$HOME/.TPM/$DOMAIN"
LOCAL_PUB="$TPM_DIR/public_key.pem"
PEER_PUB=""
if [ -n "$RECORDED_CERT_INDEX" ]; then
    PEER_PUB="$HOME/.TPM/peers/$RECORDED_CERT_INDEX/public_key.pem"
fi

PUB=""
PUB_SOURCE=""
if [ -r "$LOCAL_PUB" ]; then
    PUB="$LOCAL_PUB"
    PUB_SOURCE="local-identity ($TPM_DIR)"
elif [ -n "$PEER_PUB" ] && [ -r "$PEER_PUB" ]; then
    PUB="$PEER_PUB"
    PUB_SOURCE="peer-cache (~/.TPM/peers/$RECORDED_CERT_INDEX)"
else
    echo "verify-dir: cannot find a public key for $DOMAIN:" >&2
    echo "  tried $LOCAL_PUB" >&2
    if [ -n "$PEER_PUB" ]; then
        echo "  tried $PEER_PUB (from manifest's cert index $RECORDED_CERT_INDEX)" >&2
    else
        echo "  manifest has no '# publisher-cert-index:' line — cannot fall back" >&2
    fi
    exit 1
fi

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

# Stage 3b — cert-index informational.  Only meaningful in the
# local-identity case (we have a "current" cert index here);
# skipped silently when verifying via peer-cache.
INDEX_FILE="$TPM_DIR/index"
if [ -n "$RECORDED_CERT_INDEX" ] && [ -r "$INDEX_FILE" ]; then
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
echo "verified $DIR as $DOMAIN ($FILES_COUNTED files; key=$PUB_SOURCE)"
