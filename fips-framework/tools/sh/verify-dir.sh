#!/bin/bash
# verify-dir.sh — verify a directory signed by sign-dir.sh.
#
# Usage: verify-dir.sh DOMAIN [DIR]
#
#   DOMAIN  publisher identity, e.g. `factsorlie.com-Alice`.
#           The verification key is resolved as follows:
#             1. ~/.TPM/<DOMAIN>/public_key.pem   (local-identity case —
#                you have an enrolled identity for this DOMAIN here).
#             2. Server fetch via `fetch-publisher-key --domain DOMAIN
#                --cert-index <N>` (cross-publisher case — DOMAIN is
#                not one of *your* identities).  N comes from the
#                manifest's signed `# publisher-cert-index:` header
#                line.  fetch-publisher-key talks to the MTC server
#                over MQC, validates sha256(returned PEM) against the
#                cert's subject_public_key_hash, and writes the PEM.
#                This is the same trust model mqc_peer.c uses.
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
#          case; the server-fetch path's spk-hash check already
#          confirms the cert/key pair is current.
#        - `# git-commit:` (if recorded and DIR is in a git repo)
#          exists as a commit object in the local repo (any branch,
#          any history).  WARN on mismatch.
#
# Exit 0 only if stages 1, 2, and the publisher equality check pass.
# Cert-index and git-commit mismatches are informational warnings.

set -euo pipefail

VERBOSE=0
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help)
            echo "Usage: verify-dir.sh [-v|--verbose] DOMAIN [DIR]" >&2
            exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
        -*) echo "verify-dir: unknown flag '$1'" >&2; exit 1 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]}"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: verify-dir.sh [-v|--verbose] DOMAIN [DIR]" >&2
    exit 1
fi

DOMAIN="$1"
DIR="${2:-.}"
DIR="$(cd "$DIR" && pwd)"

[ -r "$DIR/MANIFEST.sha256" ] || { echo "verify-dir: missing $DIR/MANIFEST.sha256" >&2; exit 1; }
[ -r "$DIR/MANIFEST.sig"    ] || { echo "verify-dir: missing $DIR/MANIFEST.sig" >&2; exit 1; }

# Read the manifest's recorded cert index up front — we need it to
# drive the server-fetch fallback if the local identity dir is absent.
RECORDED_CERT_INDEX="$(awk '/^# publisher-cert-index:/ {print $3; exit}' "$DIR/MANIFEST.sha256")"

TPM_DIR="$HOME/.TPM/$DOMAIN"
LOCAL_PUB="$TPM_DIR/public_key.pem"
TMP_PUB=""
PUB=""
PUB_SOURCE=""

cleanup() {
    [ -n "$TMP_PUB" ] && [ -f "$TMP_PUB" ] && rm -f "$TMP_PUB"
}
trap cleanup EXIT

if [ -r "$LOCAL_PUB" ]; then
    PUB="$LOCAL_PUB"
    PUB_SOURCE="local-identity ($TPM_DIR)"
else
    if [ -z "$RECORDED_CERT_INDEX" ]; then
        echo "verify-dir: no local identity at $TPM_DIR and manifest has" >&2
        echo "            no '# publisher-cert-index:' line — cannot fetch" >&2
        echo "            authoritative public key from server" >&2
        exit 1
    fi
    if ! command -v fetch-publisher-key >/dev/null 2>&1; then
        echo "verify-dir: no local identity at $TPM_DIR and the" >&2
        echo "            fetch-publisher-key helper is not on PATH" >&2
        echo "            (build with: make -f Makefile.tools fips)" >&2
        exit 1
    fi
    TMP_PUB="$(mktemp -t verify-dir-pub.XXXXXX.pem)"
    if ! fetch-publisher-key \
            --domain "$DOMAIN" \
            --cert-index "$RECORDED_CERT_INDEX" \
            --out "$TMP_PUB" 2>&1; then
        echo "verify-dir: fetch-publisher-key failed for DOMAIN=$DOMAIN" >&2
        echo "            cert_index=$RECORDED_CERT_INDEX" >&2
        exit 1
    fi
    PUB="$TMP_PUB"
    PUB_SOURCE="server-fetch (DOMAIN=$DOMAIN, cert_index=$RECORDED_CERT_INDEX)"
fi

cd "$DIR"

openssl40 pkeyutl -verify -rawin -pubin \
    -inkey "$PUB" \
    -in MANIFEST.sha256 \
    -sigfile MANIFEST.sig

if [ "$VERBOSE" = "1" ]; then
    sha256sum --strict --check MANIFEST.sha256
else
    sha256sum --quiet --strict --check MANIFEST.sha256
fi

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
# skipped silently in the server-fetch case.
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
