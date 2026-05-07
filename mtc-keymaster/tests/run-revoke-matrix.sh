#!/bin/bash
#
# run-revoke-matrix.sh — TODO #19 end-to-end test runner.
#
# Enrolls a fresh sacrificial leaf ("bob-revoke-test-<timestamp>") under
# the local factsorlie.com-ca, runs the test_revoke_matrix C driver
# against the live MTC CA on MQC/8446, and reports pass/fail per row.
# The leaf is revoked at the end (positive row).  Per-run cost in the
# Merkle log: +1 leaf cert + 1 revocation row.  Append-only by design.
#
# Pre-reqs:
#   - factsorlie.com-ca enrolled at ~/.TPM/factsorlie.com-ca/
#   - frflashy.com-ca + frflashy.com leaf already in the log (used for
#     the out-of-domain + target-is-CA negative rows).  Auto-discovered
#     via /certificate/search.
#   - mtc-ca.service running locally (or --server H:P pointing elsewhere).
#   - Tools on PATH: issue_leaf_nonce, bootstrap_leaf, test_revoke_matrix.
#
# Usage:
#   ./run-revoke-matrix.sh                     # use defaults
#   ./run-revoke-matrix.sh --skip-enrol DIR    # reuse an existing bob TPM dir

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LABEL_PREFIX="bob-revoke-test"
LABEL=""
DOMAIN="factsorlie.com"
FOREIGN_DOMAIN="frflashy.com"
SERVER=""
SKIP_ENROL_DIR=""
TRACE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)        DOMAIN="$2"; shift 2 ;;
        --foreign-ca-domain) FOREIGN_DOMAIN="$2"; shift 2 ;;
        --server|-s)     SERVER="$2"; shift 2 ;;
        --skip-enrol)    SKIP_ENROL_DIR="$2"; shift 2 ;;
        --trace)         TRACE="--trace"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

LABEL="${LABEL_PREFIX}-$(date +%Y%m%d-%H%M%S)"

echo "=== TODO #19: revoke matrix end-to-end test ==="
echo "Domain:           $DOMAIN"
echo "Foreign domain:   $FOREIGN_DOMAIN  (used for out-of-domain + target-is-CA rows)"
echo "Bob label:        $LABEL"
echo

# --- locate the test driver -------------------------------------------
DRIVER="$SCRIPT_DIR/c/test_revoke_matrix"
if [ ! -x "$DRIVER" ]; then
    echo "Error: test driver not built — run 'make -C $SCRIPT_DIR/c' first" >&2
    exit 3
fi

# --- enrol Bob (or reuse an existing dir) -----------------------------
if [ -n "$SKIP_ENROL_DIR" ]; then
    BOB_DIR="$SKIP_ENROL_DIR"
    if [ ! -f "$BOB_DIR/private_key.pem" ]; then
        echo "Error: --skip-enrol $BOB_DIR has no private_key.pem" >&2
        exit 4
    fi
    echo "Reusing existing Bob TPM at: $BOB_DIR"
else
    echo "Step 1: issue_leaf_nonce --domain $DOMAIN --label $LABEL"
    NONCE_OUT=$(issue_leaf_nonce --domain "$DOMAIN" --label "$LABEL" --ttl-days 1 2>&1)
    echo "$NONCE_OUT" | grep -E '^[[:space:]]*(Nonce|Cosigner-fp|CA index):' || true
    NONCE=$(echo "$NONCE_OUT" | awk '/^[[:space:]]*Nonce:/{print $2}' | tail -1)
    COSIGNER_FP=$(echo "$NONCE_OUT" | awk '/^[[:space:]]*Cosigner-fp:/{print $2}' | tail -1)
    if [ -z "$NONCE" ] || [ -z "$COSIGNER_FP" ]; then
        echo "Error: could not parse nonce/cosigner-fp from issue_leaf_nonce output" >&2
        echo "---raw output---"; echo "$NONCE_OUT"
        exit 5
    fi

    echo
    echo "Step 2: generate Bob's ML-DSA-87 keypair (openssl40)"
    TMP=$(mktemp -d)
    if ! command -v openssl40 >/dev/null 2>&1; then
        echo "Error: openssl40 not found on PATH (needed for ML-DSA keygen)." >&2
        echo "Pre-generate a keypair and pass it via --skip-enrol DIR." >&2
        rm -rf "$TMP"
        exit 6
    fi
    openssl40 genpkey -algorithm ML-DSA-87 -out "$TMP/bob_priv.pem"
    openssl40 pkey -in "$TMP/bob_priv.pem" -pubout -out "$TMP/bob_pub.pem"

    echo
    echo "Step 3: bootstrap_leaf --domain $DOMAIN --label $LABEL ..."
    BOB_DIR_ARG=""
    [ -n "$SERVER" ] && SERVER_ARG="--server $SERVER" || SERVER_ARG=""
    bootstrap_leaf \
        --domain "$DOMAIN" \
        --public-key "$TMP/bob_pub.pem" \
        --private-key "$TMP/bob_priv.pem" \
        --nonce "$NONCE" \
        --cosigner-fp "$COSIGNER_FP" \
        --validity-days 1 \
        $SERVER_ARG

    BOB_DIR="$HOME/.TPM/${DOMAIN}-${LABEL}"
    if [ ! -f "$BOB_DIR/private_key.pem" ]; then
        echo "Error: bootstrap_leaf did not populate $BOB_DIR" >&2
        rm -rf "$TMP"
        exit 7
    fi
    rm -rf "$TMP"
    echo "Bob enrolled at: $BOB_DIR (idx=$(cat "$BOB_DIR/index"))"
fi

echo
echo "Step 4: run test_revoke_matrix"
echo "================================================="
SERVER_ARG=""
[ -n "$SERVER" ] && SERVER_ARG="--server $SERVER"
"$DRIVER" \
    --bob-tpm-path "$BOB_DIR" \
    --foreign-ca-domain "$FOREIGN_DOMAIN" \
    $SERVER_ARG \
    $TRACE
RC=$?
echo "================================================="

if [ $RC -eq 0 ]; then
    echo "OK — all rows passed."
else
    echo "FAIL — at least one row failed (driver exit=$RC)"
fi
exit $RC
