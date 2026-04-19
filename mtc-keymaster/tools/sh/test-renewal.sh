#!/bin/sh
# test-renewal.sh — manual smoke test for the /renew-cert flow.
#
# Run against a live MTC server (default: factsorlie.com:8446).  Each
# check is opt-in via an env var so you can skip the ones that require
# a writable scratch domain or root access.
#
# Quick checks (always safe, just probe state):
#   RENEW_TEST_DRY_RUN=1 ./test-renewal.sh     # check-renewal-cert --dry-run
#   RENEW_TEST_MQC_GATE=1 ./test-renewal.sh    # curl /renew-cert over TLS (8444) → 403
#   RENEW_TEST_LEGACY=1 ./test-renewal.sh      # curl /certificate/renew over TLS → 404
#
# Destructive checks (will consume a nonce / create a cert / write to ~/.TPM):
#   RENEW_TEST_FORCE=1 ./test-renewal.sh       # check-renewal-cert --force <id>
#                                              # (set RENEW_TEST_ID=<dir>)
#
# Server + port come from env:
#   RENEW_SERVER=factsorlie.com:8446 (MQC)
#   RENEW_TLS_URL=https://factsorlie.com:8444 (for the 403/404 probes)

set -eu

SERVER="${RENEW_SERVER:-factsorlie.com:8446}"
TLS_URL="${RENEW_TLS_URL:-https://factsorlie.com:8444}"

pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$1"; FAILED=$((FAILED + 1)); }
FAILED=0

# -- MQC-only gate: /renew-cert over TLS must return 403 --------------
if [ "${RENEW_TEST_MQC_GATE:-0}" = "1" ]; then
    echo "--- MQC-only gate ---"
    code=$(curl -sk -o /tmp/renew_gate.out -w '%{http_code}' \
                -X POST -H 'Content-Type: application/json' \
                -d '{"new_public_key_pem":""}' \
                "$TLS_URL/renew-cert" || echo "000")
    body=$(cat /tmp/renew_gate.out 2>/dev/null || echo "")
    if [ "$code" = "403" ]; then
        pass "MQC-only gate: TLS 8444 POST /renew-cert → 403 ($body)"
    else
        fail "MQC-only gate: expected 403, got $code ($body)"
    fi
fi

# -- Legacy endpoint removed: /certificate/renew must 404 -------------
if [ "${RENEW_TEST_LEGACY:-0}" = "1" ]; then
    echo "--- Legacy endpoint removed ---"
    code=$(curl -sk -o /dev/null -w '%{http_code}' \
                -X POST -H 'Content-Type: application/json' \
                -d '{}' "$TLS_URL/certificate/renew" || echo "000")
    if [ "$code" = "404" ]; then
        pass "legacy endpoint: /certificate/renew → 404"
    else
        fail "legacy endpoint: expected 404, got $code"
    fi
fi

# -- Dry run: inventory + decision logic ------------------------------
if [ "${RENEW_TEST_DRY_RUN:-0}" = "1" ]; then
    echo "--- Dry run ---"
    if check-renewal-cert --dry-run -v -s "$SERVER" 2>&1; then
        pass "check-renewal-cert --dry-run exited 0"
    else
        rc=$?
        # rc=1 means at least one revoked or failed — still informative
        if [ $rc -eq 1 ]; then
            pass "check-renewal-cert --dry-run exited 1 (revoked/failed; expected if any exist)"
        else
            fail "check-renewal-cert --dry-run exited $rc"
        fi
    fi
fi

# -- Force renewal of one identity ------------------------------------
if [ "${RENEW_TEST_FORCE:-0}" = "1" ]; then
    echo "--- Force renewal ---"
    id="${RENEW_TEST_ID:-}"
    if [ -z "$id" ]; then
        echo "set RENEW_TEST_ID=<dir under ~/.TPM>" >&2
        exit 2
    fi
    pre_index=$(cat "$HOME/.TPM/$id/index" 2>/dev/null || echo "?")
    if check-renewal-cert --force "$id" -v -s "$SERVER"; then
        post_index=$(cat "$HOME/.TPM/$id/index" 2>/dev/null || echo "?")
        if [ "$pre_index" != "$post_index" ] && [ "$post_index" != "?" ]; then
            pass "force renewal: $id index $pre_index → $post_index"
        else
            fail "force renewal: index did not advance ($pre_index → $post_index)"
        fi
    else
        fail "check-renewal-cert --force $id exited $?"
    fi
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "All checks passed."
else
    echo "$FAILED check(s) failed."
    exit 1
fi
