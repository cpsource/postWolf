#!/bin/sh
# test-mqc-matrix.sh — Phase 4b cross-tool matrix.
#
# Cycles mqc-revocation-policy through {mandatory, cache-only,
# disabled} and runs each MQC client tool under each policy, asserting
# the expected end-to-end outcome.  Both client and server read the
# same /etc/postWolf/config, so the policy switch + service restart
# tests both halves of the protocol under each policy.
#
# Implemented matrix (scoped from the master plan's 96 cells, which
# assumed an encrypted-mode handshake we haven't implemented):
#
#   tools  : { mqc-encode-decode, show-tpm-verify }
#   modes  : { clear }      (encrypted mode is a stub; out of scope)
#   policy : { mandatory, cache-only, disabled }
#   fixture: { valid }      (name-mismatch is covered by test_name_check
#                            in test-mqc-all.sh; orthogonal to policy)
#
#   = 2 tools × 1 mode × 3 policies × 1 fixture = 6 cells
#
# Caches are warmed under mandatory BEFORE switching to cache-only so
# the tool doesn't trip over a cold cache + denied fetch.
#
# Pre-requisites (CI / dev):
#   - mtc-ca.service active
#   - sudo without prompt for cp + systemctl restart
#   - /etc/postWolf/config exists (we save and restore it)

set -u

CONFIG=/etc/postWolf/config
BAK=/tmp/test-mqc-matrix.config.$$
TARGET_HOST="${TARGET_HOST:-factsorlie.com}"
TARGET_PORT="${TARGET_PORT:-8446}"
TARGET_IP="${TARGET_IP:-$(getent ahostsv4 "$TARGET_HOST" | awk '/STREAM/{print $1; exit}')}"

PASS=0
FAIL=0
FAILED_NAMES=""

c_green=$(printf '\033[32m'); c_red=$(printf '\033[31m')
c_cyan=$(printf '\033[36m'); c_dim=$(printf '\033[2m'); c_off=$(printf '\033[0m')

step() { printf '%s--- %s%s\n' "$c_cyan" "$1" "$c_off"; }
ok()   { PASS=$((PASS+1)); printf '%sPASS%s %s\n' "$c_green" "$c_off" "$1"; }
ko()   { FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES $1"; printf '%sFAIL%s %s\n' "$c_red" "$c_off" "$1"; }
note() { printf '%s%s%s\n' "$c_dim" "$1" "$c_off"; }

# Restore config + restart on any exit, including signals.
cleanup() {
    if [ -f "$BAK" ]; then
        sudo cp "$BAK" "$CONFIG"
        sudo systemctl restart mtc-ca.service >/dev/null 2>&1 || true
        sudo rm -f "$BAK"
        note "config restored, mtc-ca.service restarted"
    fi
}
trap cleanup EXIT INT TERM

# -- Helper: rewrite config with a single policy line ------------------
# Strips any prior `mqc-revocation-policy` line (commented or not), then
# appends the requested policy under [global].
set_policy() {
    policy="$1"
    python3 -c "
import re, sys
data = open('$CONFIG').read()
data = re.sub(r'^[# ]*mqc-revocation-policy\s+\S+\s*$', '', data, flags=re.M)
data = data.rstrip() + '\nmqc-revocation-policy        $policy\n'
open('/tmp/test-mqc-matrix.cfg.new','w').write(data)
"
    sudo cp /tmp/test-mqc-matrix.cfg.new "$CONFIG"
    rm -f /tmp/test-mqc-matrix.cfg.new
    sudo systemctl restart mtc-ca.service
    sleep 2
    if ! systemctl is-active --quiet mtc-ca.service; then
        printf '%sFATAL%s service did not restart under policy=%s\n' \
            "$c_red" "$c_off" "$policy"
        exit 2
    fi
}

clear_redis() {
    if command -v redis-cli >/dev/null 2>&1; then
        redis-cli del \
            "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
            "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
            "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
            >/dev/null 2>&1 || true
    fi
}

# -- Cells -------------------------------------------------------------
cell_encode_decode() {
    label="$1"
    out=$(echo hi | mqc --encode --env --no-cache 2>/dev/null \
                  | mqc --decode --env --no-cache 2>/dev/null)
    if [ "$out" = "hi" ]; then
        ok "$label  mqc encode|decode roundtrip"
    else
        ko "$label  mqc encode|decode roundtrip (got '$out')"
    fi
}

cell_show_tpm_verify() {
    label="$1"
    if show-tpm --verify >/tmp/test-matrix-show-tpm.out 2>&1; then
        # show-tpm exits 0 even when individual entries fail; grep for
        # the per-entry verdict line to confirm at least one [+] entry
        # actually verified end-to-end.
        if grep -q 'Verify:.*server=OK.*revoked=no.*proof=OK.*time=OK' \
                /tmp/test-matrix-show-tpm.out; then
            ok "$label  show-tpm --verify"
        else
            ko "$label  show-tpm --verify (no verified entries)"
            tail -10 /tmp/test-matrix-show-tpm.out | sed 's/^/    | /'
        fi
    else
        ko "$label  show-tpm --verify (exit non-zero)"
        tail -10 /tmp/test-matrix-show-tpm.out | sed 's/^/    | /'
    fi
}

# -- Pre-flight --------------------------------------------------------
step "pre-flight"
if ! systemctl is-active --quiet mtc-ca.service; then
    printf '%sFATAL%s mtc-ca.service is not active\n' "$c_red" "$c_off"; exit 2
fi
if [ -z "$TARGET_IP" ]; then
    printf '%sFATAL%s could not resolve %s\n' "$c_red" "$c_off" "$TARGET_HOST"; exit 2
fi
sudo cp "$CONFIG" "$BAK"
note "saved $CONFIG to $BAK"

# -- Warmup under mandatory --------------------------------------------
step "warmup (policy=mandatory)"
set_policy "mandatory"
clear_redis
# Run a couple of roundtrips so peer-revocation cache + cert cache are
# warm before we switch to cache-only (where a cold cache aborts).
echo hi | mqc --encode --env --no-cache 2>/dev/null \
       | mqc --decode --env --no-cache >/dev/null 2>&1
echo hi | mqc --encode --env --no-cache 2>/dev/null \
       | mqc --decode --env --no-cache >/dev/null 2>&1
show-tpm --verify >/dev/null 2>&1
note "caches warmed"

# -- Mandatory policy --------------------------------------------------
step "policy=mandatory"
clear_redis
cell_encode_decode      "mandatory"
clear_redis
cell_show_tpm_verify    "mandatory"

# -- Cache-only policy -------------------------------------------------
step "policy=cache-only"
set_policy "cache-only"
clear_redis
cell_encode_decode      "cache-only"
clear_redis
cell_show_tpm_verify    "cache-only"

# -- Disabled policy ---------------------------------------------------
step "policy=disabled"
set_policy "disabled"
clear_redis
cell_encode_decode      "disabled"
clear_redis
cell_show_tpm_verify    "disabled"

# -- Summary -----------------------------------------------------------
printf '\n%sMatrix summary:%s pass=%d fail=%d\n' "$c_cyan" "$c_off" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '%sfailed:%s%s\n' "$c_red" "$c_off" "$FAILED_NAMES"
    exit 1
fi
exit 0
