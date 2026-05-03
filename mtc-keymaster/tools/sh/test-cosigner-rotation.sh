#!/bin/sh
# test-cosigner-rotation.sh — Phase 4d cosigner-rotation drill.
#
# Exercises the issue-#8 cosigner-fingerprint cache invariant in
# mqc_peer_verify: when the locally-stored fingerprint at
# ~/.TPM/peers/<n>/cosigner-fp.hex doesn't match the current cosigner
# pubkey, the cached cert MUST be dropped, the cert re-fetched, the
# inclusion proof + cosignature re-verified, and the new fingerprint
# persisted.  Without that invariant, a rotated cosigner would never
# be picked up until the cache file aged out.
#
# We don't actually rotate the live cosigner (that's an admin
# operation that affects every client at once).  Instead we corrupt
# our LOCAL cosigner-fp.hex to a wrong value, run a handshake, and
# assert the invariant fired SOMEWHERE -- the file ends up rewritten
# to the correct fingerprint and the handshake completes.
#
# Note: in this single-host deployment, mtc_server runs as the same
# Linux user as the test client and consults the same ~/.TPM tree
# for its OWN outbound MQC traffic.  When we corrupt the file, the
# server's own peer_verify call may detect the mismatch first and
# rewrite it before our client process ever reads it.  That means
# the COSIGNER_ROTATED log line lands in mtc-ca.service's journal,
# not in our test process's stderr.  We grep for it in both places.
#
# Knobs:
#   PEER_INDEX     default 73
#   TARGET_HOST    default factsorlie.com

set -u

PEER_INDEX="${PEER_INDEX:-73}"
TARGET_HOST="${TARGET_HOST:-factsorlie.com}"
TARGET_IP="${TARGET_IP:-$(getent ahostsv4 "$TARGET_HOST" | awk '/STREAM/{print $1; exit}')}"

PEER_DIR="$HOME/.TPM/peers/$PEER_INDEX"
FP_FILE="$PEER_DIR/cosigner-fp.hex"

PASS=0
FAIL=0

c_green=$(printf '\033[32m'); c_red=$(printf '\033[31m')
c_cyan=$(printf '\033[36m'); c_dim=$(printf '\033[2m'); c_off=$(printf '\033[0m')

step() { printf '%s--- %s%s\n' "$c_cyan" "$1" "$c_off"; }
ok()   { PASS=$((PASS+1)); printf '%sPASS%s %s\n' "$c_green" "$c_off" "$1"; }
ko()   { FAIL=$((FAIL+1)); printf '%sFAIL%s %s\n' "$c_red" "$c_off" "$1"; }
note() { printf '%s%s%s\n' "$c_dim" "$1" "$c_off"; }

# -- Pre-flight --------------------------------------------------------
step "pre-flight"

if ! systemctl is-active --quiet mtc-ca.service; then
    printf '%sFATAL%s mtc-ca.service is not active\n' "$c_red" "$c_off"; exit 2
fi

# Warm the cache so the fingerprint file exists in a known-good state
# before we corrupt it.  Use show-tpm --verify because mqc --encode
# is purely local AES-GCM and never calls mqc_peer_verify.  Two
# invocations: first may drop on cold revocation cache, second
# populates the fingerprint.
show-tpm --verify >/dev/null 2>&1
show-tpm --verify >/dev/null 2>&1

if [ ! -f "$FP_FILE" ]; then
    printf '%sFATAL%s expected fingerprint cache at %s; is the peer index right?\n' \
        "$c_red" "$c_off" "$FP_FILE"
    exit 2
fi
GOOD_FP=$(cat "$FP_FILE")
note "good fingerprint for cert $PEER_INDEX: ${GOOD_FP%????????????????????????????????????????????????????????}…"

# -- Corruption phase --------------------------------------------------
step "corrupt local fingerprint"

# Replace with a deliberately-wrong all-zeros fingerprint.  A real
# rotation would replace the current fingerprint with a different but
# also-valid one; the invariant we're testing is "stored != current
# triggers re-verification", so any mismatching value works.
printf '%064d\n' 0 > "$FP_FILE"
note "wrote bogus fingerprint: $(cat $FP_FILE)"

if command -v redis-cli >/dev/null 2>&1; then
    redis-cli del \
        "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
        "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
        "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
        >/dev/null 2>&1 || true
fi

# -- Recovery phase ----------------------------------------------------
step "trigger recovery (handshake should detect mismatch + re-verify)"

# Snapshot journalctl cursor BEFORE the test so grep doesn't pick up
# COSIGNER_ROTATED lines from prior unrelated runs.
JOURNAL_CURSOR=$(journalctl -u mtc-ca.service -n 0 --show-cursor 2>/dev/null \
                 | awk '/cursor:/{print $2}')

# show-tpm --verify is the canonical client-side exerciser of
# mqc_peer_verify (it does an MQC connection per TPM entry).  Run it
# and capture stderr; COSIGNER_ROTATED may appear here OR in the
# server's journal (see comment at top of file).
show-tpm --verify >/tmp/cosigner-stdout.log 2>/tmp/cosigner-stderr.log

if grep -q "Verify:.*server=OK" /tmp/cosigner-stdout.log; then
    ok "show-tpm --verify succeeded after fingerprint corruption"
else
    ko "show-tpm --verify never produced a verified entry"
    tail -10 /tmp/cosigner-stdout.log | sed 's/^/    | /'
fi

# Did the fingerprint file get rewritten with the correct value?
# This is the load-bearing assertion: the invariant fired somewhere
# (server, client, or both) and recovered the cache.
NEW_FP=$(cat "$FP_FILE")
if [ "$NEW_FP" = "$GOOD_FP" ]; then
    ok "fingerprint file restored to correct value (invariant fired)"
elif [ "$NEW_FP" = "$(printf '%064d' 0)" ]; then
    ko "fingerprint file still bogus — invariant never fired"
else
    ko "fingerprint file rewrote to UNEXPECTED value: $NEW_FP"
fi

# Grep for COSIGNER_ROTATED in BOTH client stderr and server journal.
# At least one should contain it (whichever process detected the
# mismatch first).
CLIENT_HIT=0
SERVER_HIT=0
grep -q "COSIGNER_ROTATED" /tmp/cosigner-stderr.log && CLIENT_HIT=1
journalctl -u mtc-ca.service --since "30 seconds ago" 2>/dev/null \
    | grep -q "COSIGNER_ROTATED" && SERVER_HIT=1

if [ "$CLIENT_HIT" = "1" ] || [ "$SERVER_HIT" = "1" ]; then
    src="$( [ "$CLIENT_HIT" = "1" ] && echo client; [ "$SERVER_HIT" = "1" ] && echo server )"
    ok "COSIGNER_ROTATED logged ($src)"
else
    ko "no COSIGNER_ROTATED log line in client stderr OR server journal"
fi

rm -f /tmp/cosigner-stderr.log /tmp/cosigner-stdout.log

# -- Summary -----------------------------------------------------------
printf '\n%sCosigner-rotation drill:%s pass=%d fail=%d\n' \
    "$c_cyan" "$c_off" "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
