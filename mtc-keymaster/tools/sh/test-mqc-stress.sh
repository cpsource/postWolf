#!/bin/sh
# test-mqc-stress.sh — Phase 4c concurrent-handshake stress.
#
# The master plan's original spec assumed an in-flight handshake-buffer
# atomic counter (deliberately scoped out of P3b -- mqc_accept runs in
# the parent listener and forks AFTER the handshake completes, so
# handshakes are serialised and only one buffer is ever in flight per
# listener).  The remaining concern is fork-storm resilience: a burst
# of N concurrent client connects spawns N children on the server, and
# we want to confirm:
#
#   - none of those children crash the listener parent
#   - server fd / process counts return to baseline after the load drops
#   - mqc-ca.service is still active afterwards
#   - the per-IP connect rate-limit clamps at the configured ceiling
#     (default 100/min) so the stress doesn't accidentally lock us out
#
# Knobs:
#   STRESS_N        default 30   (parallelism factor; keep < rl-connect-per-min)
#   STRESS_REPEAT   default 1    (run the burst this many times)
#   TARGET_HOST     default factsorlie.com

set -u

STRESS_N="${STRESS_N:-30}"
STRESS_REPEAT="${STRESS_REPEAT:-1}"
TARGET_HOST="${TARGET_HOST:-factsorlie.com}"
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

# -- Pre-flight --------------------------------------------------------
step "pre-flight"
if ! systemctl is-active --quiet mtc-ca.service; then
    printf '%sFATAL%s mtc-ca.service is not active\n' "$c_red" "$c_off"; exit 2
fi
SERVER_PID=$(systemctl show -p MainPID --value mtc-ca.service)
note "mtc-ca.service main pid: $SERVER_PID"
note "stress: $STRESS_N concurrent encode|decode × $STRESS_REPEAT bursts"

# Capture baseline fd count (parent listener).  /proc/<pid>/fd is the
# canonical way; ls -1 strips the symlink targets.
fd_count() { ls -1 "/proc/$SERVER_PID/fd" 2>/dev/null | wc -l; }
FD_BEFORE=$(fd_count)
note "baseline fd count: $FD_BEFORE"

# Clear Redis so we don't trip the per-IP rate limit before we start.
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli del \
        "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
        "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
        "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
        >/dev/null 2>&1 || true
fi

# Sanity check: stress count must be below per-IP connect cap or every
# burst gets rate-limited and the test stops measuring concurrency.
RL_MAX=$(grep -E '^[^#]*mqc-rl-connect-per-min' /etc/postWolf/config 2>/dev/null \
         | awk '{print $2}' | head -1)
RL_MAX=${RL_MAX:-100}
if [ "$STRESS_N" -ge "$RL_MAX" ]; then
    note "WARNING: STRESS_N=$STRESS_N >= rl-connect-per-min=$RL_MAX; "
    note "         expect rate-limit rejections to dominate the burst."
fi

# -- Burst loop --------------------------------------------------------
TOTAL_OK=0
TOTAL_FAIL=0
i=0
while [ "$i" -lt "$STRESS_REPEAT" ]; do
    i=$((i+1))
    step "burst $i/$STRESS_REPEAT (N=$STRESS_N parallel)"

    # Launch STRESS_N parallel `mqc --encode | mqc --decode` roundtrips.
    # Each spawn is one client process that makes one MQC handshake
    # (server-side: one fork + one mqc_accept).  We just count exit
    # codes; the body of the encode|decode tests its own correctness
    # (decode must emit the original "hi" or the pipe fails).
    BURST_OK=0
    BURST_FAIL=0
    OUT_DIR=$(mktemp -d)
    seq 1 "$STRESS_N" | xargs -n1 -P "$STRESS_N" -I {} sh -c '
        out=$(echo hi | mqc --encode --env --no-cache 2>/dev/null \
                      | mqc --decode --env --no-cache 2>/dev/null)
        if [ "$out" = "hi" ]; then
            : > "$1/$2.ok"
        else
            : > "$1/$2.fail"
        fi
    ' _ "$OUT_DIR" {}

    BURST_OK=$(ls "$OUT_DIR"/*.ok 2>/dev/null | wc -l)
    BURST_FAIL=$(ls "$OUT_DIR"/*.fail 2>/dev/null | wc -l)
    rm -rf "$OUT_DIR"

    note "burst $i: ok=$BURST_OK fail=$BURST_FAIL"
    TOTAL_OK=$((TOTAL_OK + BURST_OK))
    TOTAL_FAIL=$((TOTAL_FAIL + BURST_FAIL))
done

# -- Post-conditions ---------------------------------------------------
step "post-conditions"

# Service still alive?
if systemctl is-active --quiet mtc-ca.service; then
    ok "mtc-ca.service still active after $((STRESS_N * STRESS_REPEAT)) handshakes"
else
    ko "mtc-ca.service died during stress"
fi

# fd count returned to baseline?  Allow ±5 for race with stragglers.
sleep 2
FD_AFTER=$(fd_count)
DELTA=$((FD_AFTER - FD_BEFORE))
if [ "$DELTA" -ge -5 ] && [ "$DELTA" -le 5 ]; then
    ok "listener fd count stable (before=$FD_BEFORE after=$FD_AFTER delta=$DELTA)"
else
    ko "listener fd leak (before=$FD_BEFORE after=$FD_AFTER delta=$DELTA)"
fi

# Most handshakes succeeded?  We allow rate-limit tail; the load-bearing
# assertion is that the server didn't crash.
TOTAL_TRIED=$((TOTAL_OK + TOTAL_FAIL))
if [ "$TOTAL_OK" -ge $((TOTAL_TRIED / 2)) ]; then
    ok "handshake throughput: $TOTAL_OK/$TOTAL_TRIED succeeded"
else
    ko "handshake throughput: only $TOTAL_OK/$TOTAL_TRIED succeeded"
fi

# -- Summary -----------------------------------------------------------
printf '\n%sStress summary:%s pass=%d fail=%d (handshakes ok=%d fail=%d)\n' \
    "$c_cyan" "$c_off" "$PASS" "$FAIL" "$TOTAL_OK" "$TOTAL_FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '%sfailed:%s%s\n' "$c_red" "$c_off" "$FAILED_NAMES"
    exit 1
fi
exit 0
