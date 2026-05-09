#!/bin/bash
# End-to-end BEFORE/AFTER runner for wolfSSL issue #<ISSUE_N>.
#
# TEMPLATE: copy to issue-<ISSUE_N>/test.sh and replace placeholders
# listed in the `USER-FILL` section below.
#
# What this script does:
#   1. Ensures <SOURCE_FILE_RELATIVE> is clean (no patch applied).
#   2. Configures wolfSSL with <CFG_FLAGS>, then builds.
#   3. Builds the reproducer in this directory (issue-<ISSUE_N>-test).
#   4. BEFORE: runs the reproducer against the unpatched server,
#      pkill'ing the server between runs. Expected result: FAIL.
#   5. Applies issue-<ISSUE_N>.patch and rebuilds wolfSSL.
#   6. AFTER: runs the reproducer against the patched server.
#      Expected result: PASS.
#   7. Restores <SOURCE_FILE_RELATIVE> to its pre-script state.
#
# Exit code: 0 iff all expected outcomes match, 1 otherwise.

set -u

# ============== USER-FILL =================================================
ISSUE_N="<ISSUE_N>"                       # e.g. 10287
SOURCE_FILE_RELATIVE="<SOURCE_FILE_RELATIVE>"   # e.g. src/tls.c
CFG_FLAGS="<CFG_FLAGS>"                   # e.g. --enable-mlkem --enable-tls-mlkem-standalone --enable-pqc-hybrids
# Patch marker: a string that appears in the patched source so the
# script can detect whether the patch is currently applied. Use a
# comment the patch introduces, e.g. "issue #<ISSUE_N>".
PATCH_MARKER="issue #<ISSUE_N>"

# Reproducer run cases. Set up to 2. If the bug has only one mode,
# leave TEST_RUN_2_LABEL empty.
TEST_RUN_1_LABEL="<TEST_RUN_1_LABEL>"     # e.g. "Case 1 (hybrid-first)"
TEST_RUN_1_FLAG="<TEST_RUN_1_FLAG>"       # e.g. "--hybrid-first"
TEST_RUN_2_LABEL="<TEST_RUN_2_LABEL>"     # e.g. "Case 2 (pqc-first)" or ""
TEST_RUN_2_FLAG="<TEST_RUN_2_FLAG>"       # e.g. "--pqc-first" or ""

# Does the reproducer need an `examples/server/server` instance
# running? Set to 0 if the test is a pure-library reproducer that
# does not need the TCP server.
NEEDS_SERVER=1
PORT=11111
# ============== END USER-FILL =============================================

# Resolve repo root from this script's location. Layout is
#   <wolfssl-tree>/wolfssl-issues/issue-N/test.sh
# so the wolfSSL repo root is two levels up.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

TEST_BIN="$HERE/issue-${ISSUE_N}-test"
TEST_SRC="$HERE/issue-${ISSUE_N}-test.c"
PATCH="$HERE/issue-${ISSUE_N}.patch"
LIB_DIR="$REPO/src/.libs"
SERVER="$REPO/examples/server/server"
SRV_LOG="/tmp/wolfsrv-${ISSUE_N}.log"
CFG_LOG="/tmp/wolfssl-cfg-${ISSUE_N}.log"
BLD_LOG="/tmp/wolfssl-build-${ISSUE_N}.log"

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
bold()  { printf '\033[1m%s\033[0m'  "$*"; }

section() { echo; echo "==================== $* ===================="; }

kill_server() {
    [ "$NEEDS_SERVER" = "1" ] || return 0
    pkill -f "examples/server/server" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        if ! pgrep -f "examples/server/server" >/dev/null; then break; fi
        sleep 0.2
    done
}

# Remember whether the patch was already applied when we started so we
# can put the tree back exactly as we found it.
PATCH_PREEXISTING=0
if grep -q "$PATCH_MARKER" "$REPO/$SOURCE_FILE_RELATIVE" 2>/dev/null; then
    PATCH_PREEXISTING=1
fi

restore_tree() {
    kill_server
    echo
    echo "Restoring tree to pre-script state..."
    git -C "$REPO" checkout -- "$SOURCE_FILE_RELATIVE"
    if [ "$PATCH_PREEXISTING" = "1" ]; then
        git -C "$REPO" apply "$PATCH" || echo "  WARN: could not re-apply patch"
        make -C "$REPO" -j"$(nproc)" >"$BLD_LOG" 2>&1 \
            || echo "  WARN: final rebuild failed (see $BLD_LOG)"
    else
        make -C "$REPO" -j"$(nproc)" >"$BLD_LOG" 2>&1 || true
    fi
}
trap restore_tree EXIT

# ---------- build (unpatched) ----------

section "Reset $SOURCE_FILE_RELATIVE to clean state"
git -C "$REPO" checkout -- "$SOURCE_FILE_RELATIVE"
if grep -q "$PATCH_MARKER" "$REPO/$SOURCE_FILE_RELATIVE"; then
    echo "ERROR: $SOURCE_FILE_RELATIVE still has patch markers after checkout."
    exit 1
fi

section "Configure wolfSSL ($CFG_FLAGS)"
./configure $CFG_FLAGS >"$CFG_LOG" 2>&1 || {
    echo "configure failed; tail of $CFG_LOG:"
    tail -30 "$CFG_LOG"
    exit 1
}

section "Build wolfSSL (unpatched)"
make -j"$(nproc)" >"$BLD_LOG" 2>&1 || {
    echo "build failed; tail of $BLD_LOG:"
    tail -40 "$BLD_LOG"
    exit 1
}
echo "  libwolfssl built: $(ls -la $LIB_DIR/libwolfssl.so* 2>/dev/null | head -1)"

section "Build reproducer"
gcc -Wall -Wextra -I"$REPO" -L"$LIB_DIR" \
    "$TEST_SRC" -lwolfssl -lm -o "$TEST_BIN"
echo "  built $TEST_BIN"

# ---------- run helper ----------

# run_case <label> <flag>  ->  prints captured output, returns test exit code
run_case() {
    local label="$1" flag="$2"
    kill_server
    echo; echo "  --- $label ---"
    if [ "$NEEDS_SERVER" = "1" ]; then
        "$SERVER" -v 4 -p "$PORT" >"$SRV_LOG" 2>&1 &
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            grep -q "listening on port" "$SRV_LOG" && break
            sleep 0.2
        done
    fi
    if [ -n "$flag" ]; then
        LD_LIBRARY_PATH="$LIB_DIR" "$TEST_BIN" "$flag" 2>&1
    else
        LD_LIBRARY_PATH="$LIB_DIR" "$TEST_BIN" 2>&1
    fi
    local rc=$?
    echo "  reproducer exit = $rc"
    kill_server
    [ "$NEEDS_SERVER" = "1" ] && echo "  server log tail : $(tail -1 "$SRV_LOG")"
    return $rc
}

# ---------- BEFORE ----------

section "BEFORE (unpatched / buggy) — expected: FAIL"
run_case "$TEST_RUN_1_LABEL" "$TEST_RUN_1_FLAG"
RC_BEF_1=$?
RC_BEF_2=""
if [ -n "$TEST_RUN_2_LABEL" ]; then
    run_case "$TEST_RUN_2_LABEL" "$TEST_RUN_2_FLAG"
    RC_BEF_2=$?
fi

# ---------- apply patch ----------

section "Apply issue-${ISSUE_N}.patch and rebuild"
git -C "$REPO" apply "$PATCH" || {
    echo "git apply failed"
    exit 1
}
grep -c "$PATCH_MARKER" "$REPO/$SOURCE_FILE_RELATIVE" | xargs -I{} echo "  patch markers in $SOURCE_FILE_RELATIVE: {}"
make -j"$(nproc)" >"$BLD_LOG" 2>&1 || {
    echo "patched build failed; tail of $BLD_LOG:"
    tail -40 "$BLD_LOG"
    exit 1
}

# ---------- AFTER ----------

section "AFTER (patched) — expected: PASS"
run_case "$TEST_RUN_1_LABEL" "$TEST_RUN_1_FLAG"
RC_AFT_1=$?
RC_AFT_2=""
if [ -n "$TEST_RUN_2_LABEL" ]; then
    run_case "$TEST_RUN_2_LABEL" "$TEST_RUN_2_FLAG"
    RC_AFT_2=$?
fi

# ---------- summary ----------

section "Summary"
fmt_expected_fail() { [ "$1" != "0" ] && green "FAIL (expected)" || red "PASS (UNEXPECTED — bug did not trigger)"; }
fmt_expected_pass() { [ "$1"  = "0" ] && green "PASS (expected)" || red "FAIL (UNEXPECTED — fix did not hold)"; }

printf "  BEFORE  %-18s : " "$TEST_RUN_1_LABEL"; fmt_expected_fail "$RC_BEF_1"; echo
[ -n "$RC_BEF_2" ] && { printf "  BEFORE  %-18s : " "$TEST_RUN_2_LABEL"; fmt_expected_fail "$RC_BEF_2"; echo; }
printf "  AFTER   %-18s : " "$TEST_RUN_1_LABEL"; fmt_expected_pass "$RC_AFT_1"; echo
[ -n "$RC_AFT_2" ] && { printf "  AFTER   %-18s : " "$TEST_RUN_2_LABEL"; fmt_expected_pass "$RC_AFT_2"; echo; }

OK=1
[ "$RC_BEF_1" = "0" ] && OK=0
[ -n "$RC_BEF_2" ] && [ "$RC_BEF_2" = "0" ] && OK=0
[ "$RC_AFT_1" = "0" ] || OK=0
[ -n "$RC_AFT_2" ] && [ "$RC_AFT_2" != "0" ] && OK=0

if [ "$OK" = "1" ]; then
    echo; bold "Overall: all outcomes as expected."; echo
    exit 0
else
    echo; bold "Overall: at least one outcome was UNEXPECTED."; echo
    exit 1
fi
