#!/bin/sh
# test-mqc-all.sh — aggregate MQC regression suite (Phase 4a).
#
# Runs every per-issue test from Phases 1-3 against a live MQC
# listener and exits 0 only if all pass.  Designed to be invoked
# via `make -f Makefile.tools test-mqc-all`.
#
# Pre-requisites (CI / dev box):
#   - mtc-ca.service active on TARGET_HOST:8446
#   - Redis on 127.0.0.1:6379 (matches mqc.c default)
#   - ~/.TPM/<DOMAIN>/ identity present for the smoke roundtrip
#     (defaults to factsorlie.com)
#   - tests/test_name_check + attack-port-8446 + attack-port-8445
#     built (handled by make dependency)
#
# Knobs (env):
#   TARGET_HOST     default factsorlie.com
#   TARGET_PORT     default 8446
#   TARGET_IP       default $(getent ahostsv4 TARGET_HOST | awk '/STREAM/{print $1; exit}')
#                   — used to clear the right per-IP rate-limit keys
#   DOMAIN          default factsorlie.com
#   SKIP_ATTACK_PACK   set to 1 to skip attack-port-844[56]
#   SKIP_NAME_CHECK    set to 1 to skip tests/test_name_check
#   QUIET           set to 1 to suppress per-step chatter

set -u

TARGET_HOST="${TARGET_HOST:-factsorlie.com}"
TARGET_PORT="${TARGET_PORT:-8446}"
DOMAIN="${DOMAIN:-factsorlie.com}"
TARGET_IP="${TARGET_IP:-$(getent ahostsv4 "$TARGET_HOST" | awk '/STREAM/{print $1; exit}')}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MQC_TESTS="$ROOT/socket-level-wrapper-MQC/tests"

PASS=0
FAIL=0
FAILED_NAMES=""

c_green=$(printf '\033[32m'); c_red=$(printf '\033[31m')
c_cyan=$(printf '\033[36m'); c_dim=$(printf '\033[2m'); c_off=$(printf '\033[0m')

step() { [ "${QUIET:-0}" = "1" ] || printf '%s--- %s%s\n' "$c_cyan" "$1" "$c_off"; }
ok()   { PASS=$((PASS+1)); printf '%sPASS%s %s\n' "$c_green" "$c_off" "$1"; }
ko()   { FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES $1"; printf '%sFAIL%s %s\n' "$c_red" "$c_off" "$1"; }
note() { [ "${QUIET:-0}" = "1" ] || printf '%s%s%s\n' "$c_dim" "$1" "$c_off"; }

# -- Pre-flight ---------------------------------------------------------
step "pre-flight"

if ! systemctl is-active --quiet mtc-ca.service; then
    printf '%sFATAL%s mtc-ca.service is not active; cannot run regression suite\n' \
        "$c_red" "$c_off"
    exit 2
fi
ok "mtc-ca.service is active"

if [ -z "$TARGET_IP" ]; then
    printf '%sFATAL%s could not resolve %s\n' "$c_red" "$c_off" "$TARGET_HOST"
    exit 2
fi
note "target=$TARGET_HOST:$TARGET_PORT  ip=$TARGET_IP  domain=$DOMAIN"

# Redis: clear the per-IP / per-cert state so prior runs don't pollute
# rate-limit counters mid-suite.  Best-effort; missing redis-cli isn't fatal.
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli del \
        "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
        "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
        "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
        >/dev/null 2>&1 || true
    note "cleared Redis rate-limit keys for $TARGET_IP"
fi

# -- Smoke: roundtrip happy path ---------------------------------------
step "smoke: mqc encode | mqc decode roundtrip"

OUT=$(echo hi | mqc --encode --env --no-cache 2>/dev/null \
              | mqc --decode --env --no-cache 2>/dev/null)
if [ "$OUT" = "hi" ]; then
    ok "encode|decode roundtrip"
else
    ko "encode|decode roundtrip (got '$OUT', expected 'hi')"
fi

# -- P2c: name-check negatives -----------------------------------------
if [ "${SKIP_NAME_CHECK:-0}" != "1" ] && [ -x "$MQC_TESTS/test_name_check" ]; then
    step "P2c: tests/test_name_check (issue #9)"
    if "$MQC_TESTS/test_name_check" \
        --tpm "$HOME/.TPM/$DOMAIN" \
        --server "$TARGET_HOST:$TARGET_PORT" \
        --host   "$TARGET_HOST" \
        --port   "$TARGET_PORT" >/tmp/test_name_check.out 2>&1
    then
        ok "test_name_check (3/3 negatives rejected)"
    else
        ko "test_name_check"
        sed -n '1,40p' /tmp/test_name_check.out | sed 's/^/    | /'
    fi
fi

# -- P1/P3a/P3b: attack-port-8446 fuzz pack ----------------------------
if [ "${SKIP_ATTACK_PACK:-0}" != "1" ] && command -v attack-port-8446 >/dev/null 2>&1; then
    step "P1+P3a+P3b: attack-port-8446 (~80 wire attacks against MQC)"
    # Clear rate-limit state again — name-check just generated 3 fails,
    # which would skew the attack pack's per-IP fail bucket.
    if command -v redis-cli >/dev/null 2>&1; then
        redis-cli del \
            "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
            "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
            "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
            >/dev/null 2>&1 || true
    fi
    if attack-port-8446 -s "$TARGET_HOST" -p "$TARGET_PORT" \
        >/tmp/attack-port-8446.out 2>&1
    then
        # attack-port-8446 returns 0 only when every probe got a clean
        # close/reply within 10s.  A non-zero exit means a probe hung
        # or the server stopped accepting — both are real regressions.
        ok "attack-port-8446 (no hangs, no connect failures)"
    else
        ko "attack-port-8446 (exit $?)"
        tail -20 /tmp/attack-port-8446.out | sed 's/^/    | /'
    fi
fi

# -- attack-port-8445 fuzz pack (DH bootstrap) -------------------------
# The bootstrap port has its own strict-parse + endpoint-allowlist
# surface (TODOs #66/#67/#69).  attack-port-8445 reads the bootstrap
# URL from /etc/postWolf/config rather than taking -s/-p; uses
# BOOTSTRAP_HOST/BOOTSTRAP_PORT env knobs to override (defaults
# track url-bootstrap from the operator's config).
if [ "${SKIP_ATTACK_PACK:-0}" != "1" ] && command -v attack-port-8445 >/dev/null 2>&1; then
    step "attack-port-8445 (~22 wire attacks against DH bootstrap)"
    if attack-port-8445 >/tmp/attack-port-8445.out 2>&1
    then
        ok "attack-port-8445 (no hangs, no connect failures)"
    else
        ko "attack-port-8445 (exit $?)"
        tail -20 /tmp/attack-port-8445.out | sed 's/^/    | /'
    fi
fi

# -- Summary ------------------------------------------------------------
printf '\n%sSummary:%s pass=%d fail=%d\n' "$c_cyan" "$c_off" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '%sfailed:%s%s\n' "$c_red" "$c_off" "$FAILED_NAMES"
    exit 1
fi

# ---------------------------------------------------------------------
# Optional follow-up steps (NOT run automatically — they mutate the
# production log).
#
#   1. End-to-end /revoke matrix:
#          mtc-keymaster/tests/run-revoke-matrix.sh
#      Enrols a sacrificial bob-revoke-test-<timestamp> leaf, walks
#      the 9-row attack matrix + 1 positive revoke + a verify_persisted
#      bootstrap GET.  Takes ~2 min and adds one permanent row to
#      mtc_log_entries (a revoked leaf at the next index).
#
#   2. Garbage-collect the sacrificial leaf afterward:
#          cleanup-tpm --index <NEW_INDEX> --full --yes
#      Runs on factsorlie only.  Stops mtc-ca.service, removes the
#      cert + log row + revocation row + matching ~/.TPM/ dir from
#      Neon, TRUNCATEs the tile tables, runs mtc_rebuild_tiles, and
#      restarts the service.  Leaves the log a row shorter than before
#      the matrix run (so calling test-mqc-all.sh + run-revoke-matrix +
#      cleanup-tpm in sequence is row-count-neutral).
#
#   Skip these if you don't want the production log mutated.
# ---------------------------------------------------------------------

exit 0
