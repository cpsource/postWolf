#!/bin/sh
# test-mqc-perf.sh — Phase 4g performance baseline.
#
# Captures current-state median + p95 + p99 wall-clock latency for
# `show-tpm --verify`, which is the canonical exerciser of MQC
# client-server handshakes (one TCP+ML-KEM+ML-DSA+Finished handshake
# per HTTP endpoint hit, several per invocation).  No "before"
# baseline was saved pre-Phase-1 cutover, so this is a snapshot-now:
# the value is to detect future regressions, not to assert against a
# prior number.
#
# `mqc --encode|--decode` is NOT used here even though that's what
# CI smoke roundtrips run -- it's pure local scrypt+AES-GCM and
# never touches the MQC server, so it would mis-measure pure crypto
# overhead instead of handshake cost.
#
# Output: stdout summary + a snapshot file at
# mtc-keymaster/perf/perf-snapshot-<date>.txt.
#
# Knobs:
#   PERF_N         default 10  (sequential show-tpm --verify runs;
#                              each is ~6-8 MQC handshakes)
#   TARGET_HOST    default factsorlie.com

set -u

PERF_N="${PERF_N:-10}"
TARGET_HOST="${TARGET_HOST:-factsorlie.com}"
TARGET_IP="${TARGET_IP:-$(getent ahostsv4 "$TARGET_HOST" | awk '/STREAM/{print $1; exit}')}"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PERF_DIR="$ROOT/mtc-keymaster/perf"
mkdir -p "$PERF_DIR"
SNAP="$PERF_DIR/perf-snapshot-$(date -u +%Y-%m-%d).txt"

c_cyan=$(printf '\033[36m'); c_dim=$(printf '\033[2m'); c_off=$(printf '\033[0m')
note() { printf '%s%s%s\n' "$c_dim" "$1" "$c_off"; }

# -- Pre-flight --------------------------------------------------------
printf '%s--- pre-flight%s\n' "$c_cyan" "$c_off"
if ! systemctl is-active --quiet mtc-ca.service; then
    printf 'FATAL mtc-ca.service is not active\n'; exit 2
fi
note "target=$TARGET_HOST  N=$PERF_N sequential roundtrips"

# Clear Redis so an early rate-limit doesn't pollute the timings.
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli del \
        "mqc:$TARGET_IP:conn:m" "mqc:$TARGET_IP:conn:h" \
        "mqc:$TARGET_IP:fail:m" "mqc:$TARGET_IP:fail:h" \
        "mqc:$TARGET_IP:cert:m" "mqc:$TARGET_IP:cert:h" \
        >/dev/null 2>&1 || true
fi

# Warmup: first run pays the cold-cache penalty (cert fetch +
# revocation cache populate + Augeas init).  Discard.
show-tpm --verify >/dev/null 2>&1

# -- Sample loop -------------------------------------------------------
printf '%s--- sampling %d show-tpm --verify runs%s\n' "$c_cyan" "$PERF_N" "$c_off"
SAMPLES=$(mktemp)
i=0
while [ "$i" -lt "$PERF_N" ]; do
    i=$((i+1))
    # Use python for monotonic-ms timing — `time(1)` rounds to ms and
    # shell math is awkward.
    ms=$(python3 -c "
import subprocess, time
t = time.monotonic()
subprocess.run(['show-tpm', '--verify'],
               capture_output=True, check=False)
print(int((time.monotonic() - t) * 1000))
")
    echo "$ms" >> "$SAMPLES"
done

# -- Stats -------------------------------------------------------------
N=$(wc -l < "$SAMPLES")
SORTED=$(sort -n "$SAMPLES")
MIN=$(echo "$SORTED" | head -1)
MAX=$(echo "$SORTED" | tail -1)
# median, p95, p99 via line indexing (1-based)
MED_IDX=$(((N + 1) / 2))
P95_IDX=$(((N * 95 + 99) / 100))      # ceil(N * 0.95)
P99_IDX=$(((N * 99 + 99) / 100))      # ceil(N * 0.99)
MED=$(echo "$SORTED" | sed -n "${MED_IDX}p")
P95=$(echo "$SORTED" | sed -n "${P95_IDX}p")
P99=$(echo "$SORTED" | sed -n "${P99_IDX}p")
SUM=$(awk '{s+=$1} END {print s}' "$SAMPLES")
MEAN=$((SUM / N))

# -- Report ------------------------------------------------------------
{
    printf 'MQC handshake latency snapshot (show-tpm --verify wall clock)\n'
    printf '=============================================================\n'
    printf 'date:     %s UTC\n' "$(date -u +%Y-%m-%dT%H:%M:%S)"
    printf 'host:     %s\n' "$(hostname)"
    printf 'target:   %s:%s\n' "$TARGET_HOST" "${TARGET_PORT:-8446}"
    printf 'commit:   %s\n' "$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf 'N:        %d (after 1 warmup, sequential)\n' "$N"
    printf '\n'
    printf 'min:      %5d ms\n' "$MIN"
    printf 'mean:     %5d ms\n' "$MEAN"
    printf 'median:   %5d ms\n' "$MED"
    printf 'p95:      %5d ms\n' "$P95"
    printf 'p99:      %5d ms\n' "$P99"
    printf 'max:      %5d ms\n' "$MAX"
    printf '\n'
    printf 'raw samples (sorted):\n'
    echo "$SORTED" | tr '\n' ' '; printf '\n'
} | tee "$SNAP"

rm -f "$SAMPLES"
printf '\n%ssaved snapshot to:%s %s\n' "$c_cyan" "$c_off" "$SNAP"
