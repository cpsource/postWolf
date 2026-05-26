#!/bin/bash
#
# redis-info.sh — show rate-limit counters per IP from Redis + recent journal activity
#

FMT="%-18s %-10s %-8s %6s / %-6s %8s\n"

# ── MTC CA/Log rate limits (rl:) ─────────────────────────────────────

printf "\n=== MTC CA/Log Rate Limits (rl:) ===\n\n"
printf "$FMT" "IP" "CATEGORY" "WINDOW" "COUNT" "MAX" "TTL"
printf "$FMT" "--" "--------" "------" "-----" "---" "---"

declare -A RL_NAME=( [0]="read" [1]="nonce-lf" [2]="nonce-ca" [3]="enroll" [4]="revoke" [5]="bootstrap" [6]="global" )
declare -A RL_MAX_M=( [0]=60 [1]=10 [2]=3 [3]=3 [4]=5 [5]=3 [6]=120 )
declare -A RL_MAX_H=( [0]=600 [1]=100 [2]=10 [3]=10 [4]=100 [5]=30 [6]=1200 )

rl_found=0
redis-cli keys 'rl:*' 2>/dev/null | sort | while read -r key; do
    ip=$(echo "$key" | cut -d: -f2)
    cat=$(echo "$key" | cut -d: -f3)
    win=$(echo "$key" | cut -d: -f4)

    count=$(redis-cli get "$key" 2>/dev/null)
    ttl=$(redis-cli ttl "$key" 2>/dev/null)

    name="${RL_NAME[$cat]:-cat-$cat}"
    if [[ "$win" == "m" ]]; then
        max="${RL_MAX_M[$cat]:-?}"
        window="min"
    else
        max="${RL_MAX_H[$cat]:-?}"
        window="hour"
    fi

    [[ "$ttl" -le 0 ]] && ttl="expired"

    printf "$FMT" "$ip" "$name" "$window" "$count" "$max" "${ttl}s"
done

# ── MQC socket rate limits (mqc:) ────────────────────────────────────

printf "\n=== MQC Socket Rate Limits (mqc:) ===\n\n"
printf "$FMT" "IP" "TYPE" "WINDOW" "COUNT" "MAX" "TTL"
printf "$FMT" "--" "----" "------" "-----" "---" "---"

declare -A MQC_MAX_CONN=( [m]=100 [h]=1000 )
declare -A MQC_MAX_FAIL=( [m]=10 [h]=100 [d]=300 )
declare -A MQC_MAX_CERT=( [m]=10 [h]=100 )
declare -A WIN_LABEL=( [m]="min" [h]="hour" [d]="day" )

redis-cli keys 'mqc:*' 2>/dev/null | sort | while read -r key; do
    ip=$(echo "$key" | cut -d: -f2)
    typ=$(echo "$key" | cut -d: -f3)
    win=$(echo "$key" | cut -d: -f4)

    # mqc:<ip>:abuse has no window suffix — handle separately
    if [[ "$typ" == "abuse" ]]; then
        continue
    fi

    ttype=$(redis-cli type "$key" 2>/dev/null)
    if [[ "$ttype" == "set" ]]; then
        count=$(redis-cli scard "$key" 2>/dev/null)
    else
        count=$(redis-cli get "$key" 2>/dev/null)
    fi
    ttl=$(redis-cli ttl "$key" 2>/dev/null)

    case "$typ" in
        conn) max="${MQC_MAX_CONN[$win]:-?}" ;;
        fail) max="${MQC_MAX_FAIL[$win]:-?}" ;;
        cert) max="${MQC_MAX_CERT[$win]:-?}" ;;
        *)    max="?" ;;
    esac

    window="${WIN_LABEL[$win]:-$win}"
    [[ "$ttl" -le 0 ]] && ttl="expired"

    printf "$FMT" "$ip" "$typ" "$window" "$count" "$max" "${ttl}s"
done

# ── AbuseIPDB score cache (mqc:<ip>:abuse) ───────────────────────────

ABUSE_FMT="%-18s %6s %8s\n"
abuse_keys=$(redis-cli keys 'mqc:*:abuse' 2>/dev/null)
if [[ -n "$abuse_keys" ]]; then
    printf "\n=== AbuseIPDB Score Cache ===\n\n"
    printf "$ABUSE_FMT" "IP" "SCORE" "TTL"
    printf "$ABUSE_FMT" "--" "-----" "---"
    echo "$abuse_keys" | sort | while read -r key; do
        ip=$(echo "$key" | cut -d: -f2)
        score=$(redis-cli get "$key" 2>/dev/null)
        ttl=$(redis-cli ttl "$key" 2>/dev/null)
        [[ "$ttl" -le 0 ]] && ttl="expired"
        printf "$ABUSE_FMT" "$ip" "$score" "${ttl}s"
    done
fi

# ── Global hits ──────────────────────────────────────────────────────

printf "\n=== Global Hits ===\n"
hits=$(redis-cli get hits 2>/dev/null)
printf "Total hits: %s\n" "${hits:-0}"

# ── Recent journal activity (last 24h) ───────────────────────────────

printf "\n=== Journal Activity (last 24h) ===\n"

JFMT="%-18s %6s %6s %6s  %-10s  %s\n"
printf "\n$JFMT" "IP" "FAIL" "DENY" "OK" "LAST-SEEN" "LAST-REASON"
printf "$JFMT" "--" "----" "----" "--" "---------" "-----------"

journalctl -u qshd --since "24 hours ago" --no-pager 2>/dev/null | \
awk '
/ratelimit_fail_record.*recorded for / {
    match($0, /recorded for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m)
    if (m[1]) {
        ip = m[1]
        fail[ip]++
        last_time[ip] = $1 " " $2 " " $3
        last_reason[ip] = "handshake-fail"
    }
}
/FAIL_RATE_LIMITED/ {
    match($0, /FAIL_RATE_LIMITED: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) failures ([^ ]+)/, m)
    if (m[1]) {
        ip = m[1]
        last_time[ip] = $1 " " $2 " " $3
        last_reason[ip] = "RATE-LIMITED " m[2]
    }
}
/DENIED by ACL/ {
    match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m)
    if (m[1]) {
        ip = m[1]
        deny[ip]++
        last_time[ip] = $1 " " $2 " " $3
        last_reason[ip] = "ACL-denied"
    }
}
/\[qshd\] accepted/ {
    match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m)
    if (m[1]) {
        ip = m[1]
        ok[ip]++
        last_time[ip] = $1 " " $2 " " $3
        last_reason[ip] = "accepted"
    }
}
/shell started/ {
    match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, m)
    if (!m[1]) next
    ip = m[1]
    last_reason[ip] = "shell-started"
}
END {
    for (ip in last_time) {
        f = fail[ip]+0
        d = deny[ip]+0
        o = ok[ip]+0
        printf "%-18s %6d %6d %6d  %-10s  %s\n", ip, f, d, o, last_time[ip], last_reason[ip]
    }
}
' | sort -t' ' -k4 -rn
printf "\n"
