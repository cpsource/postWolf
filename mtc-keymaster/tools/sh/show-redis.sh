#!/bin/bash
# show-redis.sh — Show all rate-limit state in Redis
#
# Displays all MQC and HTTP rate-limit keys with current values
# and their configured limits.
#
# Usage:  bash show-redis.sh

# MQC limits (from mqc.c)
mqc_limit() {
    case "$1" in
        *:conn:m) echo 100 ;;
        *:conn:h) echo 1000 ;;
        *:fail:m) echo 10 ;;
        *:fail:h) echo 100 ;;
        *)        echo "?" ;;
    esac
}

# HTTP limits (from mtc_ratelimit.c)
# Key format: rl:<ip>:<category>:<m|h>
# Categories: 0=read 1=nonce-leaf 2=nonce-ca 3=enroll 4=revoke 5=bootstrap 6=global
http_limit() {
    local cat="${1##*:}"   # m or h
    local tmp="${1%:*}"    # rl:<ip>:<cat>
    local num="${tmp##*:}" # category number
    if [ "$cat" = "m" ]; then
        case "$num" in
            0) echo 60 ;;   1) echo 10 ;;  2) echo 3 ;;
            3) echo 3 ;;    4) echo 2 ;;   5) echo 3 ;;
            6) echo 120 ;;  *) echo "?" ;;
        esac
    else
        case "$num" in
            0) echo 600 ;;  1) echo 100 ;; 2) echo 10 ;;
            3) echo 10 ;;   4) echo 100 ;; 5) echo 30 ;;
            6) echo 1200 ;; *) echo "?" ;;
        esac
    fi
}

http_name() {
    local tmp="${1%:*}"
    local num="${tmp##*:}"
    case "$num" in
        0) echo "read" ;;       1) echo "nonce-leaf" ;;
        2) echo "nonce-ca" ;;   3) echo "enroll" ;;
        4) echo "revoke" ;;     5) echo "bootstrap" ;;
        6) echo "global" ;;     *) echo "?" ;;
    esac
}

echo "=== MQC rate limits ==="
for key in $(redis-cli KEYS "mqc:*" 2>/dev/null); do
    val=$(redis-cli GET "$key" 2>/dev/null)
    ttl=$(redis-cli TTL "$key" 2>/dev/null)
    max=$(mqc_limit "$key")
    printf "  %-40s  %s/%s  (TTL %ss)\n" "$key" "$val" "$max" "$ttl"
done

echo
echo "=== HTTP rate limits ==="
for key in $(redis-cli KEYS "rl:*" 2>/dev/null); do
    val=$(redis-cli GET "$key" 2>/dev/null)
    ttl=$(redis-cli TTL "$key" 2>/dev/null)
    max=$(http_limit "$key")
    name=$(http_name "$key")
    printf "  %-40s  %s/%s  %-12s (TTL %ss)\n" "$key" "$val" "$max" "$name" "$ttl"
done
