#!/bin/bash
# show-redis.sh — Show all rate-limit state in Redis
#
# Displays all MQC and HTTP rate-limit keys with their current values.
#
# Usage:  bash show-redis.sh

echo "=== MQC rate limits ==="
for key in $(redis-cli KEYS "mqc:*" 2>/dev/null); do
    val=$(redis-cli GET "$key" 2>/dev/null)
    ttl=$(redis-cli TTL "$key" 2>/dev/null)
    printf "  %-40s  %s  (TTL %ss)\n" "$key" "$val" "$ttl"
done

echo
echo "=== HTTP rate limits ==="
for key in $(redis-cli KEYS "rl:*" 2>/dev/null); do
    val=$(redis-cli GET "$key" 2>/dev/null)
    ttl=$(redis-cli TTL "$key" 2>/dev/null)
    printf "  %-40s  %s  (TTL %ss)\n" "$key" "$val" "$ttl"
done
