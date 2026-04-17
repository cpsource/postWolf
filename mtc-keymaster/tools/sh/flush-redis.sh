#!/bin/bash
# flush-redis.sh — Clear all Redis rate-limit state
#
# Flushes the current Redis database, removing all MQC and HTTP
# rate-limit counters.  Useful after testing or when rate limits
# are blocking legitimate connections.
#
# Usage:  bash flush-redis.sh

redis-cli FLUSHDB
