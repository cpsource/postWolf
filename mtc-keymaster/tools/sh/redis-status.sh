#!/usr/bin/env bash
#
# redis-status — dump the docker "redis" container's keyspace with
# human-readable rate-limit budgets annotated per key.
#
# Produces one line per redis key:
#   <key>   <current count>   <limit + window + category>
#
# Categories come from mtc-keymaster/server2/c/mtc_ratelimit.c:52-59;
# if you change that table, update the case arms here too.  Category
# numbers match the RL_* enum order in mtc_ratelimit.h.
#
# Usage:
#   redis-status
#   watch -n 1 redis-status     # live tail
#
# Dependencies:
#   - docker daemon running
#   - a container named "redis" (see factsorlie/docker-compose.yml)
#
set -euo pipefail

# Allow overriding the container name for alt deployments.
CONTAINER="${REDIS_CONTAINER:-redis}"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "redis-status: container '$CONTAINER' not found" >&2
    echo "  (override with REDIS_CONTAINER=<name>)" >&2
    exit 1
fi

docker exec "$CONTAINER" sh -c '
  redis-cli KEYS "*" | while read k; do
    v=$(redis-cli GET "$k")
    case "$k" in
      rl:*:0:m) max="60 /min  RL_READ"        ;;
      rl:*:0:h) max="600 /hr  RL_READ"        ;;
      rl:*:1:m) max="10 /min  RL_NONCE_LEAF"  ;;
      rl:*:1:h) max="100 /hr  RL_NONCE_LEAF"  ;;
      rl:*:2:m) max="3 /min  RL_NONCE_CA"     ;;
      rl:*:2:h) max="10 /hr  RL_NONCE_CA"     ;;
      rl:*:3:m) max="3 /min  RL_ENROLL"       ;;
      rl:*:3:h) max="10 /hr  RL_ENROLL"       ;;
      rl:*:4:m) max="2 /min  RL_REVOKE"       ;;
      rl:*:4:h) max="100 /hr  RL_REVOKE"      ;;
      rl:*:5:m) max="3 /min  RL_BOOTSTRAP"    ;;
      rl:*:5:h) max="30 /hr  RL_BOOTSTRAP"    ;;
      rl:*:6:m) max="120 /min  RL_GLOBAL"     ;;
      rl:*:6:h) max="1200 /hr  RL_GLOBAL"     ;;
      mqc:*)    max="(no cap, observability)" ;;
      hits)     max="(Flask index counter)"   ;;
      *)        max=""                        ;;
    esac
    printf "%-42s %6s   %s\n" "$k" "$v" "$max"
  done | sort
'
