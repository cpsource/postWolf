/******************************************************************************
 * File:        mtc_ratelimit.c
 * Purpose:     Redis-backed per-IP rate limiting for the MTC CA server.
 *
 * Description:
 *   Implements sliding-window rate limiting using Redis INCR + EXPIRE
 *   counters.  Each request increments two Redis keys per category
 *   (per-minute and per-hour), plus two more for the global per-IP
 *   limit.  TTLs are set on the first increment so counters expire
 *   automatically.
 *
 *   Key format:
 *     rl:<ip>:<category>:m  — per-minute counter (TTL 60s)
 *     rl:<ip>:<category>:h  — per-hour counter (TTL 3600s)
 *
 *   If Redis is unavailable (connection failure or runtime error), all
 *   requests are allowed (fail-open policy).
 *
 * Dependencies:
 *   mtc_ratelimit.h
 *   mtc_log.h
 *   stdio.h, stdlib.h, string.h
 *   hiredis/hiredis.h   (Redis C client)
 *
 * Notes:
 *   - NOT thread-safe.  s_redis is file-scoped static.
 *   - Fail-open: Redis errors never block legitimate traffic.
 *   - Counters are always incremented, even when the request is denied,
 *     to prevent burst abuse after a limit reset.
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_ratelimit.h"
#include "mtc_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

/******************************************************************************
 * Rate limit configuration table.
 *
 * Indexed by RL_* category constants.  Each entry defines the per-minute
 * and per-hour limits and a human-readable name for log messages.
 ******************************************************************************/
static const struct {
    int per_min;          /**< Maximum requests per 60-second window  */
    int per_hour;         /**< Maximum requests per 3600-second window */
    const char *name;     /**< Category name for log output            */
} s_limits[RL_NUM_CATEGORIES] = {
    [RL_READ]       = {  60,  600, "read"       },
    [RL_NONCE_LEAF] = {  10,  100, "nonce-leaf"  },
    [RL_NONCE_CA]   = {   3,   10, "nonce-ca"    },
    [RL_ENROLL]     = {   3,   10, "enroll"      },
    [RL_REVOKE]     = {   2,    5, "revoke"      },
    [RL_BOOTSTRAP]  = {   3,   30, "bootstrap"   },
    [RL_GLOBAL]     = { 120, 1200, "global"      },
};

static redisContext *s_redis = NULL;  /**< Redis connection (NULL = disabled) */

/******************************************************************************
 * Function:    mtc_ratelimit_init
 *
 * Description:
 *   Connects to Redis with a 1-second timeout.  On failure, logs a
 *   warning and disables rate limiting (fail-open).
 *
 * Input Arguments:
 *   redis_host  - Redis hostname.  NULL defaults to "127.0.0.1".
 *   redis_port  - Redis port.  <= 0 defaults to 6379.
 *
 * Returns:
 *    0  on success (Redis connected).
 *   -1  on connection failure (rate limiting disabled).
 *
 * Side Effects:
 *   Sets s_redis.  Logs connection status.
 ******************************************************************************/
int mtc_ratelimit_init(const char *redis_host, int redis_port)
{
    struct timeval timeout = { 1, 0 }; /* 1-second connect timeout */

    if (!redis_host) redis_host = "127.0.0.1";
    if (redis_port <= 0) redis_port = 6379;

    s_redis = redisConnectWithTimeout(redis_host, redis_port, timeout);
    if (!s_redis || s_redis->err) {
        LOG_WARN("Redis connect failed: %s — rate limiting disabled",
                 s_redis ? s_redis->errstr : "NULL");
        if (s_redis) {
            redisFree(s_redis);
            s_redis = NULL;
        }
        return -1;
    }

    LOG_INFO("rate limiter connected to Redis %s:%d", redis_host, redis_port);
    return 0;
}

/******************************************************************************
 * Function:    mtc_ratelimit_close
 *
 * Description:
 *   Closes the Redis connection and sets s_redis to NULL.
 *   No-op if not initialised or already closed.
 ******************************************************************************/
void mtc_ratelimit_close(void)
{
    if (s_redis) {
        redisFree(s_redis);
        s_redis = NULL;
    }
}

/******************************************************************************
 * Function:    check_key
 *
 * Description:
 *   Atomically increments a Redis counter key and sets its TTL on the
 *   first increment (count == 1).  This implements the sliding window:
 *   the key auto-expires after ttl_secs, resetting the counter.
 *
 * Input Arguments:
 *   key       - Redis key string (e.g. "rl:1.2.3.4:0:m").
 *   ttl_secs  - TTL in seconds (60 for per-minute, 3600 for per-hour).
 *
 * Returns:
 *   Current counter value after increment (>= 1).
 *   0 on Redis error (fail-open — caller should allow the request).
 ******************************************************************************/
static int check_key(const char *key, int ttl_secs)
{
    redisReply *reply;
    int count;

    reply = redisCommand(s_redis, "INCR %s", key);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        if (reply) freeReplyObject(reply);
        return 0; /* Redis error — fail-open */
    }
    count = (int)reply->integer;
    freeReplyObject(reply);

    /* Set TTL only on first increment so the window starts from the
     * first request, not from some arbitrary point */
    if (count == 1) {
        reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
        if (reply) freeReplyObject(reply);
    }

    return count;
}

/******************************************************************************
 * Function:    mtc_ratelimit_check
 *
 * Description:
 *   Checks whether a request from the given IP is allowed under both
 *   the category-specific and global per-IP rate limits.  Increments
 *   four Redis counters (category minute + hour, global minute + hour)
 *   and compares against the configured thresholds.
 *
 *   If Redis is not connected, or ip is NULL/empty, or category is
 *   invalid, the request is always allowed (fail-open).
 *
 * Input Arguments:
 *   ip        - Client IP address string.
 *   category  - Rate limit category (RL_READ..RL_REVOKE).
 *
 * Returns:
 *   1  if allowed.
 *   0  if rate-limited (category or global limit exceeded).
 *
 * Side Effects:
 *   Increments Redis counters (even when denying the request).
 *   Logs rate limit hits at INFO level.
 ******************************************************************************/
int mtc_ratelimit_check(const char *ip, int category)
{
    char key_m[128], key_h[128];
    char gkey_m[128], gkey_h[128];
    int count_m, count_h, gcount_m, gcount_h;

    if (!s_redis || !ip || !ip[0])
        return 1; /* no Redis or no IP — fail-open */

    if (category < 0 || category >= RL_NUM_CATEGORIES)
        return 1;

    /* Category-specific counters */
    snprintf(key_m, sizeof(key_m), "rl:%s:%d:m", ip, category);
    snprintf(key_h, sizeof(key_h), "rl:%s:%d:h", ip, category);

    count_m = check_key(key_m, 60);
    count_h = check_key(key_h, 3600);

    if (count_m > s_limits[category].per_min) {
        LOG_INFO("rate limit hit: %s %s %d/min (limit %d)",
                 ip, s_limits[category].name, count_m,
                 s_limits[category].per_min);
        return 0;
    }
    if (count_h > s_limits[category].per_hour) {
        LOG_INFO("rate limit hit: %s %s %d/hour (limit %d)",
                 ip, s_limits[category].name, count_h,
                 s_limits[category].per_hour);
        return 0;
    }

    /* Global per-IP counters (always checked in addition to category) */
    snprintf(gkey_m, sizeof(gkey_m), "rl:%s:%d:m", ip, RL_GLOBAL);
    snprintf(gkey_h, sizeof(gkey_h), "rl:%s:%d:h", ip, RL_GLOBAL);

    gcount_m = check_key(gkey_m, 60);
    gcount_h = check_key(gkey_h, 3600);

    if (gcount_m > s_limits[RL_GLOBAL].per_min) {
        LOG_INFO("rate limit hit: %s global %d/min (limit %d)",
                 ip, gcount_m, s_limits[RL_GLOBAL].per_min);
        return 0;
    }
    if (gcount_h > s_limits[RL_GLOBAL].per_hour) {
        LOG_INFO("rate limit hit: %s global %d/hour (limit %d)",
                 ip, gcount_h, s_limits[RL_GLOBAL].per_hour);
        return 0;
    }

    return 1; /* allowed */
}
