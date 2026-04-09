/* mtc_ratelimit.c — Redis-backed per-IP rate limiting.
 *
 * Uses Redis INCR + EXPIRE for sliding window counters.
 * Two keys per IP per category: one for per-minute, one for per-hour.
 *
 * Key format: rl:<ip>:<category>:m  (per-minute, TTL 60s)
 *             rl:<ip>:<category>:h  (per-hour, TTL 3600s)
 */

#include "mtc_ratelimit.h"
#include "mtc_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

/* Per-minute and per-hour limits for each category */
static const struct {
    int per_min;
    int per_hour;
    const char *name;
} s_limits[RL_NUM_CATEGORIES] = {
    [RL_READ]       = {  60,  600, "read"       },
    [RL_NONCE_LEAF] = {  10,  100, "nonce-leaf"  },
    [RL_NONCE_CA]   = {   3,   10, "nonce-ca"    },
    [RL_ENROLL]     = {   3,   10, "enroll"      },
    [RL_REVOKE]     = {   2,    5, "revoke"      },
    [RL_GLOBAL]     = { 120, 1200, "global"      },
};

static redisContext *s_redis = NULL;

int mtc_ratelimit_init(const char *redis_host, int redis_port)
{
    struct timeval timeout = { 1, 0 }; /* 1 second */

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

void mtc_ratelimit_close(void)
{
    if (s_redis) {
        redisFree(s_redis);
        s_redis = NULL;
    }
}

/* Check one key: INCR + EXPIRE. Returns the current count. */
static int check_key(const char *key, int ttl_secs)
{
    redisReply *reply;
    int count;

    reply = redisCommand(s_redis, "INCR %s", key);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        if (reply) freeReplyObject(reply);
        return 0; /* Redis error — allow the request */
    }
    count = (int)reply->integer;
    freeReplyObject(reply);

    /* Set TTL only on the first increment (count == 1) */
    if (count == 1) {
        reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
        if (reply) freeReplyObject(reply);
    }

    return count;
}

int mtc_ratelimit_check(const char *ip, int category)
{
    char key_m[128], key_h[128];
    char gkey_m[128], gkey_h[128];
    int count_m, count_h, gcount_m, gcount_h;

    if (!s_redis || !ip || !ip[0])
        return 1; /* no Redis — allow */

    if (category < 0 || category >= RL_NUM_CATEGORIES)
        return 1;

    /* Category-specific check */
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

    /* Global per-IP check */
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
