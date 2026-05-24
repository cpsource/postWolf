/******************************************************************************
 * File:        mqc_ratelimit.c
 * Purpose:     Redis-backed per-IP and per-(IP, cert_index) rate-limit gates
 *              + the accept-side prologue that runs AbuseIPDB and rate-limit
 *              checks before any post-quantum work.
 *
 * Description:
 *   Split out of mqc_common.c so MQC clients (qsh, fips-manifest-*,
 *   fetch-publisher-key, ...) don't transitively drag libhiredis into
 *   their link.  The mqc_accept_prologue() entrypoint lives here too —
 *   it's the only call-site for mqc_abuse_check() and the rate-limit
 *   gates, so co-locating it keeps the dependency chain confined to the
 *   server-only translation units that already call it (mqc_clear_accept.o,
 *   mqc_encrypted_accept.o, mqc_accept_auto.o).
 *
 * Dependencies:
 *   libhiredis
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <hiredis/hiredis.h>

static redisContext *s_redis = NULL;

/* Cross-fork "Redis-down since when" state.
 *
 * The MQC server forks per-accept, so process-local state can't tell
 * a child "Redis has been down for K seconds across the last M
 * connections" — each child only sees its own one connect attempt.
 * A tiny tmpfile (default /tmp/postWolf-mqc-redis-down, override via
 * config knob mqc-rl-redis-state-path) gives us shared state with
 * zero fork-time setup: each child reads on Redis-down, the first
 * child writes "now", siblings read it; whichever child sees Redis
 * back up unlinks it.  Writes race benignly — values converge within
 * a few seconds and the policy decision tolerates jitter on that
 * scale.  Used by mqc_redis_down_decide() below. */

typedef enum {
    MQC_REDIS_DECISION_OPEN,
    MQC_REDIS_DECISION_CLOSED
} mqc_redis_decision_t;

static time_t mqc_redis_get_down_since(void)
{
    FILE *f = fopen(mqc_rt_cfg()->redis_state_path, "r");
    long ts = 0;
    if (!f) return 0;
    if (fscanf(f, "%ld", &ts) != 1) ts = 0;
    fclose(f);
    return (time_t)ts;
}

static void mqc_redis_mark_down(void)
{
    FILE *f;
    if (mqc_redis_get_down_since() != 0) return;  /* already marked */
    f = fopen(mqc_rt_cfg()->redis_state_path, "w");
    if (!f) return;                                /* best effort */
    fprintf(f, "%ld\n", (long)time(NULL));
    fclose(f);
}

static void mqc_redis_mark_up(void)
{
    /* Idempotent and racy on purpose: an unlink of a missing path
     * is a cheap ENOENT, and concurrent unlinks all converge. */
    unlink(mqc_rt_cfg()->redis_state_path);
}

/* Caller has already determined Redis is unreachable for this
 * request.  Returns the policy decision and (if @p out_dt is non-
 * NULL) the seconds-since-first-down value the caller can include
 * in its log line. */
static mqc_redis_decision_t mqc_redis_down_decide(time_t *out_dt)
{
    int p = mqc_rt_cfg()->redis_fail_policy;
    time_t down_since;
    time_t dt;

    mqc_redis_mark_down();
    down_since = mqc_redis_get_down_since();
    dt = down_since ? (time(NULL) - down_since) : 0;
    if (dt < 0) dt = 0;                            /* clock jump */
    if (out_dt) *out_dt = dt;

    if (p == MQC_REDIS_FAIL_POLICY_OPEN)
        return MQC_REDIS_DECISION_OPEN;
    if (p == MQC_REDIS_FAIL_POLICY_CLOSED)
        return MQC_REDIS_DECISION_CLOSED;
    /* CLOSED_AFTER */
    return (dt < mqc_rt_cfg()->redis_fail_closed_after_sec)
        ? MQC_REDIS_DECISION_OPEN
        : MQC_REDIS_DECISION_CLOSED;
}

void mqc_redis_init(void)
{
    struct timeval timeout = { 1, 0 };
    if (s_redis) return;  /* already connected */

    s_redis = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (!s_redis || s_redis->err) {
        /* Promoted from MQC_LOG to MQC_SECURITY: every gate that
         * relies on Redis (per-IP RL, per-IP fail RL, per-(IP,
         * cert) RL, fail-recording) silently fails OPEN when
         * Redis is unreachable.  Operators need to see this in
         * the journal — without it, an attacker who DoSes Redis
         * disables rate limiting invisibly. */
        MQC_SECURITY("REDIS_DOWN: connect failed: %s — every "
                     "rate-limit gate is now FAIL-OPEN until Redis "
                     "comes back",
                     s_redis ? s_redis->errstr : "NULL context");
        if (s_redis) { redisFree(s_redis); s_redis = NULL; }
    } else {
        MQC_LOG("Redis connected for rate limiting");
    }
}

int mqc_redis_incr(const char *key, int ttl_secs)
{
    redisReply *reply;
    int count;

    if (!s_redis) return 0;

    reply = redisCommand(s_redis, "INCR %s", key);
    if (!reply || reply->type != REDIS_REPLY_INTEGER) {
        /* Promoted from MQC_LOG: an in-flight INCR failure is
         * a Redis-side problem (server crash mid-pipeline,
         * connection reset).  Caller treats the 0 return as
         * "no count" → its rate-limit comparison can never
         * exceed the threshold → fail-open.  Operators need
         * the loud line. */
        MQC_SECURITY("RL_FAIL_OPEN: Redis INCR failed for key=%s "
                     "— gate is fail-open for this request", key);
        if (reply) freeReplyObject(reply);
        return 0;
    }
    count = (int)reply->integer;
    freeReplyObject(reply);

    if (count == 1) {
        reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
        if (reply) freeReplyObject(reply);
    }
    return count;
}

/* Check rate limit for a connection attempt. Returns 0 = OK, -1 = reject. */
int mqc_ratelimit_check(const char *ip)
{
    char key[128];
    int count_m, count_h;

    {
        long _t = mqc_now_ms();
        mqc_redis_init();
        if (mqc_get_time_enabled())
            fprintf(stderr, "[MQC-TIME]   redis_init = %ld ms\n",
                    mqc_now_ms() - _t);
    }
    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-IP connect-rate gate "
                         "enforced, Redis down %lds (ip=%s) — "
                         "rejecting connection per "
                         "mqc-rl-redis-fail-policy",
                         (long)dt, ip);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-IP connect-rate gate disabled, "
                     "Redis down %lds (ip=%s)", (long)dt, ip);
        return 0;
    }
    mqc_redis_mark_up();

    /* Per-minute */
    snprintf(key, sizeof(key), "mqc:%s:conn:m", ip);
    {
        long _t = mqc_now_ms();
        count_m = mqc_redis_incr(key, 60);
        if (mqc_get_time_enabled())
            fprintf(stderr, "[MQC-TIME]   redis_incr_m = %ld ms\n",
                    mqc_now_ms() - _t);
    }

    /* Per-hour */
    snprintf(key, sizeof(key), "mqc:%s:conn:h", ip);
    {
        long _t = mqc_now_ms();
        count_h = mqc_redis_incr(key, 3600);
        if (mqc_get_time_enabled())
            fprintf(stderr, "[MQC-TIME]   redis_incr_h = %ld ms\n",
                    mqc_now_ms() - _t);
    }

    {
        long _t = mqc_now_ms();
        const struct mqc_runtime_cfg *cfg = mqc_rt_cfg();
        if (mqc_get_time_enabled())
            fprintf(stderr, "[MQC-TIME]   rt_cfg = %ld ms\n",
                    mqc_now_ms() - _t);
        (void)cfg;
    }

    if (count_m > mqc_rt_cfg()->rl_connect_per_min) {
        MQC_SECURITY("RATE_LIMITED: %s connect %d/min (max %ld)",
                     ip, count_m, mqc_rt_cfg()->rl_connect_per_min);
        return -1;
    }
    if (count_h > mqc_rt_cfg()->rl_connect_per_hour) {
        MQC_SECURITY("RATE_LIMITED: %s connect %d/hr (max %ld)",
                     ip, count_h, mqc_rt_cfg()->rl_connect_per_hour);
        return -1;
    }
    return 0;
}

/* Check if IP has too many recent failures (does NOT increment).
 * Returns 0 = OK, -1 = too many failures. */
int mqc_ratelimit_fail_check(const char *ip)
{
    char key[128];
    redisReply *reply;
    int count_m = 0, count_h = 0, count_d = 0;

    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-IP fail-rate gate "
                         "enforced, Redis down %lds (ip=%s) — "
                         "rejecting connection",
                         (long)dt, ip);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-IP fail-rate gate disabled, "
                     "Redis down %lds (ip=%s)", (long)dt, ip);
        return 0;
    }

    snprintf(key, sizeof(key), "mqc:%s:fail:m", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) { if (reply->str) count_m = atoi(reply->str); freeReplyObject(reply); }

    snprintf(key, sizeof(key), "mqc:%s:fail:h", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) { if (reply->str) count_h = atoi(reply->str); freeReplyObject(reply); }

    snprintf(key, sizeof(key), "mqc:%s:fail:d", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) { if (reply->str) count_d = atoi(reply->str); freeReplyObject(reply); }

    if (count_m >= mqc_rt_cfg()->rl_fail_per_min ||
        count_h >= mqc_rt_cfg()->rl_fail_per_hour ||
        count_d >= mqc_rt_cfg()->rl_fail_per_day) {
        MQC_SECURITY("FAIL_RATE_LIMITED: %s failures %d/min %d/hr %d/day",
                     ip, count_m, count_h, count_d);
        return -1;
    }
    return 0;
}

/* Record a failed handshake (increment counters). */
void mqc_ratelimit_fail_record(const char *ip)
{
    char key[128];

    if (!s_redis) {
        /* Recording side has nothing to fail-closed against — the
         * connection is already failing, we just can't record it.
         * One MQC_SECURITY line is enough; no decide() call. */
        MQC_SECURITY("RL_FAIL_OPEN: failure-recording disabled, "
                     "Redis unreachable (ip=%s) — this handshake "
                     "failure will NOT count toward future fail-rate "
                     "checks, even after Redis comes back", ip);
        return;
    }

    snprintf(key, sizeof(key), "mqc:%s:fail:m", ip);
    mqc_redis_incr(key, 60);

    snprintf(key, sizeof(key), "mqc:%s:fail:h", ip);
    mqc_redis_incr(key, 3600);

    snprintf(key, sizeof(key), "mqc:%s:fail:d", ip);
    mqc_redis_incr(key, 86400);

    MQC_SECURITY("handshake failure recorded for %s", ip);
}

/* --- AbuseIPDB score cache --------------------------------------------
 * Stores the last-seen abuseConfidenceScore for an IP under
 * mqc:<ip>:abuse so mqc_abuse_check can skip the outbound HTTPS call
 * (5s curl ceiling) on cache hit.  Keyed on IP only, not on score band,
 * so tuning MQC_ABUSE_THRESHOLD does not require a cache flush.
 * Caller (mqc_abuseipdb.c) controls TTL via rt_cfg->abuse_cache_ttl_sec. */
int mqc_abuse_cache_get(const char *ip, int *out_score)
{
    char key[128];
    redisReply *reply;
    int found = 0;

    if (!s_redis || !ip || !out_score) return 0;

    snprintf(key, sizeof(key), "mqc:%s:abuse", ip);
    reply = redisCommand(s_redis, "GET %s", key);
    if (reply) {
        if (reply->str) {
            *out_score = atoi(reply->str);
            found = 1;
        }
        freeReplyObject(reply);
    }
    return found;
}

void mqc_abuse_cache_put(const char *ip, int score, int ttl_secs)
{
    char key[128];
    redisReply *reply;

    if (!s_redis || !ip || ttl_secs <= 0) return;

    snprintf(key, sizeof(key), "mqc:%s:abuse", ip);
    reply = redisCommand(s_redis, "SETEX %s %d %d", key, ttl_secs, score);
    if (reply) freeReplyObject(reply);
}

/* --- Per-IP distinct-cert_index rate limit (issue #12) ----------------
 * Inside the per-IP connection budget, an attacker that rotates
 * cert_index every connect forces a fresh certificate fetch + Merkle
 * inclusion + cosignature verify per attempt -- ~ms of asymmetric
 * work per cheap client byte.  This pair of buckets caps how many
 * DISTINCT cert_index values a single source IP can present per
 * minute / per hour.
 *
 * Implementation note: a SET keyed by IP with cert_index values as
 * members lets SCARD give us the exact distinct-count.  Per-(IP,
 * cert_index) counters would only catch repeated hits on the SAME
 * index -- not what we want here. */
int mqc_redis_sadd_count(const char *key, int cert_index, int ttl_secs)
{
    redisReply *reply;
    int count = 0;

    if (!s_redis) return 0;

    reply = redisCommand(s_redis, "SADD %s %d", key, cert_index);
    if (!reply) return 0;
    freeReplyObject(reply);

    reply = redisCommand(s_redis, "EXPIRE %s %d", key, ttl_secs);
    if (reply) freeReplyObject(reply);

    reply = redisCommand(s_redis, "SCARD %s", key);
    if (!reply) return 0;
    if (reply->type == REDIS_REPLY_INTEGER)
        count = (int)reply->integer;
    freeReplyObject(reply);
    return count;
}

int mqc_ratelimit_cert_check(const char *ip, int cert_index)
{
    char key[160];
    int count_m, count_h;

    if (!s_redis) {
        time_t dt;
        if (mqc_redis_down_decide(&dt) == MQC_REDIS_DECISION_CLOSED) {
            MQC_SECURITY("RL_FAIL_CLOSED: per-(IP, cert) gate "
                         "enforced, Redis down %lds (ip=%s cert=%d) "
                         "— rejecting connection",
                         (long)dt, ip, cert_index);
            return -1;
        }
        MQC_SECURITY("RL_FAIL_OPEN: per-(IP, cert) gate disabled, "
                     "Redis down %lds (ip=%s cert=%d)",
                     (long)dt, ip, cert_index);
        return 0;
    }

    snprintf(key, sizeof(key), "mqc:%s:cert:m", ip);
    count_m = mqc_redis_sadd_count(key, cert_index, 60);
    snprintf(key, sizeof(key), "mqc:%s:cert:h", ip);
    count_h = mqc_redis_sadd_count(key, cert_index, 3600);

    if (count_m > mqc_rt_cfg()->rl_cert_per_min) {
        MQC_SECURITY("CERT_RATE_LIMITED: %s distinct cert_index "
                     "%d/min (max %ld); last cert_index=%d",
                     ip, count_m, mqc_rt_cfg()->rl_cert_per_min,
                     cert_index);
        return -1;
    }
    if (count_h > mqc_rt_cfg()->rl_cert_per_hour) {
        MQC_SECURITY("CERT_RATE_LIMITED: %s distinct cert_index "
                     "%d/hr (max %ld); last cert_index=%d",
                     ip, count_h, mqc_rt_cfg()->rl_cert_per_hour,
                     cert_index);
        return -1;
    }
    return 0;
}

/* --- Accept-side prologue --------------------------------------------------
 * Runs the cheap server-side gates (AbuseIPDB + rate limits) on a freshly
 * accept()'d fd before any post-quantum work.  Lives here so that the
 * mqc_abuse_check / mqc_ratelimit_* references stay inside a single
 * server-only TU and don't get dragged into client links.
 *
 * Returns 0 on success — caller continues with the handshake.
 * Returns -1 if the connection should be dropped — caller is
 * responsible for close(fd) and returning NULL.
 *
 * The slow-loris HANDSHAKE_DEADLINE_ACTIVE() macro stays the
 * caller's responsibility because it relies on cleanup-attribute
 * scope: arm it in the function whose lifetime should bound the
 * deadline. */
int mqc_accept_prologue(int fd, const char *client_ip)
{
    long _t_total = mqc_now_ms();

    /* Cheap in-process Redis gates run BEFORE the AbuseIPDB HTTPS lookup
     * so an IP already over its rate-limit cap (connect or fail) never
     * triggers an outbound api.abuseipdb.com call.  Reorder matters: the
     * abuse check has no local cache and a 5s curl ceiling per accept. */

    MQC_TIME_BEGIN(rl_check);
    if (mqc_ratelimit_check(client_ip) != 0) return -1;
    MQC_TIME_END(rl_check);

    MQC_TIME_BEGIN(rl_fail);
    if (mqc_ratelimit_fail_check(client_ip) != 0) return -1;
    MQC_TIME_END(rl_fail);

    MQC_TIME_BEGIN(abuse);
    if (mqc_abuse_check(client_ip) != 0) return -1;
    MQC_TIME_END(abuse);

    mqc_set_socket_timeout(fd, mqc_rt_cfg()->handshake_stall_sec);

    if (mqc_get_time_enabled())
        fprintf(stderr, "[MQC-TIME] setup_total = %ld ms\n",
                mqc_now_ms() - _t_total);
    return 0;
}
