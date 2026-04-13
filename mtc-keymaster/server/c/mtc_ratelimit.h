/**
 * @file mtc_ratelimit.h
 * @brief Redis-backed per-IP rate limiting for the MTC CA server.
 *
 * @details
 * Provides sliding-window rate limiting using Redis INCR + EXPIRE counters.
 * Each request is checked against both a category-specific limit and a
 * global per-IP limit.  Two time windows are enforced per category:
 * per-minute and per-hour.
 *
 * Redis key format:
 *   - rl:&lt;ip&gt;:&lt;category&gt;:m  — per-minute counter (TTL 60s)
 *   - rl:&lt;ip&gt;:&lt;category&gt;:h  — per-hour counter (TTL 3600s)
 *
 * If Redis is unavailable, all requests are allowed (fail-open).
 *
 * Thread safety: NOT thread-safe.  The Redis connection is file-scoped
 * static storage.
 *
 * @date 2026-04-13
 */

#ifndef MTC_RATELIMIT_H
#define MTC_RATELIMIT_H

/** @name Rate limit category constants
 *  Each category has independent per-minute and per-hour limits.
 *  Every check also counts against RL_GLOBAL.
 *  @{ */
#define RL_READ           0   /**< GET endpoints (60/min, 600/hr)          */
#define RL_NONCE_LEAF     1   /**< POST /enrollment/nonce type=leaf
                                   (10/min, 100/hr)                        */
#define RL_NONCE_CA       2   /**< POST /enrollment/nonce type=ca
                                   (3/min, 10/hr)                          */
#define RL_ENROLL         3   /**< POST /certificate/request (3/min, 10/hr)*/
#define RL_REVOKE         4   /**< POST /revoke (2/min, 5/hr)              */
#define RL_GLOBAL         5   /**< Catch-all per-IP (120/min, 1200/hr)     */
#define RL_NUM_CATEGORIES 6   /**< Total number of categories              */
/** @} */

/**
 * @brief    Initialise the rate limiter and connect to Redis.
 *
 * @param[in] redis_host  Redis hostname.  NULL defaults to "127.0.0.1".
 * @param[in] redis_port  Redis port.  <= 0 defaults to 6379.
 *
 * @return
 *   0   on success (Redis connected).
 *  -1   on connection failure (rate limiting disabled — fail-open).
 */
int mtc_ratelimit_init(const char *redis_host, int redis_port);

/**
 * @brief    Close the Redis connection and release resources.
 *
 * @details  No-op if not initialised or already closed.
 */
void mtc_ratelimit_close(void);

/**
 * @brief    Check whether a request from @p ip is allowed.
 *
 * @details
 * Increments both the category-specific and RL_GLOBAL counters for
 * the given IP in Redis, then compares against the configured limits.
 * If Redis is not connected, the request is always allowed (fail-open).
 *
 * @param[in] ip        Client IP address string.  NULL or empty = allow.
 * @param[in] category  Rate limit category (RL_READ..RL_REVOKE).
 *                       Invalid values = allow.
 *
 * @return
 *   1  if the request is allowed.
 *   0  if rate-limited (either category or global limit exceeded).
 *
 * @note  The counters are always incremented, even when the request is
 *        ultimately denied — this is intentional to prevent burst abuse.
 */
int mtc_ratelimit_check(const char *ip, int category);

#endif
