/* mtc_ratelimit.h — Redis-backed per-IP rate limiting */

#ifndef MTC_RATELIMIT_H
#define MTC_RATELIMIT_H

/* Rate limit categories */
#define RL_READ           0   /* GET endpoints */
#define RL_NONCE_LEAF     1   /* POST /enrollment/nonce type=leaf (CA operator) */
#define RL_NONCE_CA       2   /* POST /enrollment/nonce type=ca */
#define RL_ENROLL         3   /* POST /certificate/request */
#define RL_REVOKE         4   /* POST /revoke */
#define RL_GLOBAL         5   /* catch-all per-IP */
#define RL_NUM_CATEGORIES 6

/* Initialize rate limiter. Connects to Redis at host:port.
 * Returns 0 on success, -1 on failure (rate limiting disabled). */
int mtc_ratelimit_init(const char *redis_host, int redis_port);

/* Close Redis connection. */
void mtc_ratelimit_close(void);

/* Check if a request is allowed.
 * Returns 1 if allowed, 0 if rate-limited.
 * Always checks both the specific category AND RL_GLOBAL. */
int mtc_ratelimit_check(const char *ip, int category);

#endif
