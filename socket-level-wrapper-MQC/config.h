/*
 * config.h — deployment-specific constants for socket-level-wrapper-MQC.
 *
 * Change these if you run your own postWolf infrastructure; the default
 * values point at the reference deployment (factsorlie.com).
 *
 * Each constant is wrapped in `#ifndef` so a downstream builder can
 * override via -DMQC_DEFAULT_SERVER_HOST=\"example.com\" etc. without
 * editing this file.
 *
 * Protocol-level invariants (ML-KEM-768 / ML-DSA-87 / AES-256-GCM
 * parameters, HKDF info strings, frame headers) are NOT here — those
 * live in mqc.c and changing them would break interop with other
 * postWolf peers.
 */

#ifndef MQC_CONFIG_H
#define MQC_CONFIG_H

/* -- Reference deployment hostname ------------------------------------ */
/* Default MTC CA / transparency-log server.  Clients fall back to this
 * when no --server flag is given.  Only the host is meaningful; the
 * bootstrap port is hardcoded below. */
#ifndef MQC_DEFAULT_SERVER_HOST
#define MQC_DEFAULT_SERVER_HOST     "factsorlie.com"
#endif

/* -- Ports ------------------------------------------------------------ */
/* MQC — post-quantum authenticated endpoint.  Served by mtc_server. */
#ifndef MQC_DEFAULT_SERVER_PORT
#define MQC_DEFAULT_SERVER_PORT     8446
#endif

/* Bootstrap — pre-authentication public lookups (ca_pubkey, http_get
 * proxy) and DH enrollment.  Used by mqc_load_ca_pubkey,
 * bootstrap_http_get, bootstrap_ca, bootstrap_leaf. */
#ifndef MQC_BOOTSTRAP_PORT
#define MQC_BOOTSTRAP_PORT          8445
#endif

/* -- Combined default server string ----------------------------------- */
/* Build "factsorlie.com:8446" at preprocess time so tool defaults stay
 * in sync with the host/port macros above.  Do not edit these two
 * helpers — change MQC_DEFAULT_SERVER_HOST / _PORT instead. */
#define MQC__STR_(x)                #x
#define MQC__STR(x)                 MQC__STR_(x)
#ifndef MQC_DEFAULT_SERVER
#define MQC_DEFAULT_SERVER          MQC_DEFAULT_SERVER_HOST ":" \
                                    MQC__STR(MQC_DEFAULT_SERVER_PORT)
#endif

/* -- Revocation cache TTL (client-side) ------------------------------- */
/* Lifetime in seconds of ~/.TPM/peers/<n>/revoked.json.  A stale entry
 * forces a refresh via /revoked/<n>; the server drops the first
 * handshake, the peer retries with the fresh cache. */
#ifndef MQC_REVOKED_CACHE_TTL_SEC
#define MQC_REVOKED_CACHE_TTL_SEC   (24 * 60 * 60)   /* 24 h */
#endif

/* -- AbuseIPDB score cache TTL (server-side accept-prologue) ----------- */
/* Lifetime of the Redis-backed per-IP abuseConfidenceScore cache.  A
 * cache hit lets the accept-prologue skip the outbound HTTPS call to
 * api.abuseipdb.com (5s curl ceiling).  Default 24h matches the
 * revocation-cache cadence. */
#ifndef MQC_ABUSE_CACHE_TTL_SEC
#define MQC_ABUSE_CACHE_TTL_SEC     (24 * 60 * 60)   /* 24 h */
#endif

/* -- Signature freshness window (server-side: /revoke, /enrollment ...) */
/* Max allowed skew between a signed-payload timestamp and the server
 * clock.  Matches handle_revoke's ±5 min enforcement. */
#ifndef MQC_SIG_FRESHNESS_SEC
#define MQC_SIG_FRESHNESS_SEC       300              /* 5 min */
#endif

/* -- MQC handshake slow-client budgets (server-side accept path) ------ */
/* Per-read SO_RCVTIMEO on an accepted MQC socket.  Kills outright-
 * hung peers.  The whole handshake is small, so a tight value is fine. */
#ifndef MQC_HANDSHAKE_STALL_SEC
#define MQC_HANDSHAKE_STALL_SEC     3
#endif

/* Total wall-clock budget for completing the MQC handshake.  Kills
 * slow-loris drip attacks where each individual read is under the
 * per-read cap but the overall exchange crawls.  Legit handshakes
 * complete in milliseconds even over slow links. */
#ifndef MQC_HANDSHAKE_TOTAL_SEC
#define MQC_HANDSHAKE_TOTAL_SEC     5
#endif

/* -- Revocation policy (issue #7) ------------------------------------- */
/* Default policy if /etc/postWolf/config has no mqc-revocation-policy
 * key.  Values: "mandatory", "cache-only", "disabled".  See spec
 * Section 10.5; status table in
 * socket-level-wrapper-MQC/reviews/README-mqc-1-issues.md row #7. */
#ifndef MQC_REVOCATION_POLICY_DEFAULT
#define MQC_REVOCATION_POLICY_DEFAULT "mandatory"
#endif

/* -- Per-(IP, cert_index) rate limits (issue #12) --------------------- */
/* A single legitimate peer rotates cert_index slowly (a fresh leaf
 * enrollment is rare).  An attacker cycling cert_index every connect
 * would force a fresh cert fetch + cosignature verify each time —
 * cheap to send, expensive to handle.  Cap fresh-index attempts per
 * (source-IP, cert_index) at the same scale as the per-IP fail
 * bucket (issue #6a). */
#ifndef MQC_RL_CERT_MIN
#define MQC_RL_CERT_MIN     10
#endif
#ifndef MQC_RL_CERT_HOUR
#define MQC_RL_CERT_HOUR    100
#endif

/* -- Redis-down failure policy --------------------------------------- */
/* What every rate-limit / abuse gate does when its Redis backing
 * store is unreachable.  Three values:
 *
 *   "open"          — allow the request, log MQC_SECURITY.  Pre-fix
 *                     default.  Operationally safest (a Redis blip
 *                     never causes a service outage) but lets a
 *                     coordinated attacker who can DoS Redis disable
 *                     all rate limiting.
 *
 *   "closed"        — refuse the request immediately, log
 *                     MQC_SECURITY.  Stops the attack class but a
 *                     normal Redis restart causes a brief total
 *                     outage of every gate-protected port.
 *
 *   "closed-after"  — stay fail-OPEN for the first N seconds of
 *                     Redis being down (covers a routine restart),
 *                     flip to fail-CLOSED past N (the outage now
 *                     looks hostile or persistent).  N defaults to
 *                     a conservative Redis-restart budget; tune via
 *                     mqc-rl-redis-fail-closed-after-sec.
 *
 * The CLOSED_AFTER timer is shared across forks via a tiny tmpfile
 * (mqc-rl-redis-state-path).  Each child writes the unix timestamp
 * the FIRST time it sees Redis-down; siblings read it; whichever
 * child sees Redis-up unlinks it. */
#ifndef MQC_REDIS_FAIL_POLICY_DEFAULT
#define MQC_REDIS_FAIL_POLICY_DEFAULT "closed-after"
#endif
#ifndef MQC_REDIS_FAIL_CLOSED_AFTER_SEC_DEFAULT
#define MQC_REDIS_FAIL_CLOSED_AFTER_SEC_DEFAULT 8
#endif
#ifndef MQC_REDIS_STATE_PATH_DEFAULT
#define MQC_REDIS_STATE_PATH_DEFAULT "/tmp/postWolf-mqc-redis-down"
#endif

#endif /* MQC_CONFIG_H */
