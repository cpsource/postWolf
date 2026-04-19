/*
 * config.h — deployment-tunable constants for mtc_server.
 *
 * One place to tweak timeouts, thresholds, and default paths.  Each
 * macro is wrapped in `#ifndef` so a downstream builder can override
 * via -DMTC_NONCE_TTL_SECS=1800 (etc.) without editing this file.
 *
 * What lives here:
 *   - AbuseIPDB cache TTL + rejection thresholds
 *   - Nonce and signature freshness windows
 *   - Default ports for the three listeners
 *   - Default on-disk paths
 *
 * What does NOT live here (and why):
 *   - Protocol invariants — AES key sizes, HKDF info strings, frame
 *     headers, DH curve.  Changing those breaks interop with every
 *     enrolled peer.  They live next to the code that uses them
 *     (mtc_bootstrap.c, mtc_crypt.c, socket-level-wrapper-MQC/mqc.c).
 *   - Per-category rate-limit counts — defined in mtc_ratelimit.c's
 *     s_limits[] array.  Moving them here is possible but buys little
 *     (they're already one table, not scattered literals).
 */

#ifndef MTC_SERVER_CONFIG_H
#define MTC_SERVER_CONFIG_H

/* -- AbuseIPDB ------------------------------------------------------- */
/* How long to trust a cached AbuseIPDB lookup before refreshing. */
#ifndef ABUSEIPDB_CACHE_TTL_DAYS
#define ABUSEIPDB_CACHE_TTL_DAYS        5
#endif

/* SQL INTERVAL literal form of the same value, used in Postgres
 * queries (mtc_checkendpoint.c).  Keep in sync with the DAYS macro. */
#ifndef ABUSEIPDB_CACHE_TTL_INTERVAL
#define ABUSEIPDB_CACHE_TTL_INTERVAL    "5 days"
#endif

/* Enrollment/revocation endpoints use a stricter threshold than
 * general GETs — a lower score triggers rejection here. */
#ifndef ABUSEIPDB_ENROLL_THRESHOLD
#define ABUSEIPDB_ENROLL_THRESHOLD      25
#endif

/* Default for general-access reject score (overridable by
 * --abuse-threshold on the mtc_server command line). */
#ifndef MTC_ABUSE_DEFAULT_THRESHOLD
#define MTC_ABUSE_DEFAULT_THRESHOLD     75
#endif

/* -- Nonce / signature freshness ------------------------------------- */
/* How long an issued enrollment nonce stays valid. */
#ifndef MTC_NONCE_TTL_SECS
#define MTC_NONCE_TTL_SECS              900       /* 15 min */
#endif

/* Max skew between a signed-payload timestamp and server clock.
 * Used by handle_revoke (and any future signed-POST endpoint). */
#ifndef MTC_SIG_FRESHNESS_SEC
#define MTC_SIG_FRESHNESS_SEC           300       /* ±5 min */
#endif

/* -- Default listener ports ------------------------------------------ */
#ifndef MTC_HTTP_DEFAULT_PORT
#define MTC_HTTP_DEFAULT_PORT           8444      /* TLS debug / curl */
#endif

#ifndef MTC_DH_DEFAULT_PORT
#define MTC_DH_DEFAULT_PORT             8445      /* DH bootstrap + public lookups */
#endif

#ifndef MTC_MQC_DEFAULT_PORT
#define MTC_MQC_DEFAULT_PORT            8446      /* post-quantum authenticated */
#endif

/* -- Default on-disk paths ------------------------------------------- */
#ifndef MTC_LOG_DEFAULT_PATH
#define MTC_LOG_DEFAULT_PATH            "/var/log/mtc/mtc_server.log"
#endif

/* -- Bootstrap-port slow-client budgets ------------------------------ */
/* Per-read (SO_RCVTIMEO): a single read call stalling longer than this
 * drops the connection.  Kills outright-hung peers. */
#ifndef MTC_BOOTSTRAP_READ_STALL_SEC
#define MTC_BOOTSTRAP_READ_STALL_SEC    2
#endif

/* Total wall-clock budget for reading one plaintext-JSON request.
 * Kills slow-loris drip attacks where each individual read stays
 * under the per-read timeout but the overall exchange crawls. */
#ifndef MTC_BOOTSTRAP_READ_TOTAL_SEC
#define MTC_BOOTSTRAP_READ_TOTAL_SEC    3
#endif

#endif /* MTC_SERVER_CONFIG_H */
