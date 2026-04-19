/**
 * @file mtc_checkendpoint.h
 * @brief AbuseIPDB CHECK endpoint client — public API.
 *
 * @details
 * Provides IP reputation checking via the AbuseIPDB v2 CHECK endpoint.
 * Results are optionally cached in a PostgreSQL (Neon) database to reduce
 * API calls.  The module must be initialised with mtc_init() before any
 * calls to mtc_checkendpoint().
 *
 * Thread safety: this module is NOT thread-safe.  All calls must be
 * serialised by the caller (the HTTP server currently runs single-threaded).
 *
 * @date 2026-04-13
 */

#ifndef MTC_CHECKENDPOINT_H
#define MTC_CHECKENDPOINT_H

#include "config.h"   /* ABUSEIPDB_CACHE_TTL_DAYS, ABUSEIPDB_ENROLL_THRESHOLD */

/**
 * @brief    Initialise the AbuseIPDB module.
 *
 * @details
 * Loads the API key from the ABUSEIPDB_KEY environment variable or from
 * ~/.env.  If a MERKLE_NEON database connection string is available,
 * connects to PostgreSQL and ensures the cache schema exists.
 * Calls curl_global_init() — must be called before mtc_checkendpoint().
 *
 * @return
 *   0   on success.
 *  -1   on general failure (DB schema init failed but API key loaded).
 *  -2   if no API key was found (module is non-functional).
 *
 * @note  Must be called exactly once before any other module function.
 *        curl_global_init() is invoked internally.
 */
int mtc_init(void);

/**
 * @brief    Check an IP address against AbuseIPDB.
 *
 * @details
 * Returns the abuseConfidenceScore for the given IP.  If a DB cache is
 * available and holds a fresh entry (younger than ABUSEIPDB_CACHE_TTL_DAYS),
 * the cached score is returned without an API call.  Otherwise the
 * AbuseIPDB v2 CHECK endpoint is queried and the result is cached.
 *
 * @param[in] ipaddr  Null-terminated IPv4 or IPv6 address string.
 *                     Must not be NULL.
 *
 * @return
 *   0..100  abuseConfidenceScore on success.
 *  -1       on network or parse failure.
 *  -2       if no API key is configured (mtc_init() returned -2 or was
 *           not called).
 *
 * @note  The caller retains ownership of @p ipaddr.
 */
int mtc_checkendpoint(char *ipaddr);

/**
 * @brief    Set the abuse confidence score threshold for rejecting requests.
 *
 * @param[in] threshold  Score (0-100).  Scores >= threshold cause rejection.
 *                        Default is 75.
 */
void mtc_set_abuse_threshold(int threshold);

/**
 * @brief    Get the current abuse confidence score threshold.
 *
 * @return   Current threshold (0-100).  Default is 75.
 */
int  mtc_get_abuse_threshold(void);

#endif
