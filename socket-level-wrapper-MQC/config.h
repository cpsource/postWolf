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

#endif /* MQC_CONFIG_H */
