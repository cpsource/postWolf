/**
 * @file mtc_db.h
 * @brief PostgreSQL (Neon) persistence layer for the MTC CA server.
 *
 * @details
 * Provides CRUD operations for all server-side state: log entries,
 * checkpoints, landmarks, certificates, revocations, CA configuration
 * (key persistence), and enrollment nonces.  The schema mirrors the
 * Python server's db.py so both implementations share the same database.
 *
 * Connection strings are resolved from (in priority order):
 *   1. $MERKLE_NEON environment variable
 *   2. --tokenpath file  (MERKLE_NEON= line)
 *   3. ~/.env fallback   (MERKLE_NEON= line)
 *
 * Thread safety: this module is NOT thread-safe.  The connection string
 * is cached in file-scoped static storage.  All calls sharing a PGconn
 * must be serialised by the caller.
 *
 * @date 2026-04-13
 */

#ifndef MTC_DB_H
#define MTC_DB_H

#include <libpq-fe.h>
#include <json-c/json.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Connection management                                               */
/* ------------------------------------------------------------------ */

/**
 * @brief    Set an explicit file path to search for MERKLE_NEON.
 *
 * @details
 * Overrides the default ~/.env fallback.  Typically set from --tokenpath
 * on the command line.
 *
 * @param[in] path  Null-terminated file path.  If NULL, the tokenpath is
 *                   cleared.  The string is copied internally.
 */
void mtc_db_set_tokenpath(const char *path);

/**
 * @brief    Resolve and return the PostgreSQL connection string.
 *
 * @details
 * Searches for MERKLE_NEON in the following order:
 *   1. $MERKLE_NEON environment variable
 *   2. --tokenpath file  (MERKLE_NEON= line)
 *   3. ~/.env fallback   (MERKLE_NEON= line)
 *
 * The result is cached after the first successful lookup.
 *
 * @return  Pointer to an internal static buffer containing the connection
 *          string, or NULL if not found.  Caller must NOT free.
 */
const char *mtc_db_get_connstr(void);

/**
 * @brief    Connect to PostgreSQL using the resolved connection string.
 *
 * @return  Active PGconn pointer on success.  Caller owns the connection
 *          and must call PQfinish() when done.
 * @return  NULL on failure (error logged to stderr).
 */
PGconn *mtc_db_connect(void);

/**
 * @brief    Create all required tables and indexes if they don't exist.
 *
 * @details
 * Executes CREATE TABLE IF NOT EXISTS for: mtc_log_entries, mtc_checkpoints,
 * mtc_landmarks, mtc_certificates, mtc_ca_config, mtc_revocations, and
 * mtc_enrollment_nonces.  Also applies ALTER TABLE migrations for columns
 * added after initial deployment.
 *
 * @param[in] conn  Active PostgreSQL connection.  Must not be NULL.
 *
 * @return
 *   0   on success.
 *  -1   if any DDL statement failed (error logged to stderr).
 *
 * @note  Safe to call multiple times; all statements use IF NOT EXISTS.
 */
int mtc_db_init_schema(PGconn *conn);

/* ------------------------------------------------------------------ */
/* Log entries                                                         */
/* ------------------------------------------------------------------ */

/**
 * @brief    Persist a Merkle tree log entry.
 *
 * @param[in] conn           Active PostgreSQL connection.
 * @param[in] index          Log entry index (primary key).
 * @param[in] entry_type     Entry type code (e.g. CA=0, leaf=1).
 * @param[in] tbs_json       JSON string of the TBS (to-be-signed) data.
 *                            May be NULL.
 * @param[in] serialized     Binary serialized entry (sent as BYTEA).
 * @param[in] serialized_sz  Length of @p serialized in bytes.
 * @param[in] leaf_hash      32-byte leaf hash (sent as BYTEA).
 *
 * @return
 *   0   on success (or if the index already exists — ON CONFLICT DO NOTHING).
 *  -1   on query failure.
 */
int  mtc_db_save_entry(PGconn *conn, int index, int entry_type,
                       const char *tbs_json, const uint8_t *serialized,
                       int serialized_sz, const uint8_t *leaf_hash);

/**
 * @brief    Load all log entries from the database.
 *
 * @param[in]  conn      Active PostgreSQL connection.
 * @param[out] out_arr   Receives a new json_object array.  Each element is
 *                        an object with keys: index, entry_type, tbs_data,
 *                        serialized_hex, serialized_len.
 *
 * @return  Number of rows loaded (>= 0), or -1 on query failure.
 *
 * @note  Caller owns *out_arr and must call json_object_put() to free.
 */
int  mtc_db_load_entries(PGconn *conn, struct json_object **out_arr);

/* ------------------------------------------------------------------ */
/* Checkpoints                                                         */
/* ------------------------------------------------------------------ */

/**
 * @brief    Save a Merkle tree checkpoint.
 *
 * @param[in] conn       Active PostgreSQL connection.
 * @param[in] log_id     Log identifier string.
 * @param[in] tree_size  Number of leaves in the tree at checkpoint time.
 * @param[in] root_hash  Hex-encoded root hash string.
 * @param[in] ts         UNIX timestamp (double precision).
 *
 * @return   0 on success, -1 on failure.
 */
int  mtc_db_save_checkpoint(PGconn *conn, const char *log_id,
                            int tree_size, const char *root_hash, double ts);

/**
 * @brief    Load all checkpoints for a given log ID.
 *
 * @param[in]  conn      Active PostgreSQL connection.
 * @param[in]  log_id    Log identifier to filter by.
 * @param[out] out_arr   Receives a new json_object array of checkpoint
 *                        objects (log_id, tree_size, root_hash, timestamp).
 *
 * @return  Number of rows loaded (>= 0), or -1 on query failure.
 *
 * @note  Caller owns *out_arr and must call json_object_put() to free.
 */
int  mtc_db_load_checkpoints(PGconn *conn, const char *log_id,
                             struct json_object **out_arr);

/* ------------------------------------------------------------------ */
/* Landmarks                                                           */
/* ------------------------------------------------------------------ */

/**
 * @brief    Record a landmark tree size.
 *
 * @param[in] conn       Active PostgreSQL connection.
 * @param[in] tree_size  Tree size to record (unique constraint; duplicates
 *                        are silently ignored).
 *
 * @return   0 on success, -1 on failure.
 */
int  mtc_db_save_landmark(PGconn *conn, int tree_size);

/**
 * @brief    Load recorded landmark tree sizes.
 *
 * @param[in]  conn       Active PostgreSQL connection.
 * @param[out] out        Caller-owned array to fill with tree sizes,
 *                         sorted ascending.
 * @param[in]  max_count  Capacity of @p out.
 *
 * @return  Number of landmarks written to @p out (may be less than total
 *          if max_count is reached).  0 on query failure.
 */
int  mtc_db_load_landmarks(PGconn *conn, int *out, int max_count);

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

/**
 * @brief    Save or update a certificate JSON blob.
 *
 * @param[in] conn       Active PostgreSQL connection.
 * @param[in] index      Certificate log index (primary key; upserted on
 *                        conflict).
 * @param[in] cert_json  JSON string of the certificate.
 *
 * @return   0 on success, -1 on failure.
 */
int  mtc_db_save_certificate(PGconn *conn, int index, const char *cert_json);

/**
 * @brief    Load a single certificate by log index.
 *
 * @param[in] conn   Active PostgreSQL connection.
 * @param[in] index  Certificate log index.
 *
 * @return  Parsed json_object on success (caller owns; free with
 *          json_object_put()), or NULL if not found or on error.
 */
struct json_object *mtc_db_load_certificate(PGconn *conn, int index);

/**
 * @brief    Load all certificates into an index-addressed array.
 *
 * @details
 * Allocates an array of (max_index + 1) json_object pointers via calloc.
 * Slots without a certificate are NULL.
 *
 * @param[in]  conn   Active PostgreSQL connection.
 * @param[out] out    Receives a calloc'd array of json_object pointers.
 *                     Caller must free each non-NULL element with
 *                     json_object_put() and then free(*out).
 * @param[out] count  Receives the array length (max_index + 1).
 *
 * @return  Number of certificate rows loaded (>= 0), or -1 on failure.
 */
int  mtc_db_load_all_certificates(PGconn *conn,
                                   struct json_object ***out, int *count);

/* ------------------------------------------------------------------ */
/* Revocations                                                         */
/* ------------------------------------------------------------------ */

/**
 * @brief    Record a certificate revocation.
 *
 * @param[in] conn        Active PostgreSQL connection.
 * @param[in] cert_index  Log index of the certificate to revoke.
 * @param[in] reason      Human-readable reason string.  NULL defaults to
 *                         "unspecified".
 *
 * @return   0 on success, -1 on failure.
 *
 * @note  Multiple revocation records for the same cert_index are allowed.
 */
int  mtc_db_save_revocation(PGconn *conn, int cert_index, const char *reason);

/**
 * @brief    Load revoked certificate indices.
 *
 * @param[in]  conn       Active PostgreSQL connection.
 * @param[out] indices    Caller-owned array to fill with cert indices,
 *                         sorted ascending.
 * @param[in]  max_count  Capacity of @p indices.
 *
 * @return  Number of revocations written to @p indices.  0 on failure.
 */
int  mtc_db_load_revocations(PGconn *conn, int *indices, int max_count);

/**
 * @brief    Check whether a certificate has been revoked.
 *
 * @param[in] conn        Active PostgreSQL connection.
 * @param[in] cert_index  Log index of the certificate.
 *
 * @return  1 if revoked, 0 if not revoked or on error.
 */
int  mtc_db_is_revoked(PGconn *conn, int cert_index);

/* ------------------------------------------------------------------ */
/* CA config (key persistence)                                         */
/* ------------------------------------------------------------------ */

/**
 * @brief    Save a CA configuration key/value pair (upsert).
 *
 * @param[in] conn   Active PostgreSQL connection.
 * @param[in] key    Configuration key (primary key; upserted on conflict).
 * @param[in] value  Configuration value string.
 *
 * @return   0 on success, -1 on failure.
 */
int  mtc_db_save_config(PGconn *conn, const char *key, const char *value);

/**
 * @brief    Load a CA configuration value by key.
 *
 * @param[in] conn  Active PostgreSQL connection.
 * @param[in] key   Configuration key to look up.
 *
 * @return  strdup'd value string on success (caller must free()),
 *          or NULL if not found.
 */
char *mtc_db_load_config(PGconn *conn, const char *key);

/* ------------------------------------------------------------------ */
/* Enrollment nonces                                                   */
/* ------------------------------------------------------------------ */

/** Nonce time-to-live in seconds (15 minutes). */
/* MTC_NONCE_TTL_SECS now defined in config.h (defaults to 900). */
#include "config.h"

/** Hex string length for a 256-bit nonce (32 bytes = 64 hex chars). */
#define MTC_NONCE_HEX_LEN  64

/** Max length of an operator-assigned label (~/.TPM/<domain>-<label>/). */
#define MTC_LABEL_MAX      64

/**
 * @brief    Create a cryptographically random enrollment nonce.
 *
 * @details
 * Generates a 256-bit random nonce via wolfCrypt, inserts it into the
 * mtc_enrollment_nonces table with status 'pending', and returns the
 * hex-encoded nonce and expiration timestamp.  Stale nonces are expired
 * first.  If a pending non-expired nonce already exists for the given
 * domain+fp pair, it is returned unchanged (idempotent reissue) — its
 * label is returned verbatim even if the reissuing caller passes a
 * different label, so labels are effectively immutable until expiry.
 *
 * @param[in]  conn         Active PostgreSQL connection.
 * @param[in]  domain       Domain name bound to this nonce.
 * @param[in]  fp_hex       Public key fingerprint (hex string) bound to
 *                           this nonce, or NULL to issue a
 *                           fingerprint-less reservation nonce whose
 *                           fp is late-bound at consume time.
 * @param[in]  ca_index     Log index of the issuing CA (-1 for CA
 *                           self-enrollment via DNS).
 * @param[in]  label         Optional operator-assigned label
 *                            (NULL = none).  Persisted verbatim; the
 *                            server does not sanitize — client tools
 *                            (bootstrap_leaf, bootstrap_ca) are
 *                            authoritative.
 * @param[in]  ttl_secs     TTL in seconds.  Pass 0 to use the default
 *                            MTC_NONCE_TTL_SECS (15 min).  Caller is
 *                            responsible for clamping to
 *                            MTC_NONCE_MAX_TTL_DAYS.
 * @param[out] nonce_out     Buffer for the hex nonce.  Must be at least
 *                            MTC_NONCE_HEX_LEN + 1 bytes.
 * @param[out] expires_out   Receives the UNIX expiration timestamp.
 * @param[out] label_out     May be NULL.  If non-NULL, receives the
 *                            canonical stored label (empty string if
 *                            none).  On idempotent reissue this is the
 *                            label from the FIRST call, not @p label.
 *                            Buffer must be at least MTC_LABEL_MAX + 1
 *                            bytes when non-NULL.
 * @param[in]  label_out_sz  Size of @p label_out (ignored if NULL).
 *
 * @return
 *   0   on success (new or reused nonce written to nonce_out).
 *  -1   on failure (RNG error or DB error).
 */
int  mtc_db_create_nonce(PGconn *conn, const char *domain, const char *fp_hex,
                         int ca_index, const char *label,
                         long ttl_secs,
                         char *nonce_out, long *expires_out,
                         char *label_out, size_t label_out_sz);

/**
 * @brief    Find the registered CA log index for a domain.
 *
 * @details
 * Searches mtc_certificates for a certificate whose subject matches
 * "&lt;domain&gt;-ca" (the CA enrollment naming convention).  Returns
 * the most recent (highest index) match.
 *
 * @param[in] conn    Active PostgreSQL connection.
 * @param[in] domain  Domain name to search for.
 *
 * @return  CA log index (>= 0) on success, -1 if not found or on error.
 */
int  mtc_db_find_ca_for_domain(PGconn *conn, const char *domain);

/**
 * @brief    Validate a nonce without consuming it.
 *
 * @details
 * Checks that the nonce exists, has status 'pending', and is not expired.
 * Optionally matches domain and/or fingerprint for defense-in-depth.
 *
 * @param[in] conn       Active PostgreSQL connection.
 * @param[in] nonce_hex  Hex-encoded nonce to validate.
 * @param[in] domain     Domain to match (NULL or "" to skip check).
 * @param[in] fp_hex     Fingerprint to match (NULL or "" to skip check).
 *
 * @return  1 if valid, 0 otherwise.
 *
 * @warning  For enrollment flows, prefer mtc_db_validate_and_consume_nonce()
 *           to avoid TOCTOU races between validation and consumption.
 */
int  mtc_db_validate_nonce(PGconn *conn, const char *nonce_hex,
                           const char *domain, const char *fp_hex);

/**
 * @brief    Atomically validate and consume a nonce in a single query.
 *
 * @details
 * Issues a single UPDATE ... WHERE (pending + unexpired + matching)
 * to eliminate the TOCTOU race between validate and consume.  If zero
 * rows are affected, the nonce was invalid, expired, or already consumed.
 * On success, also returns the label column (empty string if NULL in DB)
 * so the caller can echo it in the bootstrap response.
 *
 * @param[in]  conn          Active PostgreSQL connection.
 * @param[in]  nonce_hex     Hex-encoded nonce to validate and consume.
 * @param[in]  domain        Domain to match (NULL or "" to skip check).
 * @param[in]  fp_hex        Fingerprint to match (NULL or "" to skip check).
 * @param[out] label_out     Buffer for the label (may be NULL if caller
 *                            doesn't care).  On success, written with
 *                            the label or empty string if the row's
 *                            label column is NULL.  Buffer must be at
 *                            least MTC_LABEL_MAX + 1 bytes.
 * @param[in]  label_out_sz  Size of label_out buffer.
 *
 * @return  1 if the nonce was valid and is now consumed, 0 otherwise.
 */
int  mtc_db_validate_and_consume_nonce(PGconn *conn, const char *nonce_hex,
                                       const char *domain, const char *fp_hex,
                                       char *label_out, size_t label_out_sz);

/**
 * @brief    Mark a nonce as consumed (unconditionally).
 *
 * @param[in] conn       Active PostgreSQL connection.
 * @param[in] nonce_hex  Hex-encoded nonce to consume.
 */
void mtc_db_consume_nonce(PGconn *conn, const char *nonce_hex);

/**
 * @brief    Expire all pending nonces that have passed their TTL.
 *
 * @details
 * Sets status = 'expired' for all rows where status = 'pending' and
 * expires_at <= now().
 *
 * @param[in] conn  Active PostgreSQL connection.
 */
void mtc_db_expire_nonces(PGconn *conn);

/**
 * @brief    Cancel a pending reservation nonce early.
 *
 * @details
 * Atomically expires a pending nonce matching `(domain, label)`,
 * but only if `caller_ca_index` equals the nonce's stored
 * `ca_index` (i.e., the cancelling caller is the same CA that
 * issued the reservation).  This lets an operator retract a
 * long-lived reservation without waiting out the TTL —
 * otherwise the partial unique index `(domain, label) WHERE
 * status='pending'` would block re-issuance of a fresh
 * reservation for the same slot.
 *
 * @param[in] conn              Active PostgreSQL connection.
 * @param[in] domain            Domain the nonce was issued for.
 * @param[in] label             Label the nonce was bound to.
 * @param[in] caller_ca_index   MQC peer's cert_index (must match).
 *
 * @return  1 if exactly one row cancelled, 0 if no matching
 *          pending nonce (wrong CA, wrong label, already consumed,
 *          or already expired), -1 on DB error.
 */
int mtc_db_cancel_nonce(PGconn *conn, const char *domain,
                        const char *label, int caller_ca_index);

/**
 * @brief    Check connection and reconnect if needed.
 *
 * @param[in,out] conn_ptr  Pointer to PGconn pointer. May be replaced
 *                          on reconnect.
 *
 * @return  0 if connected, -1 if reconnect failed.
 */
int mtc_db_ensure_connected(PGconn **conn_ptr);

/**
 * @brief    Look up a public key by name from mtc_public_keys.
 *
 * @param[in]  conn      Active PostgreSQL connection.
 * @param[in]  key_name  Key name to look up (e.g., domain or subject).
 *
 * @return  strdup'd PEM string on success (caller frees).  NULL if not found.
 */
char *mtc_db_get_public_key(PGconn *conn, const char *key_name);

/**
 * @brief    Upsert a public key PEM into mtc_public_keys.
 *
 * @details
 * Used by the bootstrap enrollment handler to record the leaf/CA
 * pubkey keyed by the same directory-name convention clients use
 * under ~/.TPM/ (subject or subject-label).
 *
 * @param[in] conn      Active PostgreSQL connection.
 * @param[in] key_name  Canonical name (subject or subject-label).
 * @param[in] key_pem   Full PEM-encoded public key.
 *
 * @return   0 on success (INSERT or UPDATE), -1 on query failure.
 */
int mtc_db_save_public_key(PGconn *conn, const char *key_name,
                           const char *key_pem);

#endif
