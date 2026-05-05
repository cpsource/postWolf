/**
 * @file mtc_store.h
 * @brief Persistence and CA operations for the MTC CA server.
 *
 * @details
 * Manages all server-side state: the Merkle tree, issued certificates,
 * checkpoints, landmarks, revocations, and the ML-DSA-87 CA signing key.
 * Supports two storage backends:
 *   - PostgreSQL (Neon) when MERKLE_NEON is available
 *   - File-based JSON in data_dir as fallback
 *
 * The store owns all memory for its internal arrays (certificates,
 * checkpoints, revocations).  Call mtc_store_free() to release.
 *
 * Thread safety: NOT thread-safe.  All operations must be serialised.
 *
 * @date 2026-04-13
 */

#ifndef MTC_STORE_H
#define MTC_STORE_H

#include "mtc_merkle.h"
#include "mtc_db.h"
#include <json-c/json.h>

#define MTC_MAX_CERTS          10000  /**< Upper bound for revocation loading   */
#define MTC_MAX_LANDMARKS      1000   /**< Maximum landmark entries             */
#define MTC_LANDMARK_INTERVAL  16     /**< Tree sizes divisible by this become
                                           landmarks automatically             */

/**
 * @brief Central state container for the MTC CA server.
 *
 * @details
 * Aggregates the Merkle tree, CA identity, signing key, issued
 * certificates, checkpoints, landmarks, and revocations.  Created by
 * mtc_store_init() and destroyed by mtc_store_free().
 *
 * Ownership: the store owns all json_object pointers in the certificates
 * and checkpoints arrays (ref-counted via json_object_get/put).
 */
typedef struct {
    char             data_dir[512];    /**< File-based storage directory        */
    PGconn          *db;               /**< PostgreSQL connection (NULL = file
                                            mode).  Owned by the store.        */
    int              use_db;           /**< 1 = PostgreSQL active, 0 = files   */

    /* CA identity */
    char             ca_name[64];      /**< CA display name                    */
    char             log_id[64];       /**< Log identifier (e.g. "32473.2")    */
    char             cosigner_id[64];  /**< Cosigner ID ("<log_id>.ca")        */

    /* ML-DSA-87 CA key (DER-encoded priv, raw pub).  Sized to
     * wolfCrypt's DILITHIUM_LEVEL5_* constants with a safety margin
     * on the DER form (raw priv = 4896 B, DER adds ~16 B header). */
    uint8_t          ca_priv_key[8192];  /**< Private key DER bytes            */
    int              ca_priv_key_sz;     /**< Private key size in bytes        */
    uint8_t          ca_pub_key[2592];   /**< Raw ML-DSA-87 public key (2592 B)*/
    int              ca_pub_key_sz;      /**< Public key size (always 2592)    */

    /* Merkle tree */
    MtcMerkleTree    tree;             /**< Append-only Merkle hash tree       */

    /* Issued certificates (indexed by log index) */
    struct json_object **certificates; /**< Array of certificate json_objects
                                            (store owns refs, slots may be NULL)*/
    int              cert_count;       /**< Number of slots in use             */
    int              cert_capacity;    /**< Allocated slots                    */

    /* Checkpoints */
    struct json_object **checkpoints;  /**< Array of checkpoint json_objects
                                            (store owns refs; max 256)         */
    int              checkpoint_count; /**< Number of checkpoints stored       */

    /* Landmarks (tree sizes that are multiples of MTC_LANDMARK_INTERVAL) */
    int              landmarks[MTC_MAX_LANDMARKS]; /**< Landmark tree sizes    */
    int              landmark_count;   /**< Number of recorded landmarks       */

    /* Revocations (sorted array of revoked cert indices) */
    int             *revoked_indices;  /**< Sorted array of revoked cert indices
                                            (store owns; NULL if none)         */
    int              revocation_count; /**< Number of revocations              */
    int              revocation_capacity; /**< Allocated slots                 */
} MtcStore;

/**
 * @brief    Initialise the store: create data dir, connect to DB, load
 *           or generate the CA key, and restore persisted state.
 *
 * @param[out] store     Store to initialise.
 * @param[in]  data_dir  Directory for file-based storage.
 * @param[in]  ca_name   CA display name.
 * @param[in]  log_id    Log identifier string.
 *
 * @return
 *   0   on success.
 *  -1   if the CA key could not be initialised.
 */
int  mtc_store_init(MtcStore *store, const char *data_dir,
                    const char *ca_name, const char *log_id);

/**
 * @brief    Free all memory owned by the store.
 *
 * @details
 * Frees the Merkle tree, all certificate and checkpoint json_objects,
 * and the certificate/checkpoint arrays.  Does NOT close the DB
 * connection (caller should call PQfinish separately if needed).
 *
 * @param[in,out] store  Store to free.
 */
void mtc_store_free(MtcStore *store);

/**
 * @brief    Persist current state to the data_dir as JSON files.
 *
 * @details
 * Writes entries.json, certificates.json, and landmarks.json.
 *
 * @param[in] store  Store to save.
 *
 * @return  0 on success.
 */
int  mtc_store_save(MtcStore *store);

/**
 * @brief    Reload tree/cert/landmark/revocation state from DB (or files).
 *
 * @details
 * Used by the parent's SIGHUP-driven reload thread (TODO #56 fix).
 * After a fork-after-accept child commits a new entry to the DB and
 * exits, the parent's in-memory state is stale; raising SIGHUP to the
 * parent triggers this function, which frees the per-state contents
 * (tree, certs, landmarks, revocations) and re-runs the DB load path
 * to resync.  The CA key, cosigner key, DB connection, and
 * configuration fields are NOT touched.
 *
 * @param[in,out] store  Store to refresh in place.
 *
 * @return  0 on success, -1 if @p store is NULL or load fails.
 */
int  mtc_store_reload(MtcStore *store);

/**
 * @brief    Sanity-check the cert/leaf invariant after load (TODO #57
 *           item 3).
 *
 * @details
 * For every non-NULL @p store->certificates[i] with a corresponding
 * leaf at @p store->tree.entries[i], compare the cert's
 * standalone_certificate.tbs_entry scalar fields (subject,
 * subject_public_key_algorithm, subject_public_key_hash, not_before,
 * not_after) to the same fields in the canonical leaf payload at
 * that index.  Any mismatch is logged at WARN with a pointer at the
 * `admin_recosign --repair-tbs --write` recovery path.
 *
 * Called automatically from mtc_store_init() and mtc_store_reload();
 * exposed so admin tools can run the check on demand.
 *
 * @param[in] store  Loaded store.
 *
 * @return  Count of divergent cert indices (0 = clean).
 */
int  mtc_store_check_invariants(MtcStore *store);

/**
 * @brief    Load state from DB (if available) or from data_dir JSON files.
 *
 * @param[in,out] store  Store to populate.
 *
 * @return  0 on success (an empty store is still success).
 */
int  mtc_store_load(MtcStore *store);

/**
 * @brief    Append a serialised entry to the Merkle tree and persist it.
 *
 * @details
 * Persists to DB FIRST (if connected), then appends to the tree, then
 * records a landmark if the new tree size is a multiple of
 * MTC_LANDMARK_INTERVAL.  This ordering means a DB write failure
 * leaves the in-memory tree untouched (TODO #57 item 4).
 *
 * Callers MUST check the return value: a -1 indicates the DB persist
 * failed and the operation has been aborted with no state change.
 * The caller is expected to surface the failure (e.g. abort the
 * enrollment) rather than continue as if the entry had been issued.
 *
 * @param[in,out] store    Target store.
 * @param[in]     entry    Serialised entry bytes.
 * @param[in]     entrySz  Size of entry in bytes.
 *
 * @return   0-based log index of the new entry on success.
 *          -1 if DB persistence failed (in-memory tree is unchanged).
 */
int  mtc_store_add_entry(MtcStore *store, const uint8_t *entry, int entrySz);

/**
 * @brief    Create a checkpoint for the current tree state.
 *
 * @param[in,out] store  Store (checkpoint is appended and persisted to DB).
 *
 * @return  New json_object checkpoint.  Caller owns the reference and must
 *          call json_object_put() when done.
 */
struct json_object *mtc_store_checkpoint(MtcStore *store);

/**
 * @brief    Cosign a subtree range [start, end) with the CA ML-DSA-87 key.
 *
 * @details
 * Builds the MTC subtree signature input per the MTC draft specification
 * and signs it with the CA's ML-DSA-87 private key.
 *
 * @param[in]  store    Store (provides CA key and tree).
 * @param[in]  start    Subtree start index (inclusive).
 * @param[in]  end      Subtree end index (exclusive).
 * @param[out] sig_out  Buffer for the signature (must be
 *                      >= DILITHIUM_LEVEL5_SIG_SIZE = 4627 bytes).
 * @param[out] sig_sz   Receives the signature size in bytes.
 *
 * @return  0 on success, non-zero wolfCrypt error code on failure.
 */
int  mtc_store_cosign(MtcStore *store, int start, int end,
                      uint8_t *sig_out, int *sig_sz);

/**
 * @brief    Export the CA public key as PEM.
 *
 * @param[in]  store  Store (provides CA key).
 * @param[out] out    Caller-owned buffer for the PEM string.
 * @param[in]  maxSz  Size of out in bytes.
 *
 * @return  Number of PEM bytes written on success, or a negative
 *          wolfCrypt error code on failure.
 */
int  mtc_store_get_public_key_pem(MtcStore *store, char *out, int maxSz);

/**
 * @brief    Revoke a certificate by log index.
 *
 * @param[in,out] store       Store.
 * @param[in]     cert_index  Log index of the certificate to revoke.
 * @param[in]     reason      Human-readable reason (may be NULL).
 *
 * @return
 *   0   on success (including if already revoked).
 *  -1   on memory allocation failure.
 */
int  mtc_store_revoke(MtcStore *store, int cert_index, const char *reason);

/**
 * @brief    Check whether a certificate is revoked.
 *
 * @param[in] store       Store.
 * @param[in] cert_index  Log index to check.
 *
 * @return  1 if revoked, 0 if not.
 */
int  mtc_store_is_revoked(MtcStore *store, int cert_index);

/**
 * @brief    Build a signed revocation list as a JSON object.
 *
 * @details
 * Returns a JSON object containing the log_id, revoked indices array,
 * count, timestamp, and an ML-DSA-87 signature over the indices array.
 *
 * @param[in] store  Store.
 *
 * @return  New json_object.  Caller owns and must free with
 *          json_object_put().
 */
struct json_object *mtc_store_get_revocation_list(MtcStore *store);

#endif
