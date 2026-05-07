/**
 * @file mtc_store.h
 * @brief Persistence and CA operations for the MTC CA server.
 *
 * @details
 * Manages all server-side state: the tiled Merkle tree (TODO #74 phase 3),
 * checkpoints, the cert-cache LRU, and the ML-DSA-87 CA signing key.
 *
 * Storage backend: Postgres (Neon).  File-mode was retired in TODO #74
 * phase 3 — the server refuses to start without a working DB connection.
 *
 * Cert blobs and revocations are NOT held in RAM; reads fault through
 * `mtc_store_get_cert` (cert_cache → Neon) and `mtc_store_is_revoked`
 * (mtc_db_is_revoked) on demand.
 *
 * Thread safety: NOT thread-safe.  All operations must be serialised.
 *
 * @date 2026-04-13 (rewritten 2026-05-07 for phase 3)
 */

#ifndef MTC_STORE_H
#define MTC_STORE_H

#include "mtc_merkle.h"        /* MTC_HASH_SIZE constant + hash helpers */
#include "mtc_merkle_tiled.h"
#include "mtc_db.h"
#include "mtc_cert_cache.h"
#include <json-c/json.h>

#define MTC_MAX_CERTS          10000  /**< Upper bound for revocation enumeration */

/**
 * @brief Central state container for the MTC CA server.
 *
 * @details
 * Aggregates the tiled Merkle tree, CA identity, signing key, the
 * checkpoint cache, and the cert-cache LRU.  Created by mtc_store_init()
 * and destroyed by mtc_store_free().
 */
typedef struct {
    char             data_dir[512];    /**< File-based storage directory
                                            (kept for compatibility; CA-key
                                            files still live here)        */
    PGconn          *db;               /**< PostgreSQL connection.
                                            Required (no file mode).      */
    int              use_db;           /**< Always 1 post-phase-3.        */

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

    /* Tiled Merkle tree (TODO #74 phase 3).  Holds the top-K node
     * snapshot in RAM; lower levels page through cert_cache + Neon. */
    MtcTiledTree     tree;

    /* Bounded LRU on the cert read path.  Populated by
     * mtc_store_get_cert.  Each forked child inherits the parent's
     * cache via COW; subsequent inserts/evictions diverge the
     * child's copy from the parent's. */
    mtc_cert_cache_t cert_cache;

    /* Checkpoints */
    struct json_object **checkpoints;  /**< Array of checkpoint json_objects
                                            (store owns refs; max 256)         */
    int              checkpoint_count; /**< Number of checkpoints stored       */
} MtcStore;

/**
 * @brief    Initialise the store: connect to DB, load or generate the
 *           CA key, and open the tiled Merkle tree.
 *
 * @return
 *   0   on success.
 *  -1   if the CA key could not be initialised, or the tile-store
 *       open failed (Neon unreachable, schema not initialised, etc.).
 */
int  mtc_store_init(MtcStore *store, const char *data_dir,
                    const char *ca_name, const char *log_id);

/**
 * @brief    Free all memory owned by the store.
 *
 * Does NOT close the DB connection.
 */
void mtc_store_free(MtcStore *store);

/**
 * @brief    Sanity-check the cert/leaf invariant after load (TODO #57
 *           item 3).  No-op in DB mode (post-phase-2).
 *
 * @return  Count of divergent cert indices (0 = clean).
 */
int  mtc_store_check_invariants(MtcStore *store);

/**
 * @brief    Look up a stored certificate by log index.
 *
 * @details
 * Consults the per-process cert_cache and falls through to
 * mtc_db_load_certificate on miss, caching the result for subsequent
 * lookups.  Returns a caller-owned reference (json_object_get-bumped);
 * callers MUST `json_object_put` when done.
 *
 * @return  json_object with caller-owned ref, or NULL.
 */
struct json_object *mtc_store_get_cert(MtcStore *store, int index);

/**
 * @brief    Append a serialised entry to the tiled Merkle tree.
 *
 * @details
 * Wraps the full operation in a Postgres transaction:
 *   1. BEGIN
 *   2. SELECT pg_advisory_xact_lock(<log_id-key>)
 *   3. mtc_db_save_entry  (writes leaf row + computed leaf hash)
 *   4. mtc_tiled_tree_append_leaf  (walks levels, writes tiles +
 *      top_nodes for each affected complete subtree)
 *   5. COMMIT
 *
 * Concurrent appends from sibling forked children serialise on the
 * advisory lock.  Failure at any step rolls back.
 *
 * @return  0-based log index of the new entry on success, -1 on
 *          failure (transaction rolled back).
 */
int  mtc_store_add_entry(MtcStore *store, const uint8_t *entry, int entrySz);

/**
 * @brief    Create a checkpoint for the current tree state.
 *
 * @return  New json_object checkpoint.  Caller owns the reference and must
 *          call json_object_put() when done.
 */
struct json_object *mtc_store_checkpoint(MtcStore *store);

/**
 * @brief    Cosign a subtree range [start, end) with the CA ML-DSA-87 key.
 */
int  mtc_store_cosign(MtcStore *store, int start, int end,
                      uint8_t *sig_out, int *sig_sz);

/**
 * @brief    Export the CA public key as PEM.
 */
int  mtc_store_get_public_key_pem(MtcStore *store, char *out, int maxSz);

/**
 * @brief    Revoke a certificate by log index.
 *
 * @return  0 on success (including if already revoked); -1 on DB error.
 */
int  mtc_store_revoke(MtcStore *store, int cert_index, const char *reason);

/**
 * @brief    Check whether a certificate is revoked.
 *
 * @return  1 if revoked, 0 if not.
 */
int  mtc_store_is_revoked(MtcStore *store, int cert_index);

/**
 * @brief    Build a signed revocation list as a JSON object.
 *
 * @return  New json_object.  Caller owns and must free with
 *          json_object_put().
 */
struct json_object *mtc_store_get_revocation_list(MtcStore *store);

#endif
