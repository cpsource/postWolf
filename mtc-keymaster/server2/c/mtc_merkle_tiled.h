/**
 * @file mtc_merkle_tiled.h
 * @brief Tiled (DB-backed) Merkle tree (TODO #74 phase 3).
 *
 * @details
 * Same algorithmic surface as `mtc_merkle.h` (root_hash, subtree_hash,
 * inclusion_proof, consistency_proof — all RFC 9162 / CT v2) but with
 * the underlying leaf/inner-node hashes paged out to Postgres via the
 * `mtc_tile_store.h` abstraction.  Top-K levels of inner-node hashes
 * (those at level >= MTC_TOP_K_LEVEL_THRESHOLD) are pinned in RAM in
 * a small flat array; lower levels are tile-cached LRU-style.
 *
 * Append concurrency: callers run `mtc_tiled_tree_append_leaf` inside
 * a Postgres transaction that has already taken
 * `mtc_tile_store_lock_for_append` — see mtc_tile_store.h.  The tiled
 * tree itself does NOT depend on `mtc_db.c`; the caller is responsible
 * for persisting the leaf row to `mtc_log_entries` separately
 * (allows the tests to use a mock store without DB).
 *
 * Thread safety: not thread-safe.  Each forked child gets its own
 * cache via COW.  Same model as `mtc_cert_cache` from phase 2.
 *
 * @date 2026-05-07
 */

#ifndef MTC_MERKLE_TILED_H
#define MTC_MERKLE_TILED_H

#include <stdint.h>

#include <libpq-fe.h>

#include "mtc_merkle.h"      /* MTC_HASH_SIZE + mtc_hash_leaf/_node */
#include "mtc_tile.h"
#include "mtc_tile_cache.h"
#include "mtc_tile_store.h"

/**
 * @brief    Top-K storage threshold.
 *
 * @details
 * Nodes at level >= MTC_TOP_K_LEVEL_THRESHOLD are stored in
 * `mtc_merkle_top_nodes` and mirrored in the in-RAM `top_nodes`
 * array.  Nodes at level < MTC_TOP_K_LEVEL_THRESHOLD live in
 * `mtc_merkle_tiles` and fault through `tile_cache` on the read path.
 * Level 0 (leaves) is always stored in `mtc_log_entries.leaf_hash`.
 *
 * For trees up to ~10 M leaves the top-K node count is bounded at
 * ~5000, so the in-RAM array stays under 200 KB.
 */
#define MTC_TOP_K_LEVEL_THRESHOLD  12

/**
 * @brief    Tiled Merkle tree.
 *
 * @details
 * Holds:
 *   - the live Postgres connection (shared with the rest of the
 *     server2/c surface; the tree does not own it),
 *   - the FNV-1a-keyed log_id for advisory locks,
 *   - the current tree size (mirror of `MAX(index)+1` from
 *     `mtc_log_entries`),
 *   - the in-RAM top-K array (sorted by (level, node_index)),
 *   - the tile-cache LRU.
 */
typedef struct {
    PGconn               *conn;
    char                  log_id[64];
    int                   size;          /**< Current tree size.        */
    mtc_tile_cache_t      cache;
    mtc_tile_top_node_t  *top_nodes;     /**< Sorted by (level, idx).   */
    int                   top_count;
    int                   top_capacity;
} MtcTiledTree;

/**
 * @brief    Open a tiled tree against an existing Postgres connection.
 *
 * @details
 * Reads `MAX(index)+1` from `mtc_log_entries` for the size, allocates
 * the tile cache, and loads every row from `mtc_merkle_top_nodes`
 * into the in-RAM top-K array.
 *
 * @param[out] tree     Tree to initialise.
 * @param[in]  conn     Live Postgres connection (caller-owned).
 * @param[in]  log_id   Log identifier; used to derive the per-log
 *                       advisory-lock key.
 *
 * @return  0 on success, -1 on failure (state may be partially
 *          initialised; caller should call mtc_tiled_tree_close).
 */
int  mtc_tiled_tree_open(MtcTiledTree *tree, PGconn *conn,
                         const char *log_id);

/**
 * @brief    Free in-RAM resources owned by the tree.
 *
 * Does NOT close the Postgres connection (caller-owned).
 */
void mtc_tiled_tree_close(MtcTiledTree *tree);

/**
 * @brief    Tile-aware analogue of `mtc_tree_root_hash`.
 *
 * @return  0 on success.  Returns SHA-256("") in @p out for
 *          `tree_size <= 0 || tree_size > tree->size`.
 */
int  mtc_tiled_tree_root_hash(MtcTiledTree *tree, int tree_size,
                              uint8_t *out);

/**
 * @brief    Tile-aware analogue of `mtc_tree_subtree_hash`.
 *
 * @return  0 on success, -1 on out-of-range.
 */
int  mtc_tiled_tree_subtree_hash(MtcTiledTree *tree, int start, int end,
                                 uint8_t *out);

/**
 * @brief    Tile-aware analogue of `mtc_tree_inclusion_proof`.
 *
 * Caller must `free(*proof_out)` on success.  Same RFC 9162 §2.1.3
 * sibling-path layout as the legacy implementation.
 */
int  mtc_tiled_tree_inclusion_proof(MtcTiledTree *tree, int index,
                                    int start, int end,
                                    uint8_t **proof_out,
                                    int *proof_count);

/**
 * @brief    Tile-aware analogue of `mtc_tree_consistency_proof`.
 */
int  mtc_tiled_tree_consistency_proof(MtcTiledTree *tree, int old_size,
                                      int new_size,
                                      uint8_t **proof_out,
                                      int *proof_count);

/**
 * @brief    Append a leaf hash and update affected inner-node tiles.
 *
 * @details
 * Caller is responsible for:
 *   1. Beginning a Postgres transaction.
 *   2. Taking the advisory lock via `mtc_tile_store_lock_for_append`.
 *   3. Persisting the leaf row (`mtc_db_save_entry`) so subsequent
 *      readers see `index = tree->size` with the same leaf_hash.
 *   4. Calling this function with the same leaf hash.
 *   5. Committing the transaction.
 *
 * The tree's in-RAM `size` is incremented on success.  On failure
 * the transaction must be rolled back; the caller should not trust
 * `tree->size` until reload.
 *
 * @param[in,out] tree       Tree.
 * @param[in]     leaf_hash  32-byte leaf hash.
 *
 * @return  0-based index of the new leaf on success, -1 on failure.
 */
int  mtc_tiled_tree_append_leaf(MtcTiledTree *tree,
                                const uint8_t *leaf_hash);

#endif
