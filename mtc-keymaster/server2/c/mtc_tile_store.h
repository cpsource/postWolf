/**
 * @file mtc_tile_store.h
 * @brief Backend-agnostic API for the tiled Merkle tree storage layer.
 *
 * @details
 * The Postgres backend lives in mtc_tile_store_pg.c.  Test binaries
 * substitute an in-memory mock (mtc_tile_store_mock.c, added in commit
 * B) by linking that .o instead of mtc_tile_store_pg.o; both
 * implementations satisfy this header.
 *
 * Coordinate system: see mtc_tile.h.  Leaf hashes (level 0 in the
 * conceptual tree, but stored in `mtc_log_entries.leaf_hash` rather
 * than as a tile) are fetched via `mtc_tile_store_get_leaf_hash`.
 * Inner-node tiles for levels >= 1 are fetched via
 * `mtc_tile_store_get_tile`.
 *
 * Concurrency: every append-mutating call must run inside a Postgres
 * transaction that has already taken `mtc_tile_store_lock_for_append`.
 * The lock is released automatically at COMMIT/ROLLBACK.
 *
 * @date 2026-05-07
 */

#ifndef MTC_TILE_STORE_H
#define MTC_TILE_STORE_H

#include <stdint.h>
#include <libpq-fe.h>

#include "mtc_tile.h"

/**
 * @brief    Fetch the leaf hash at the given log index.
 *
 * @details
 * Reads `leaf_hash` from `mtc_log_entries`.  Leaf hashes are not
 * duplicated into `mtc_merkle_tiles` — `mtc_log_entries` is the
 * authoritative source.
 *
 * @param[in]  conn        Active connection.
 * @param[in]  leaf_index  0-based log index.
 * @param[out] out         32-byte buffer (caller-owned).
 *
 * @return  0 on success; -1 if the leaf doesn't exist or on query
 *          error.
 */
int mtc_tile_store_get_leaf_hash(PGconn *conn, int64_t leaf_index,
                                 uint8_t out[MTC_TILE_HASH_SIZE]);

/**
 * @brief    Fetch a tile of inner-node hashes from `mtc_merkle_tiles`.
 *
 * @param[in]  conn        Active connection.
 * @param[in]  level       Tree level (>= 1; level 0 leaf hashes go
 *                         through `mtc_tile_store_get_leaf_hash`).
 * @param[in]  tile_index  Tile coordinate at @p level.
 * @param[out] out_hashes  Buffer of at least MTC_TILE_BYTES bytes;
 *                         function writes `count_out *
 *                         MTC_TILE_HASH_SIZE` bytes.
 * @param[out] count_out   Number of hashes written (1 .. MTC_TILE_LEAF_COUNT).
 *
 * @return  0 on success; -1 if the tile doesn't exist; -2 on query
 *          error.
 */
int mtc_tile_store_get_tile(PGconn *conn, int level, int64_t tile_index,
                            uint8_t *out_hashes, int *count_out);

/**
 * @brief    UPSERT a tile of inner-node hashes.
 *
 * @details
 * Caller must already hold the append advisory lock.  `node_count`
 * may be < MTC_TILE_LEAF_COUNT for the rightmost partial tile at a
 * level; subsequent appends typically rewrite the same tile_index
 * with a higher node_count until it fills up.
 *
 * `tile_height` and `first_node` are stored alongside as redundant
 * documentation (derivable from level + tile_index + the constants
 * in mtc_tile.h, but useful for ad-hoc psql inspection).
 *
 * @return  0 on success; -1 on query error.
 */
int mtc_tile_store_put_tile(PGconn *conn, int level, int64_t tile_index,
                            const uint8_t *in_hashes, int node_count);

/**
 * @brief    Top-K node row, used by load_top_nodes.
 */
typedef struct {
    int     level;
    int64_t node_index;
    uint8_t hash[MTC_TILE_HASH_SIZE];
} mtc_tile_top_node_t;

/**
 * @brief    Load every row from `mtc_merkle_top_nodes`.
 *
 * @details
 * Called once at startup by `mtc_tiled_tree_open`.  The total row
 * count is bounded by MTC_TOP_K_MAX_NODES; the caller supplies an
 * array of that size.
 *
 * @param[in]  conn       Active connection.
 * @param[out] out_array  Caller-owned array; rows written in
 *                         (level ASC, node_index ASC) order.
 * @param[in]  max_count  Capacity of @p out_array.
 *
 * @return  Number of rows written (>= 0), or -1 on query error.
 */
int mtc_tile_store_load_top_nodes(PGconn *conn,
                                  mtc_tile_top_node_t *out_array,
                                  int max_count);

/**
 * @brief    UPSERT a single top-K node.
 *
 * @return  0 on success; -1 on query error.
 */
int mtc_tile_store_put_top_node(PGconn *conn, int level, int64_t node_index,
                                const uint8_t hash[MTC_TILE_HASH_SIZE]);

/**
 * @brief    Take the per-log advisory lock for the current transaction.
 *
 * @details
 * Caller must already be in a Postgres transaction (e.g. via
 * `BEGIN`).  The lock is released automatically at COMMIT/ROLLBACK.
 * Multiple concurrent appends across forked children serialize on
 * this lock.  Key derivation: FNV-1a-64 over @p log_id (deterministic
 * across processes and restarts).
 *
 * @return  0 on success; -1 on query error.
 */
int mtc_tile_store_lock_for_append(PGconn *conn, const char *log_id);

/**
 * @brief    Compute the current tree size from `mtc_log_entries`.
 *
 * @details
 * Returns `MAX(index) + 1`, or 0 if the table is empty.  Used at
 * startup to seed `tree->size` before any tiles are touched.
 *
 * @return  0 on success; -1 on query error.
 */
int mtc_tile_store_get_tree_size(PGconn *conn, int64_t *size_out);

#endif
