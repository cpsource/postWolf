/**
 * @file mtc_merkle_tiled.c
 * @brief Tiled Merkle tree backed by mtc_tile_store.
 *
 * See mtc_merkle_tiled.h for the public contract and the storage
 * tier layout (level 0 → mtc_log_entries.leaf_hash;
 * level 1..(THRESHOLD-1) → mtc_merkle_tiles tiles;
 * level >= THRESHOLD → mtc_merkle_top_nodes).
 *
 * Algorithms (mth_tiled, inclusion_path_tiled, consistency_subproof_tiled)
 * mirror the legacy implementations in mtc_merkle.c byte-for-byte; the
 * only difference is that node hashes come from the tile store rather
 * than a RAM array.
 */

#include "mtc_merkle_tiled.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* ------------------------------------------------------------------ */
/* In-RAM top-K array helpers                                          */
/* ------------------------------------------------------------------ */

/* Compare two (level, node_index) keys; -1/0/+1. */
static int top_cmp(int a_level, int64_t a_idx, int b_level, int64_t b_idx)
{
    if (a_level != b_level) return a_level < b_level ? -1 : 1;
    if (a_idx   != b_idx)   return a_idx   < b_idx   ? -1 : 1;
    return 0;
}

/* Binary-search the sorted top_nodes array for (level, node_index).
 * Returns the index of the matching slot, or -(insertion_point + 1) if
 * not found.  Insertion point is the index where the new entry should
 * be inserted to keep the array sorted. */
static int top_search(const MtcTiledTree *tree, int level, int64_t node_idx)
{
    int lo = 0, hi = tree->top_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        int c = top_cmp(tree->top_nodes[mid].level,
                        tree->top_nodes[mid].node_index,
                        level, node_idx);
        if (c == 0) return mid;
        else if (c < 0) lo = mid + 1;
        else hi = mid - 1;
    }
    return -(lo + 1);
}

static int top_grow(MtcTiledTree *tree)
{
    int newcap = tree->top_capacity == 0 ? 64 : tree->top_capacity * 2;
    mtc_tile_top_node_t *tmp = (mtc_tile_top_node_t *)
        realloc(tree->top_nodes, (size_t)newcap * sizeof(*tmp));
    if (!tmp) return -1;
    tree->top_nodes = tmp;
    tree->top_capacity = newcap;
    return 0;
}

static int top_upsert(MtcTiledTree *tree, int level, int64_t node_idx,
                      const uint8_t hash[MTC_HASH_SIZE])
{
    int pos = top_search(tree, level, node_idx);
    if (pos >= 0) {
        memcpy(tree->top_nodes[pos].hash, hash, MTC_HASH_SIZE);
        return 0;
    }
    pos = -(pos + 1);
    if (tree->top_count >= tree->top_capacity) {
        if (top_grow(tree) != 0) return -1;
    }
    /* Shift right to make room at pos. */
    memmove(&tree->top_nodes[pos + 1], &tree->top_nodes[pos],
            (size_t)(tree->top_count - pos) * sizeof(tree->top_nodes[0]));
    tree->top_nodes[pos].level = level;
    tree->top_nodes[pos].node_index = node_idx;
    memcpy(tree->top_nodes[pos].hash, hash, MTC_HASH_SIZE);
    tree->top_count++;
    return 0;
}

static int top_get(const MtcTiledTree *tree, int level, int64_t node_idx,
                   uint8_t out[MTC_HASH_SIZE])
{
    int pos = top_search(tree, level, node_idx);
    if (pos < 0) return -1;
    memcpy(out, tree->top_nodes[pos].hash, MTC_HASH_SIZE);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Storage routing                                                     */
/* ------------------------------------------------------------------ */

/* Fetch the hash of the inner node at (level, node_index).
 * Routes to leaf store / tile store / top-K cache depending on level.
 * Returns 0 on success, -1 on miss (node doesn't exist), -2 on error. */
static int node_get(MtcTiledTree *tree, int level, int64_t node_index,
                    uint8_t out[MTC_HASH_SIZE])
{
    if (level == 0) {
        int rc = mtc_tile_store_get_leaf_hash(tree->conn, node_index, out);
        return rc == 0 ? 0 : -1;
    }
    if (level >= MTC_TOP_K_LEVEL_THRESHOLD) {
        return top_get(tree, level, node_index, out);
    }
    /* Tile store: cache → DB. */
    {
        int64_t tile_index = node_index >> MTC_TILE_HEIGHT;
        int     slot       = (int)(node_index & (MTC_TILE_LEAF_COUNT - 1));
        mtc_tile_cache_slot_t *cs =
            mtc_tile_cache_get(&tree->cache, level, tile_index);
        if (cs && slot < cs->node_count) {
            memcpy(out,
                   cs->hashes + (size_t)slot * MTC_TILE_HASH_SIZE,
                   MTC_TILE_HASH_SIZE);
            return 0;
        }
        if (cs) {
            /* Cached but slot beyond node_count — node doesn't exist
             * yet in the tile.  Fall through to DB to refresh in case
             * the tile grew since we last cached it. */
        }

        {
            uint8_t buf[MTC_TILE_BYTES];
            int count = 0;
            int rc = mtc_tile_store_get_tile(tree->conn, level, tile_index,
                                             buf, &count);
            if (rc == -1) return -1;       /* tile doesn't exist */
            if (rc != 0)  return -2;       /* query error */
            mtc_tile_cache_put(&tree->cache, level, tile_index, buf,
                               count, 0 /* not dirty */);
            if (slot >= count) return -1;
            memcpy(out, buf + (size_t)slot * MTC_TILE_HASH_SIZE,
                   MTC_TILE_HASH_SIZE);
            return 0;
        }
    }
}

/* Persist the hash of the inner node at (level, node_index).
 * Routes to top-K (table + RAM) or tile store.  Caller must hold the
 * append advisory lock + an open transaction. */
static int node_put(MtcTiledTree *tree, int level, int64_t node_index,
                    const uint8_t hash[MTC_HASH_SIZE])
{
    if (level == 0) {
        /* Leaf hashes live in mtc_log_entries; the caller's
         * mtc_db_save_entry already wrote them.  Nothing to do here. */
        return 0;
    }
    if (level >= MTC_TOP_K_LEVEL_THRESHOLD) {
        if (mtc_tile_store_put_top_node(tree->conn, level, node_index,
                                        hash) != 0)
            return -1;
        return top_upsert(tree, level, node_index, hash);
    }
    /* Tile store path: read-modify-write the tile. */
    {
        int64_t tile_index = node_index >> MTC_TILE_HEIGHT;
        int     slot       = (int)(node_index & (MTC_TILE_LEAF_COUNT - 1));
        uint8_t buf[MTC_TILE_BYTES];
        int     count = 0;

        mtc_tile_cache_slot_t *cs =
            mtc_tile_cache_get(&tree->cache, level, tile_index);
        if (cs) {
            memcpy(buf, cs->hashes,
                   (size_t)cs->node_count * MTC_TILE_HASH_SIZE);
            count = cs->node_count;
        } else {
            int rc = mtc_tile_store_get_tile(tree->conn, level, tile_index,
                                             buf, &count);
            if (rc == -1) {
                count = 0;          /* tile didn't exist yet */
            } else if (rc != 0) {
                return -1;
            }
        }

        if (slot + 1 > count) {
            /* Tile is growing; zero-fill any gap (shouldn't happen
             * under sequential append, but be defensive). */
            if (slot > count) {
                memset(buf + (size_t)count * MTC_TILE_HASH_SIZE, 0,
                       (size_t)(slot - count) * MTC_TILE_HASH_SIZE);
            }
            count = slot + 1;
        }
        memcpy(buf + (size_t)slot * MTC_TILE_HASH_SIZE, hash,
               MTC_TILE_HASH_SIZE);

        if (mtc_tile_store_put_tile(tree->conn, level, tile_index, buf,
                                    count) != 0)
            return -1;
        mtc_tile_cache_put(&tree->cache, level, tile_index, buf, count,
                           0 /* not dirty — we just persisted it */);
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Open / close                                                        */
/* ------------------------------------------------------------------ */

int mtc_tiled_tree_open(MtcTiledTree *tree, PGconn *conn,
                        const char *log_id)
{
    int64_t sz = 0;
    int rc;

    /* conn may be NULL for the test mock backend; the store layer
     * ignores it.  Production callers always pass a live conn. */
    if (!tree || !log_id) return -1;

    memset(tree, 0, sizeof(*tree));
    tree->conn = conn;
    snprintf(tree->log_id, sizeof(tree->log_id), "%s", log_id);

    if (mtc_tile_cache_init(&tree->cache, MTC_TILE_CACHE_DEFAULT_CAP) != 0)
        return -1;

    if (mtc_tile_store_get_tree_size(conn, &sz) != 0) {
        mtc_tile_cache_free(&tree->cache);
        return -1;
    }
    if (sz < 0) sz = 0;
    if (sz > 0x7fffffff) {
        fprintf(stderr,
                "[merkle_tiled] tree size %lld exceeds int range\n",
                (long long)sz);
        mtc_tile_cache_free(&tree->cache);
        return -1;
    }
    tree->size = (int)sz;

    /* Top-K snapshot.  MTC_TOP_K_MAX_NODES caps the array; we'll grow
     * dynamically up to that bound during runtime via top_grow(). */
    tree->top_capacity = 256;
    tree->top_nodes = (mtc_tile_top_node_t *)
        calloc((size_t)tree->top_capacity, sizeof(*tree->top_nodes));
    if (!tree->top_nodes) {
        mtc_tile_cache_free(&tree->cache);
        return -1;
    }

    rc = mtc_tile_store_load_top_nodes(conn, tree->top_nodes,
                                       tree->top_capacity);
    while (rc >= 0 && rc == tree->top_capacity) {
        /* Loaded all rows but hit our capacity; double and try again. */
        if (top_grow(tree) != 0) {
            free(tree->top_nodes);
            mtc_tile_cache_free(&tree->cache);
            return -1;
        }
        rc = mtc_tile_store_load_top_nodes(conn, tree->top_nodes,
                                           tree->top_capacity);
    }
    if (rc < 0) {
        free(tree->top_nodes);
        mtc_tile_cache_free(&tree->cache);
        return -1;
    }
    tree->top_count = rc;
    return 0;
}

void mtc_tiled_tree_close(MtcTiledTree *tree)
{
    if (!tree) return;
    mtc_tile_cache_free(&tree->cache);
    free(tree->top_nodes);
    tree->top_nodes = NULL;
    tree->top_count = 0;
    tree->top_capacity = 0;
    tree->size = 0;
    tree->conn = NULL;
}

/* ------------------------------------------------------------------ */
/* mth_tiled — recursive subtree hash                                  */
/* ------------------------------------------------------------------ */

/* Returns 0 on success, -1 on storage error. */
static int mth_tiled(MtcTiledTree *tree, int start, int end, uint8_t *out)
{
    int n = end - start;
    int k;
    uint8_t left[MTC_HASH_SIZE], right[MTC_HASH_SIZE];

    if (n == 1)
        return node_get(tree, 0, (int64_t)start, out) == 0 ? 0 : -1;

    /* Largest power of 2 less than n (RFC 9162 split). */
    k = 1;
    while (k * 2 < n) k *= 2;

    /* If [start, start+n) is a complete power-of-2 subtree at a
     * multiple of itself (start % n == 0) then the inner-node hash is
     * stored in the tile store / top-K.  Look it up directly. */
    if (n == k * 2 && (start % n) == 0) {
        int level = 0;
        int tmp = n;
        while (tmp > 1) { level++; tmp >>= 1; }
        if (node_get(tree, level, (int64_t)(start / n), out) == 0)
            return 0;
        /* Fall through: stored hash missing for some reason; recompute. */
    }

    if (mth_tiled(tree, start, start + k, left) != 0) return -1;
    if (mth_tiled(tree, start + k, end, right) != 0) return -1;
    mtc_hash_node(left, right, out);
    return 0;
}

int mtc_tiled_tree_root_hash(MtcTiledTree *tree, int tree_size, uint8_t *out)
{
    if (!tree || !out) return -1;
    if (tree_size <= 0 || tree_size > tree->size) {
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        wc_Sha256Final(&sha, out);
        wc_Sha256Free(&sha);
        return 0;
    }
    return mth_tiled(tree, 0, tree_size, out);
}

int mtc_tiled_tree_subtree_hash(MtcTiledTree *tree, int start, int end,
                                uint8_t *out)
{
    if (!tree || !out) return -1;
    if (start < 0 || end > tree->size || start >= end) return -1;
    return mth_tiled(tree, start, end, out);
}

/* ------------------------------------------------------------------ */
/* Inclusion proof                                                     */
/* ------------------------------------------------------------------ */

/* Returns 0 on success, -1 on error. */
static int inclusion_path_tiled(MtcTiledTree *tree, int m, int n, int offset,
                                uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (n == 1) return 0;

    k = 1;
    while (k * 2 < n) k *= 2;

    if (m < k) {
        if (inclusion_path_tiled(tree, m, k, offset, proof, count) != 0)
            return -1;
        if (mth_tiled(tree, offset + k, offset + n, h) != 0) return -1;
    } else {
        if (inclusion_path_tiled(tree, m - k, n - k, offset + k,
                                 proof, count) != 0)
            return -1;
        if (mth_tiled(tree, offset, offset + k, h) != 0) return -1;
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
    return 0;
}

int mtc_tiled_tree_inclusion_proof(MtcTiledTree *tree, int index,
                                   int start, int end,
                                   uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (!tree || !proof_out || !proof_count) return -1;
    if (index < start || index >= end || end > tree->size) return -1;

    max_depth = 0;
    { int tmp = end - start; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t *)malloc((size_t)max_depth * MTC_HASH_SIZE);
    if (!proof) return -1;

    if (inclusion_path_tiled(tree, index - start, end - start, start,
                             proof, &count) != 0) {
        free(proof);
        return -1;
    }

    *proof_out = proof;
    *proof_count = count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Consistency proof                                                   */
/* ------------------------------------------------------------------ */

static int consistency_subproof_tiled(MtcTiledTree *tree, int m, int n,
                                      int offset, int start_from_old,
                                      uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (m == n) {
        if (!start_from_old) {
            if (mth_tiled(tree, offset, offset + n, h) != 0) return -1;
            memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
            (*count)++;
        }
        return 0;
    }

    k = 1;
    while (k * 2 < n) k *= 2;

    if (m <= k) {
        if (consistency_subproof_tiled(tree, m, k, offset,
                                       start_from_old, proof, count) != 0)
            return -1;
        if (mth_tiled(tree, offset + k, offset + n, h) != 0) return -1;
    } else {
        if (consistency_subproof_tiled(tree, m - k, n - k, offset + k,
                                       0, proof, count) != 0)
            return -1;
        if (mth_tiled(tree, offset, offset + k, h) != 0) return -1;
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
    return 0;
}

int mtc_tiled_tree_consistency_proof(MtcTiledTree *tree, int old_size,
                                     int new_size,
                                     uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (!tree || !proof_out || !proof_count) return -1;
    if (old_size < 1 || new_size > tree->size || old_size > new_size)
        return -1;

    max_depth = 0;
    { int tmp = new_size; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t *)malloc((size_t)max_depth * MTC_HASH_SIZE);
    if (!proof) return -1;

    if (consistency_subproof_tiled(tree, old_size, new_size, 0, 1,
                                   proof, &count) != 0) {
        free(proof);
        return -1;
    }

    *proof_out = proof;
    *proof_count = count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Append                                                              */
/* ------------------------------------------------------------------ */

int mtc_tiled_tree_append_leaf(MtcTiledTree *tree, const uint8_t *leaf_hash)
{
    int64_t pos;
    int level;
    uint8_t cur[MTC_HASH_SIZE];

    if (!tree || !leaf_hash) return -1;

    pos = (int64_t)tree->size;
    memcpy(cur, leaf_hash, MTC_HASH_SIZE);

    /* Leaf-level (level 0) hash is already in mtc_log_entries via the
     * caller's mtc_db_save_entry; no node_put call needed for level 0. */

    /* Walk up: for each level, if the just-completed node has an odd
     * coordinate, its parent is now complete and we hash it.  Stop
     * when we reach an even-coordinate node (parent not yet
     * complete). */
    for (level = 1; level < 64; level++) {
        if ((pos & 1) == 0) break;     /* parent at this level not ready */
        {
            int64_t left_idx  = pos - 1;
            int64_t parent_idx = pos >> 1;
            uint8_t left[MTC_HASH_SIZE];
            uint8_t parent_hash[MTC_HASH_SIZE];
            if (node_get(tree, level - 1, left_idx, left) != 0) {
                fprintf(stderr,
                        "[merkle_tiled] append: missing sibling "
                        "(level=%d, idx=%lld)\n",
                        level - 1, (long long)left_idx);
                return -1;
            }
            mtc_hash_node(left, cur, parent_hash);
            if (node_put(tree, level, parent_idx, parent_hash) != 0)
                return -1;
            memcpy(cur, parent_hash, MTC_HASH_SIZE);
            pos = parent_idx;
        }
    }

    {
        int idx = tree->size;
        tree->size++;
        return idx;
    }
}
