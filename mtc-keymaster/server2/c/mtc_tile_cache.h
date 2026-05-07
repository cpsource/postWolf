/**
 * @file mtc_tile_cache.h
 * @brief Bounded LRU cache for Merkle tile pages (TODO #74 phase 3).
 *
 * @details
 * The tiled Merkle tree pages lower-level inner-node hashes from
 * `mtc_merkle_tiles` on demand.  This cache bounds the working set so
 * proof generation runs in O(log N) tile fetches with most fetches
 * served from RAM.
 *
 * Ownership: each slot owns a fixed-size `hashes[MTC_TILE_BYTES]`
 * buffer; `node_count` indicates how many of those 256 hash slots are
 * filled (partial tiles at the rightmost edge of a level may have
 * count < 256).  `dirty` is set when the cached tile has uncommitted
 * mutations from the current append; the writer flushes dirty tiles to
 * the DB before eviction.
 *
 * Concurrency: not thread-safe.  Each forked child gets its own cache
 * via COW at fork time; subsequent inserts/evictions diverge the
 * child's copy from the parent's, but neither side mutates shared
 * memory so no synchronization is needed.  This mirrors the cert_cache
 * pattern from phase 2.
 *
 * @date 2026-05-07
 */

#ifndef MTC_TILE_CACHE_H
#define MTC_TILE_CACHE_H

#include <stdint.h>
#include "mtc_tile.h"

typedef struct {
    int      level;        /**< Tree level; 0 = leaf row.                */
    int64_t  tile_index;   /**< Tile coordinate at @p level.             */
    int      node_count;   /**< Number of valid hashes in @p hashes.     */
    int      dirty;        /**< 1 if the tile has uncommitted writes.    */
    uint64_t last_used;    /**< Monotonic counter for LRU eviction.      */
    uint8_t  hashes[MTC_TILE_BYTES]; /**< Packed 32-byte hashes.        */
} mtc_tile_cache_slot_t;

/**
 * Bounded LRU cache.
 *
 * Implementation: fixed-size array of slots; lookups are O(capacity)
 * linear scans (capacity defaults to 1024, so a hit/miss costs ~1024
 * comparisons of (level, tile_index) — vastly cheaper than the Neon
 * RTT it avoids).  Eviction picks the slot with the smallest
 * `last_used` counter; if `dirty`, the caller is responsible for
 * flushing to the store before eviction (the cache itself does not
 * hold a DB connection).
 */
typedef struct {
    int                     capacity;
    uint64_t                next_age;
    mtc_tile_cache_slot_t  *slots;
} mtc_tile_cache_t;

/**
 * @brief    Initialise a cache with the given capacity.
 *
 * @param[in,out] cache     Cache to initialise.
 * @param[in]     capacity  Number of slots; if <= 0 uses
 *                          MTC_TILE_CACHE_DEFAULT_CAP.
 *
 * @return  0 on success, -1 on allocation failure.
 */
int  mtc_tile_cache_init(mtc_tile_cache_t *cache, int capacity);

/**
 * @brief    Drop all slots and free the slot array.
 *
 * @details
 * Does NOT flush dirty tiles — the caller must ensure dirty tiles
 * are flushed to the store before calling this.
 */
void mtc_tile_cache_free(mtc_tile_cache_t *cache);

/**
 * @brief    Look up a cached tile; bumps recency on hit.
 *
 * @param[in,out] cache       Cache to query.
 * @param[in]     level       Tree level.
 * @param[in]     tile_index  Tile coordinate.
 *
 * @return  Pointer to the slot on hit (caller may read the hashes
 *          buffer in place; valid until the next put/invalidate),
 *          or NULL on miss.
 */
mtc_tile_cache_slot_t *mtc_tile_cache_get(mtc_tile_cache_t *cache,
                                          int level, int64_t tile_index);

/**
 * @brief    Insert or replace a cached tile.
 *
 * @param[in,out] cache       Cache.
 * @param[in]     level       Tree level.
 * @param[in]     tile_index  Tile coordinate.
 * @param[in]     hashes      Source buffer of @p node_count *
 *                            MTC_TILE_HASH_SIZE bytes.
 * @param[in]     node_count  Number of hashes (1..MTC_TILE_LEAF_COUNT).
 * @param[in]     dirty       1 if the tile has uncommitted writes.
 *
 * @return  Pointer to the (possibly evicted-and-rewritten) slot on
 *          success, or NULL on invalid input.  The returned slot has
 *          its `last_used` bumped.
 *
 * @note    If eviction selects a dirty slot, this function does NOT
 *          flush — the caller's responsibility is to flush dirty
 *          tiles to the store explicitly before putting a new tile
 *          when the cache is full of dirty entries.  Use
 *          mtc_tile_cache_find_dirty() to iterate dirty slots.
 */
mtc_tile_cache_slot_t *mtc_tile_cache_put(mtc_tile_cache_t *cache,
                                          int level, int64_t tile_index,
                                          const uint8_t *hashes,
                                          int node_count, int dirty);

/**
 * @brief    Drop a specific tile from the cache.
 *
 * No-op if the (level, tile_index) isn't currently cached.  Does NOT
 * flush dirty tiles — caller must flush first.
 */
void mtc_tile_cache_invalidate(mtc_tile_cache_t *cache,
                               int level, int64_t tile_index);

/**
 * @brief    Iterate dirty slots for flushing.
 *
 * @param[in]     cache  Cache.
 * @param[in,out] cursor In/out: pass *cursor = 0 on first call;
 *                       function updates it for the next iteration.
 *
 * @return  Pointer to the next dirty slot, or NULL when no more
 *          dirty slots exist.  The caller is expected to flush the
 *          slot to the store and then clear `slot->dirty = 0` before
 *          continuing iteration.
 */
mtc_tile_cache_slot_t *mtc_tile_cache_find_dirty(mtc_tile_cache_t *cache,
                                                  int *cursor);

#endif
