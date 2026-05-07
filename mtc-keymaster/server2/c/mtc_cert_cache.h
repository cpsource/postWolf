/**
 * @file mtc_cert_cache.h
 * @brief Bounded LRU cache for cert json_objects on the read path.
 *
 * @details
 * Phase-2 of TODO #74 moves the cert array out of MtcStore — every
 * /certificate/N read becomes a Neon round-trip on cache miss.  This
 * cache absorbs the verification-clusters-around-active-certs pattern
 * so steady-state latency stays close to the in-memory baseline.
 *
 * Ownership: the cache holds its own json_object_get() reference on
 * each cached cert.  `mtc_cert_cache_get` returns a NEW reference to
 * the caller (pre-bumped) — callers MUST `json_object_put` when done,
 * regardless of cache hit/miss.  Eviction `json_object_put`s the
 * cache's reference; if a caller still holds an outstanding reference
 * the underlying object stays alive until that ref is also dropped.
 *
 * Concurrency: not thread-safe.  Each forked child gets its own
 * cache via COW at fork time; subsequent inserts/evictions diverge
 * the child's copy from the parent's, but neither side mutates
 * shared memory so no synchronization is needed.
 *
 * @date 2026-05-07
 */

#ifndef MTC_CERT_CACHE_H
#define MTC_CERT_CACHE_H

#include <stdint.h>
#include <json-c/json.h>

/**
 * Default cache capacity (in cert entries).  At ~3 KB per ML-DSA-87
 * cert this puts the steady-state footprint at ~750 KB per process,
 * which COW-shares cleanly across forked children.  Tunable at
 * mtc_cert_cache_init time; not exposed on the wire (purely an
 * operator knob, see TODO #74 phase 2).
 */
#define MTC_CERT_CACHE_DEFAULT_CAP  256

/**
 * Per-slot record.  Internal — exposed only for the cache struct
 * literal layout below.  Slots with `cert == NULL` are empty.
 */
typedef struct {
    int                 idx;       /**< Cert log index, valid iff cert != NULL */
    struct json_object *cert;      /**< Cached cert (cache holds 1 ref) */
    uint64_t            last_used; /**< Monotonic counter for LRU eviction    */
} mtc_cert_cache_slot_t;

/**
 * Bounded LRU cache.
 *
 * Implementation: fixed-size array of slots; lookups are O(capacity)
 * linear scans (capacity defaults to 256, so a hit/miss costs ~256
 * int compares — vastly cheaper than the Neon RTT it avoids).
 * Eviction picks the slot with the smallest `last_used` counter.
 */
typedef struct {
    int                     capacity;
    uint64_t                next_age;
    mtc_cert_cache_slot_t  *slots;
} mtc_cert_cache_t;

/**
 * @brief    Initialise a cache with the given capacity.
 *
 * @param[in,out] cache     Cache to initialise.
 * @param[in]     capacity  Number of slots; if <= 0 uses
 *                          MTC_CERT_CACHE_DEFAULT_CAP.
 *
 * @return  0 on success, -1 on allocation failure.
 */
int  mtc_cert_cache_init(mtc_cert_cache_t *cache, int capacity);

/**
 * @brief    Drop all cached refs and free the slot array.
 */
void mtc_cert_cache_free(mtc_cert_cache_t *cache);

/**
 * @brief    Look up a cached cert; bumps recency on hit.
 *
 * @param[in,out] cache  Cache to query.
 * @param[in]     idx    Cert log index.
 *
 * @return  json_object* with caller-owned reference (must
 *          json_object_put), or NULL on miss.
 */
struct json_object *mtc_cert_cache_get(mtc_cert_cache_t *cache, int idx);

/**
 * @brief    Insert or replace a cached cert; takes its own reference.
 *
 * @param[in,out] cache  Cache.
 * @param[in]     idx    Cert log index.
 * @param[in]     cert   json_object to cache (caller's ref stays
 *                       intact; cache calls json_object_get).
 *                       NULL is a no-op.
 */
void mtc_cert_cache_put(mtc_cert_cache_t *cache, int idx,
                        struct json_object *cert);

/**
 * @brief    Drop a specific cert from the cache (e.g. on revocation).
 *
 * No-op if the index isn't currently cached.
 */
void mtc_cert_cache_invalidate(mtc_cert_cache_t *cache, int idx);

#endif
