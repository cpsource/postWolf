/**
 * @file mtc_tile_cache.c
 * @brief Implementation of the bounded LRU tile cache.
 *
 * See mtc_tile_cache.h for the public contract.
 */

#include "mtc_tile_cache.h"

#include <stdlib.h>
#include <string.h>

int mtc_tile_cache_init(mtc_tile_cache_t *cache, int capacity)
{
    if (!cache) return -1;
    if (capacity <= 0) capacity = MTC_TILE_CACHE_DEFAULT_CAP;
    cache->capacity = capacity;
    cache->next_age = 0;
    cache->slots = (mtc_tile_cache_slot_t *)
        calloc((size_t)capacity, sizeof(mtc_tile_cache_slot_t));
    if (!cache->slots) {
        cache->capacity = 0;
        return -1;
    }
    /* tile_index = -1 marks an empty slot.  level 0 + tile_index 0 is
     * a real coordinate, so we can't use the zero value as the empty
     * sentinel.  Use last_used == 0 as the empty sentinel — `put`
     * always assigns a fresh non-zero `next_age`, so any populated
     * slot has last_used > 0. */
    return 0;
}

void mtc_tile_cache_free(mtc_tile_cache_t *cache)
{
    if (!cache || !cache->slots) return;
    free(cache->slots);
    cache->slots = NULL;
    cache->capacity = 0;
    cache->next_age = 0;
}

mtc_tile_cache_slot_t *mtc_tile_cache_get(mtc_tile_cache_t *cache,
                                          int level, int64_t tile_index)
{
    int i;
    if (!cache || !cache->slots) return NULL;
    for (i = 0; i < cache->capacity; i++) {
        mtc_tile_cache_slot_t *s = &cache->slots[i];
        if (s->last_used != 0 &&
            s->level == level && s->tile_index == tile_index) {
            s->last_used = ++cache->next_age;
            return s;
        }
    }
    return NULL;
}

mtc_tile_cache_slot_t *mtc_tile_cache_put(mtc_tile_cache_t *cache,
                                          int level, int64_t tile_index,
                                          const uint8_t *hashes,
                                          int node_count, int dirty)
{
    int i, victim;
    uint64_t oldest;
    mtc_tile_cache_slot_t *s;
    size_t copy_bytes;

    if (!cache || !cache->slots || !hashes) return NULL;
    if (node_count <= 0 || node_count > MTC_TILE_LEAF_COUNT) return NULL;

    /* Replace in place if (level, tile_index) is already cached. */
    for (i = 0; i < cache->capacity; i++) {
        s = &cache->slots[i];
        if (s->last_used != 0 &&
            s->level == level && s->tile_index == tile_index) {
            copy_bytes = (size_t)node_count * MTC_TILE_HASH_SIZE;
            memcpy(s->hashes, hashes, copy_bytes);
            s->node_count = node_count;
            s->dirty = dirty;
            s->last_used = ++cache->next_age;
            return s;
        }
    }

    /* Take an empty slot if available. */
    for (i = 0; i < cache->capacity; i++) {
        s = &cache->slots[i];
        if (s->last_used == 0) {
            s->level = level;
            s->tile_index = tile_index;
            s->node_count = node_count;
            s->dirty = dirty;
            copy_bytes = (size_t)node_count * MTC_TILE_HASH_SIZE;
            memcpy(s->hashes, hashes, copy_bytes);
            s->last_used = ++cache->next_age;
            return s;
        }
    }

    /* Evict least-recently-used.  The caller is responsible for
     * flushing dirty tiles before calling put when the cache is full;
     * we don't have a DB connection here. */
    victim = 0;
    oldest = cache->slots[0].last_used;
    for (i = 1; i < cache->capacity; i++) {
        if (cache->slots[i].last_used < oldest) {
            oldest = cache->slots[i].last_used;
            victim = i;
        }
    }
    s = &cache->slots[victim];
    s->level = level;
    s->tile_index = tile_index;
    s->node_count = node_count;
    s->dirty = dirty;
    copy_bytes = (size_t)node_count * MTC_TILE_HASH_SIZE;
    memcpy(s->hashes, hashes, copy_bytes);
    s->last_used = ++cache->next_age;
    return s;
}

void mtc_tile_cache_invalidate(mtc_tile_cache_t *cache,
                               int level, int64_t tile_index)
{
    int i;
    if (!cache || !cache->slots) return;
    for (i = 0; i < cache->capacity; i++) {
        mtc_tile_cache_slot_t *s = &cache->slots[i];
        if (s->last_used != 0 &&
            s->level == level && s->tile_index == tile_index) {
            /* Mark empty by zeroing last_used; clear dirty so the
             * caller doesn't try to flush a now-evicted slot. */
            s->last_used = 0;
            s->dirty = 0;
            s->node_count = 0;
            return;
        }
    }
}

mtc_tile_cache_slot_t *mtc_tile_cache_find_dirty(mtc_tile_cache_t *cache,
                                                  int *cursor)
{
    int i;
    if (!cache || !cache->slots || !cursor) return NULL;
    for (i = *cursor; i < cache->capacity; i++) {
        if (cache->slots[i].last_used != 0 && cache->slots[i].dirty) {
            *cursor = i + 1;
            return &cache->slots[i];
        }
    }
    *cursor = cache->capacity;
    return NULL;
}
