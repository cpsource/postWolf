/**
 * @file mtc_cert_cache.c
 * @brief Implementation of the bounded LRU cache for cert json_objects.
 *
 * See mtc_cert_cache.h for the public contract; this file only
 * implements it.
 */

#include "mtc_cert_cache.h"
#include <stdlib.h>
#include <string.h>

int mtc_cert_cache_init(mtc_cert_cache_t *cache, int capacity)
{
    if (!cache) return -1;
    if (capacity <= 0) capacity = MTC_CERT_CACHE_DEFAULT_CAP;
    cache->capacity = capacity;
    cache->next_age = 0;
    cache->slots = (mtc_cert_cache_slot_t *)
        calloc((size_t)capacity, sizeof(mtc_cert_cache_slot_t));
    return cache->slots ? 0 : -1;
}

void mtc_cert_cache_free(mtc_cert_cache_t *cache)
{
    int i;
    if (!cache || !cache->slots) return;
    for (i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].cert) {
            json_object_put(cache->slots[i].cert);
            cache->slots[i].cert = NULL;
        }
    }
    free(cache->slots);
    cache->slots = NULL;
    cache->capacity = 0;
}

struct json_object *mtc_cert_cache_get(mtc_cert_cache_t *cache, int idx)
{
    int i;
    if (!cache || !cache->slots || idx < 0) return NULL;
    for (i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].cert && cache->slots[i].idx == idx) {
            cache->slots[i].last_used = ++cache->next_age;
            return json_object_get(cache->slots[i].cert);
        }
    }
    return NULL;
}

void mtc_cert_cache_put(mtc_cert_cache_t *cache, int idx,
                        struct json_object *cert)
{
    int i, victim;
    uint64_t oldest;

    if (!cache || !cache->slots || !cert || idx < 0) return;

    /* If the index is already present, replace in place. */
    for (i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].cert && cache->slots[i].idx == idx) {
            json_object_put(cache->slots[i].cert);
            cache->slots[i].cert = json_object_get(cert);
            cache->slots[i].last_used = ++cache->next_age;
            return;
        }
    }

    /* Take an empty slot if available. */
    for (i = 0; i < cache->capacity; i++) {
        if (!cache->slots[i].cert) {
            cache->slots[i].idx = idx;
            cache->slots[i].cert = json_object_get(cert);
            cache->slots[i].last_used = ++cache->next_age;
            return;
        }
    }

    /* Otherwise evict the slot with the smallest last_used. */
    victim = 0;
    oldest = cache->slots[0].last_used;
    for (i = 1; i < cache->capacity; i++) {
        if (cache->slots[i].last_used < oldest) {
            oldest = cache->slots[i].last_used;
            victim = i;
        }
    }
    json_object_put(cache->slots[victim].cert);
    cache->slots[victim].idx = idx;
    cache->slots[victim].cert = json_object_get(cert);
    cache->slots[victim].last_used = ++cache->next_age;
}

void mtc_cert_cache_invalidate(mtc_cert_cache_t *cache, int idx)
{
    int i;
    if (!cache || !cache->slots || idx < 0) return;
    for (i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].cert && cache->slots[i].idx == idx) {
            json_object_put(cache->slots[i].cert);
            cache->slots[i].cert = NULL;
            cache->slots[i].idx = 0;
            cache->slots[i].last_used = 0;
            return;
        }
    }
}
