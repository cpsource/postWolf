/**
 * @file mtc_tile_store_mock.c
 * @brief In-memory mock backend for mtc_tile_store.h.
 *
 * Used by test_merkle_tiled.c to exercise the tiled tree without a
 * live Postgres connection.  Same symbols as mtc_tile_store_pg.c, so
 * test binaries link this .c instead of the PG impl; production never
 * sees the mock.
 *
 * Storage:
 *   - leaves   : sorted array indexed by leaf_index → 32-byte hash
 *   - tiles    : linked list of (level, tile_index, count, hashes)
 *   - top_nodes: sorted array of (level, node_index, hash)
 *
 * The PGconn* parameter is ignored by every function; tests pass NULL
 * for it.  Advisory lock + tree_size queries are no-ops / counters.
 *
 * Concurrency: single-threaded test only.
 */

#include "mtc_tile_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Mock state (file-scope singletons; tests reset between runs).      */
/* ------------------------------------------------------------------ */

typedef struct {
    int     used;
    uint8_t hash[MTC_TILE_HASH_SIZE];
} mock_leaf_t;

typedef struct {
    int     level;
    int64_t tile_index;
    int     count;
    uint8_t hashes[MTC_TILE_BYTES];
} mock_tile_t;

typedef struct {
    int     level;
    int64_t node_index;
    uint8_t hash[MTC_TILE_HASH_SIZE];
} mock_top_t;

#define MOCK_MAX_LEAVES   100000
#define MOCK_MAX_TILES    8192
#define MOCK_MAX_TOPS     8192

static mock_leaf_t g_leaves[MOCK_MAX_LEAVES];
static int         g_leaf_count;        /* highest_index + 1 */

static mock_tile_t g_tiles[MOCK_MAX_TILES];
static int         g_tile_count;

static mock_top_t  g_tops[MOCK_MAX_TOPS];
static int         g_top_count;

/* Test-only API to seed/reset mock state.  Not declared in
 * mtc_tile_store.h because production code doesn't see it. */
void mtc_tile_store_mock_reset(void)
{
    memset(g_leaves, 0, sizeof(g_leaves));
    g_leaf_count = 0;
    g_tile_count = 0;
    g_top_count = 0;
}

void mtc_tile_store_mock_set_leaf(int64_t idx, const uint8_t hash[32])
{
    if (idx < 0 || idx >= MOCK_MAX_LEAVES) {
        fprintf(stderr, "[mock] set_leaf out of range: %lld\n",
                (long long)idx);
        exit(2);
    }
    memcpy(g_leaves[idx].hash, hash, MTC_TILE_HASH_SIZE);
    g_leaves[idx].used = 1;
    if ((int)idx + 1 > g_leaf_count) g_leaf_count = (int)idx + 1;
}

/* ------------------------------------------------------------------ */
/* mtc_tile_store_*: implementations                                  */
/* ------------------------------------------------------------------ */

int mtc_tile_store_get_leaf_hash(PGconn *conn, int64_t leaf_index,
                                 uint8_t out[MTC_TILE_HASH_SIZE])
{
    (void)conn;
    if (leaf_index < 0 || leaf_index >= MOCK_MAX_LEAVES) return -1;
    if (!g_leaves[leaf_index].used) return -1;
    memcpy(out, g_leaves[leaf_index].hash, MTC_TILE_HASH_SIZE);
    return 0;
}

int mtc_tile_store_get_tile(PGconn *conn, int level, int64_t tile_index,
                            uint8_t *out_hashes, int *count_out)
{
    int i;
    (void)conn;
    for (i = 0; i < g_tile_count; i++) {
        if (g_tiles[i].level == level &&
            g_tiles[i].tile_index == tile_index) {
            *count_out = g_tiles[i].count;
            memcpy(out_hashes, g_tiles[i].hashes,
                   (size_t)g_tiles[i].count * MTC_TILE_HASH_SIZE);
            return 0;
        }
    }
    return -1;
}

int mtc_tile_store_put_tile(PGconn *conn, int level, int64_t tile_index,
                            const uint8_t *in_hashes, int node_count)
{
    int i;
    (void)conn;
    for (i = 0; i < g_tile_count; i++) {
        if (g_tiles[i].level == level &&
            g_tiles[i].tile_index == tile_index) {
            g_tiles[i].count = node_count;
            memcpy(g_tiles[i].hashes, in_hashes,
                   (size_t)node_count * MTC_TILE_HASH_SIZE);
            return 0;
        }
    }
    if (g_tile_count >= MOCK_MAX_TILES) {
        fprintf(stderr, "[mock] tile table full\n");
        return -1;
    }
    g_tiles[g_tile_count].level = level;
    g_tiles[g_tile_count].tile_index = tile_index;
    g_tiles[g_tile_count].count = node_count;
    memcpy(g_tiles[g_tile_count].hashes, in_hashes,
           (size_t)node_count * MTC_TILE_HASH_SIZE);
    g_tile_count++;
    return 0;
}

int mtc_tile_store_load_top_nodes(PGconn *conn,
                                  mtc_tile_top_node_t *out_array,
                                  int max_count)
{
    int i, n = g_top_count;
    (void)conn;
    if (n > max_count) n = max_count;
    for (i = 0; i < n; i++) {
        out_array[i].level = g_tops[i].level;
        out_array[i].node_index = g_tops[i].node_index;
        memcpy(out_array[i].hash, g_tops[i].hash, MTC_TILE_HASH_SIZE);
    }
    return n;
}

int mtc_tile_store_put_top_node(PGconn *conn, int level, int64_t node_index,
                                const uint8_t hash[MTC_TILE_HASH_SIZE])
{
    int i;
    (void)conn;
    for (i = 0; i < g_top_count; i++) {
        if (g_tops[i].level == level &&
            g_tops[i].node_index == node_index) {
            memcpy(g_tops[i].hash, hash, MTC_TILE_HASH_SIZE);
            return 0;
        }
    }
    if (g_top_count >= MOCK_MAX_TOPS) {
        fprintf(stderr, "[mock] top table full\n");
        return -1;
    }
    g_tops[g_top_count].level = level;
    g_tops[g_top_count].node_index = node_index;
    memcpy(g_tops[g_top_count].hash, hash, MTC_TILE_HASH_SIZE);
    g_top_count++;
    return 0;
}

int mtc_tile_store_lock_for_append(PGconn *conn, const char *log_id)
{
    (void)conn;
    (void)log_id;
    return 0;
}

int mtc_tile_store_get_tree_size(PGconn *conn, int64_t *size_out)
{
    (void)conn;
    *size_out = (int64_t)g_leaf_count;
    return 0;
}
