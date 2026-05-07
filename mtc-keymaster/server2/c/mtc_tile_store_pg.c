/**
 * @file mtc_tile_store_pg.c
 * @brief Postgres backend for the tiled Merkle tree store.
 *
 * Implements the API in mtc_tile_store.h against the schema declared
 * by `mtc_db_init_schema` (mtc_merkle_tiles, mtc_merkle_top_nodes).
 * See mtc_tile.h for the tile coordinate convention.
 */

#include "mtc_tile_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* FNV-1a 64-bit hash, used to turn log_id into a deterministic int8
 * key for pg_advisory_xact_lock.  Postgres advisory locks take a
 * single bigint or two ints; we use the single-arg form. */
static int64_t fnv1a_64(const char *s)
{
    const uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    const uint64_t FNV_PRIME  = 0x100000001b3ULL;
    uint64_t h = FNV_OFFSET;
    if (!s) return 0;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= FNV_PRIME;
    }
    /* Reinterpret as int64 — pg_advisory_xact_lock takes signed. */
    return (int64_t)h;
}

int mtc_tile_store_get_leaf_hash(PGconn *conn, int64_t leaf_index,
                                 uint8_t out[MTC_TILE_HASH_SIZE])
{
    PGresult *res;
    char idx_str[32];
    const char *params[1];
    int rc = -1;

    if (!conn || leaf_index < 0 || !out) return -1;

    snprintf(idx_str, sizeof(idx_str), "%" PRId64, leaf_index);
    params[0] = idx_str;

    res = PQexecParams(conn,
        "SELECT leaf_hash FROM mtc_log_entries WHERE index = $1",
        1, NULL, params, NULL, NULL, 1 /* binary result */);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0)
        goto out;

    {
        const char *bytes = PQgetvalue(res, 0, 0);
        int len = PQgetlength(res, 0, 0);
        if (len != MTC_TILE_HASH_SIZE) {
            fprintf(stderr,
                    "[tile_store] leaf %" PRId64
                    " has unexpected hash length %d\n",
                    leaf_index, len);
            goto out;
        }
        memcpy(out, bytes, MTC_TILE_HASH_SIZE);
        rc = 0;
    }

out:
    PQclear(res);
    return rc;
}

int mtc_tile_store_get_tile(PGconn *conn, int level, int64_t tile_index,
                            uint8_t *out_hashes, int *count_out)
{
    PGresult *res;
    char level_str[16], idx_str[32];
    const char *params[2];
    int rc = -1;

    if (!conn || level < 0 || tile_index < 0 || !out_hashes || !count_out)
        return -2;

    snprintf(level_str, sizeof(level_str), "%d", level);
    snprintf(idx_str,   sizeof(idx_str),   "%" PRId64, tile_index);
    params[0] = level_str;
    params[1] = idx_str;

    res = PQexecParams(conn,
        "SELECT hashes, node_count FROM mtc_merkle_tiles "
        "WHERE level = $1 AND tile_index = $2",
        2, NULL, params, NULL, NULL, 1 /* binary result */);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        rc = -2;
        goto out;
    }
    if (PQntuples(res) == 0) {
        rc = -1;
        goto out;
    }

    {
        const char *bytes = PQgetvalue(res, 0, 0);
        int blen = PQgetlength(res, 0, 0);
        const char *cnt_bytes = PQgetvalue(res, 0, 1);
        int clen = PQgetlength(res, 0, 1);
        int node_count;

        if (clen != 4) {
            fprintf(stderr,
                    "[tile_store] tile (%d,%" PRId64
                    ") node_count column has unexpected length %d\n",
                    level, tile_index, clen);
            rc = -2;
            goto out;
        }
        node_count = (int)((((unsigned char)cnt_bytes[0]) << 24) |
                           (((unsigned char)cnt_bytes[1]) << 16) |
                           (((unsigned char)cnt_bytes[2]) <<  8) |
                            ((unsigned char)cnt_bytes[3]));
        if (node_count < 1 || node_count > MTC_TILE_LEAF_COUNT) {
            fprintf(stderr,
                    "[tile_store] tile (%d,%" PRId64
                    ") has out-of-range node_count %d\n",
                    level, tile_index, node_count);
            rc = -2;
            goto out;
        }
        if (blen != node_count * MTC_TILE_HASH_SIZE) {
            fprintf(stderr,
                    "[tile_store] tile (%d,%" PRId64
                    ") hashes len %d != node_count %d * %d\n",
                    level, tile_index, blen, node_count,
                    MTC_TILE_HASH_SIZE);
            rc = -2;
            goto out;
        }
        memcpy(out_hashes, bytes, (size_t)blen);
        *count_out = node_count;
        rc = 0;
    }

out:
    PQclear(res);
    return rc;
}

int mtc_tile_store_put_tile(PGconn *conn, int level, int64_t tile_index,
                            const uint8_t *in_hashes, int node_count)
{
    PGresult *res;
    char level_str[16], tile_idx_str[32], height_str[16];
    char first_node_str[32], count_str[16];
    int64_t first_node;
    const char *params[6];
    int param_lens[6];
    int param_fmts[6] = {0, 0, 0, 0, 0, 1 /* hashes is binary */};
    int rc = -1;

    if (!conn || level < 0 || tile_index < 0 || !in_hashes ||
        node_count < 1 || node_count > MTC_TILE_LEAF_COUNT)
        return -1;

    first_node = tile_index * (int64_t)MTC_TILE_LEAF_COUNT;

    snprintf(level_str,      sizeof(level_str),      "%d", level);
    snprintf(tile_idx_str,   sizeof(tile_idx_str),   "%" PRId64, tile_index);
    snprintf(height_str,     sizeof(height_str),     "%d", MTC_TILE_HEIGHT);
    snprintf(first_node_str, sizeof(first_node_str), "%" PRId64, first_node);
    snprintf(count_str,      sizeof(count_str),      "%d", node_count);

    params[0] = level_str;        param_lens[0] = 0;
    params[1] = tile_idx_str;     param_lens[1] = 0;
    params[2] = height_str;       param_lens[2] = 0;
    params[3] = first_node_str;   param_lens[3] = 0;
    params[4] = count_str;        param_lens[4] = 0;
    params[5] = (const char *)in_hashes;
    param_lens[5] = node_count * MTC_TILE_HASH_SIZE;

    res = PQexecParams(conn,
        "INSERT INTO mtc_merkle_tiles "
        "  (level, tile_index, tile_height, first_node, node_count, hashes) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (level, tile_index) DO UPDATE SET "
        "  tile_height = EXCLUDED.tile_height,"
        "  first_node  = EXCLUDED.first_node,"
        "  node_count  = EXCLUDED.node_count,"
        "  hashes      = EXCLUDED.hashes,"
        "  updated_at  = now()",
        6, NULL, params, param_lens, param_fmts, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "[tile_store] put_tile (%d,%" PRId64 ") failed: %s",
                level, tile_index, PQerrorMessage(conn));
        goto out;
    }
    rc = 0;

out:
    PQclear(res);
    return rc;
}

int mtc_tile_store_load_top_nodes(PGconn *conn,
                                  mtc_tile_top_node_t *out_array,
                                  int max_count)
{
    PGresult *res;
    int rows, i, written = 0;

    if (!conn || !out_array || max_count <= 0) return -1;

    res = PQexec(conn,
        "SELECT level, node_index, hash FROM mtc_merkle_top_nodes "
        "ORDER BY level ASC, node_index ASC");

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[tile_store] load_top_nodes failed: %s",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    rows = PQntuples(res);
    if (rows > max_count) rows = max_count;

    for (i = 0; i < rows; i++) {
        const char *hash_bytes = PQgetvalue(res, i, 2);
        int hash_len = PQgetlength(res, i, 2);
        if (hash_len != MTC_TILE_HASH_SIZE) {
            fprintf(stderr,
                    "[tile_store] top_node row %d has hash length %d\n",
                    i, hash_len);
            continue;
        }
        out_array[written].level      = atoi(PQgetvalue(res, i, 0));
        out_array[written].node_index = (int64_t)strtoll(
                                            PQgetvalue(res, i, 1), NULL, 10);
        memcpy(out_array[written].hash, hash_bytes, MTC_TILE_HASH_SIZE);
        written++;
    }

    PQclear(res);
    return written;
}

int mtc_tile_store_put_top_node(PGconn *conn, int level, int64_t node_index,
                                const uint8_t hash[MTC_TILE_HASH_SIZE])
{
    PGresult *res;
    char level_str[16], idx_str[32];
    const char *params[3];
    int param_lens[3] = {0, 0, MTC_TILE_HASH_SIZE};
    int param_fmts[3] = {0, 0, 1};
    int rc = -1;

    if (!conn || level < 0 || node_index < 0 || !hash) return -1;

    snprintf(level_str, sizeof(level_str), "%d", level);
    snprintf(idx_str,   sizeof(idx_str),   "%" PRId64, node_index);
    params[0] = level_str;
    params[1] = idx_str;
    params[2] = (const char *)hash;

    res = PQexecParams(conn,
        "INSERT INTO mtc_merkle_top_nodes (level, node_index, hash) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (level, node_index) DO UPDATE SET "
        "  hash = EXCLUDED.hash",
        3, NULL, params, param_lens, param_fmts, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr,
                "[tile_store] put_top_node (%d,%" PRId64 ") failed: %s",
                level, node_index, PQerrorMessage(conn));
        goto out;
    }
    rc = 0;

out:
    PQclear(res);
    return rc;
}

int mtc_tile_store_lock_for_append(PGconn *conn, const char *log_id)
{
    PGresult *res;
    char key_str[32];
    const char *params[1];
    int rc = -1;
    int64_t key;

    if (!conn || !log_id) return -1;

    key = fnv1a_64(log_id);
    snprintf(key_str, sizeof(key_str), "%" PRId64, key);
    params[0] = key_str;

    res = PQexecParams(conn,
        "SELECT pg_advisory_xact_lock($1::bigint)",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[tile_store] advisory lock failed: %s",
                PQerrorMessage(conn));
        goto out;
    }
    rc = 0;

out:
    PQclear(res);
    return rc;
}

int mtc_tile_store_get_tree_size(PGconn *conn, int64_t *size_out)
{
    PGresult *res;
    int rc = -1;

    if (!conn || !size_out) return -1;

    res = PQexec(conn, "SELECT COALESCE(MAX(index), -1) + 1 FROM mtc_log_entries");

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        fprintf(stderr, "[tile_store] get_tree_size failed: %s",
                PQerrorMessage(conn));
        goto out;
    }

    *size_out = (int64_t)strtoll(PQgetvalue(res, 0, 0), NULL, 10);
    rc = 0;

out:
    PQclear(res);
    return rc;
}
