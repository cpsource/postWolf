/******************************************************************************
 * File:        mtc_rebuild_tiles.c
 * Purpose:     One-shot migration tool — rebuild mtc_merkle_tiles +
 *              mtc_merkle_top_nodes from mtc_log_entries (TODO #74 phase 3).
 *
 * Description:
 *   Approach: load every leaf hash from mtc_log_entries (ORDER BY index)
 *   into a legacy in-memory MtcMerkleTree using mtc_tree_append, which
 *   silently compacts gaps the same way the running mtc-ca.service does
 *   on startup.  Then walk levels bottom-up, computing each complete-
 *   subtree inner-node hash via mtc_tree_subtree_hash and writing it to
 *   either mtc_merkle_tiles (level < MTC_TOP_K_LEVEL_THRESHOLD) or
 *   mtc_merkle_top_nodes (level >= threshold).
 *
 *   The whole rebuild happens inside one Postgres transaction guarded
 *   by mtc_tile_store_lock_for_append.  At the end the rebuilt root is
 *   compared to the latest cosigned checkpoint's root_hash.  Mismatch →
 *   ROLLBACK; tile tables remain at their pre-rebuild state.
 *
 * Build:  make mtc_rebuild_tiles
 *
 * Usage:
 *   mtc_rebuild_tiles [options]
 *
 *   --tokenpath FILE     .env with MERKLE_NEON (default: $HOME/.env)
 *   --log-id ID          Log identifier (default: 32473.2)
 *   --dry-run            Walk + verify; don't TRUNCATE or write tiles
 *   --yes                Skip the interactive confirmation
 *   -h, --help           Show this help
 *
 * Exit codes:
 *   0 — success (tile tables rebuilt; root matches checkpoint)
 *   1 — DB error or root mismatch
 *   2 — invocation / argument error
 *
 * Created: 2026-05-07
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <json-c/json.h>
#include <libpq-fe.h>

#include "mtc_db.h"
#include "mtc_merkle.h"
#include "mtc_merkle_tiled.h"   /* MTC_TOP_K_LEVEL_THRESHOLD */
#include "mtc_tile.h"
#include "mtc_tile_store.h"

static int g_dry_run = 0;
static int g_yes     = 0;
static int g_skip_cp = 0;

static void usage(const char *prog)
{
    printf("Rebuild mtc_merkle_tiles + mtc_merkle_top_nodes from mtc_log_entries.\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --tokenpath FILE     .env with MERKLE_NEON (default: $HOME/.env)\n");
    printf("  --log-id ID          Log identifier (default: 32473.2)\n");
    printf("  --dry-run            Walk + verify; mutate nothing\n");
    printf("  --yes                Skip the interactive confirmation\n");
    printf("  --skip-checkpoint-compare\n");
    printf("                       Skip the rebuilt-vs-latest-checkpoint\n");
    printf("                       sanity check.  Use only when the log is\n");
    printf("                       known to be inconsistent with the latest\n");
    printf("                       checkpoint (e.g. after cleanup-tpm runs).\n");
    printf("  -h, --help           Show this help\n");
}

static int load_checkpoint_root(PGconn *conn, const char *log_id,
                                uint8_t out[MTC_HASH_SIZE])
{
    struct json_object *cp = mtc_db_load_latest_checkpoint(conn, log_id);
    struct json_object *rh_v;
    const char *rh;
    int rc = -1;

    if (!cp) {
        fprintf(stderr,
            "rebuild: no checkpoint found for log_id='%s'\n", log_id);
        return -1;
    }
    if (!json_object_object_get_ex(cp, "root_hash", &rh_v) ||
        !(rh = json_object_get_string(rh_v))) {
        fprintf(stderr, "rebuild: checkpoint missing root_hash field\n");
        goto out;
    }
    if (strlen(rh) != MTC_HASH_SIZE * 2) {
        fprintf(stderr,
            "rebuild: checkpoint root_hash length %zu != %d\n",
            strlen(rh), MTC_HASH_SIZE * 2);
        goto out;
    }
    {
        int i;
        for (i = 0; i < MTC_HASH_SIZE; i++) {
            unsigned int b;
            if (sscanf(rh + i * 2, "%02x", &b) != 1) {
                fprintf(stderr, "rebuild: invalid hex in root_hash\n");
                goto out;
            }
            out[i] = (uint8_t)b;
        }
    }
    rc = 0;

out:
    json_object_put(cp);
    return rc;
}

/* Walk mtc_log_entries ORDER BY index, append each row's leaf into the
 * legacy in-memory tree.  Gaps are compacted to sequential tree
 * positions to match how mtc_store_load currently runs in production.
 *
 * Returns the number of leaves loaded, or -1 on error.
 *
 * Each leaf is a 1-byte synthetic placeholder; mtc_tree_append computes
 * a leaf hash from it, but we OVERWRITE that hash with the real
 * leaf_hash from mtc_log_entries afterwards.  This keeps the tree's
 * leaf_hashes array authoritative without requiring us to re-hash
 * the original entry bytes (we don't have them in this query). */
static int load_leaves_into_legacy(PGconn *conn, MtcMerkleTree *tree,
                                   int *gap_count_out)
{
    PGresult *res;
    int j, n, gap_count = 0;

    res = PQexec(conn,
        "SELECT index, leaf_hash FROM mtc_log_entries ORDER BY index");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "rebuild: SELECT failed: %s",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    n = PQntuples(res);

    for (j = 0; j < n; j++) {
        int idx = atoi(PQgetvalue(res, j, 0));
        const char *lh_bytes = PQgetvalue(res, j, 1);
        int lh_len = PQgetlength(res, j, 1);
        uint8_t leaf[MTC_HASH_SIZE];
        uint8_t placeholder = 0x00;

        if (idx != j) {
            if (gap_count == 0)
                fprintf(stderr,
                    "rebuild: WARNING — index discontinuity at row %d "
                    "(DB index=%d); compacting to tree position %d "
                    "(matches legacy server load order)\n",
                    j, idx, j);
            gap_count++;
        }

        if (PQfformat(res, 1) == 0) {
            size_t out_len = 0;
            unsigned char *decoded = PQunescapeBytea(
                (const unsigned char *)lh_bytes, &out_len);
            if (!decoded || out_len != MTC_HASH_SIZE) {
                fprintf(stderr,
                    "rebuild: leaf_hash decode failed at idx=%d\n", idx);
                if (decoded) PQfreemem(decoded);
                PQclear(res);
                return -1;
            }
            memcpy(leaf, decoded, MTC_HASH_SIZE);
            PQfreemem(decoded);
        } else {
            if (lh_len != MTC_HASH_SIZE) {
                fprintf(stderr,
                    "rebuild: leaf_hash binary len %d != %d\n",
                    lh_len, MTC_HASH_SIZE);
                PQclear(res);
                return -1;
            }
            memcpy(leaf, lh_bytes, MTC_HASH_SIZE);
        }

        /* mtc_tree_append computes a leaf hash from the placeholder
         * and stores it.  Overwrite with the real leaf_hash from DB
         * so subsequent mth() calls produce the right inner-node
         * hashes.  Tree's `entries` array gets a 1-byte placeholder,
         * which is fine — the rebuild tool doesn't read entry bytes. */
        mtc_tree_append(tree, &placeholder, 1);
        memcpy(tree->leaf_hashes[tree->size - 1], leaf, MTC_HASH_SIZE);
    }

    PQclear(res);
    *gap_count_out = gap_count;
    return n;
}

/* Walk every complete subtree at every level and persist its hash to
 * the appropriate store (tile vs top_node).
 *
 * "Complete subtree at (level, node_index)" covers leaf range
 * [node_index * 2^level, (node_index+1) * 2^level), and is complete
 * when (node_index+1) * 2^level <= tree.size. */
static int write_inner_nodes(PGconn *conn, MtcMerkleTree *tree,
                             int *tile_writes_out, int *top_writes_out)
{
    int N = tree->size;
    int level;
    int tile_writes = 0;
    int top_writes = 0;

    for (level = 1; ; level++) {
        int64_t span = (int64_t)1 << level;
        if (span > N) break;
        int64_t max_node = N / span;          /* number of complete nodes */
        if (max_node == 0) break;

        if (level < MTC_TOP_K_LEVEL_THRESHOLD) {
            int64_t n_tiles = (max_node + MTC_TILE_LEAF_COUNT - 1) /
                              MTC_TILE_LEAF_COUNT;
            int64_t t;
            for (t = 0; t < n_tiles; t++) {
                uint8_t buf[MTC_TILE_BYTES];
                int count = 0;
                int slot;
                int64_t base = t * MTC_TILE_LEAF_COUNT;
                for (slot = 0;
                     slot < MTC_TILE_LEAF_COUNT && base + slot < max_node;
                     slot++) {
                    int64_t node_idx = base + slot;
                    int leaf_start = (int)(node_idx * span);
                    int leaf_end   = leaf_start + (int)span;
                    if (mtc_tree_subtree_hash(tree, leaf_start, leaf_end,
                            buf + (size_t)slot * MTC_TILE_HASH_SIZE) != 0) {
                        fprintf(stderr,
                            "rebuild: subtree_hash(%d,%d) failed\n",
                            leaf_start, leaf_end);
                        return -1;
                    }
                    count++;
                }
                if (count == 0) continue;
                if (mtc_tile_store_put_tile(conn, level, t, buf, count) != 0)
                    return -1;
                tile_writes++;
            }
        } else {
            int64_t node_idx;
            for (node_idx = 0; node_idx < max_node; node_idx++) {
                uint8_t hash[MTC_TILE_HASH_SIZE];
                int leaf_start = (int)(node_idx * span);
                int leaf_end   = leaf_start + (int)span;
                if (mtc_tree_subtree_hash(tree, leaf_start, leaf_end,
                                          hash) != 0) {
                    fprintf(stderr,
                        "rebuild: subtree_hash(%d,%d) failed\n",
                        leaf_start, leaf_end);
                    return -1;
                }
                if (mtc_tile_store_put_top_node(conn, level, node_idx,
                                                hash) != 0)
                    return -1;
                top_writes++;
            }
        }
    }

    *tile_writes_out = tile_writes;
    *top_writes_out = top_writes;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *tokenpath = NULL;
    const char *log_id    = "32473.2";
    char default_tokenpath[512];
    int i, rc_main = 1;
    PGconn *conn = NULL;
    PGresult *res = NULL;
    MtcMerkleTree legacy;
    int legacy_inited = 0;
    int in_txn = 0;
    int leaf_count, gap_count = 0;
    int tile_writes = 0, top_writes = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tokenpath") == 0 && i + 1 < argc) {
            tokenpath = argv[++i];
        } else if (strcmp(argv[i], "--log-id") == 0 && i + 1 < argc) {
            log_id = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            g_dry_run = 1;
        } else if (strcmp(argv[i], "--yes") == 0) {
            g_yes = 1;
        } else if (strcmp(argv[i], "--skip-checkpoint-compare") == 0) {
            g_skip_cp = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr,
                "mtc_rebuild_tiles: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!tokenpath) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(default_tokenpath, sizeof(default_tokenpath),
                     "%s/.env", home);
            tokenpath = default_tokenpath;
        }
    }
    if (tokenpath) mtc_db_set_tokenpath(tokenpath);

    conn = mtc_db_connect();
    if (!conn) {
        fprintf(stderr,
            "mtc_rebuild_tiles: cannot connect to Neon DB.\n");
        return 1;
    }

    if (!g_dry_run && !g_yes) {
        char buf[16];
        printf("This will TRUNCATE mtc_merkle_tiles + mtc_merkle_top_nodes\n");
        printf("and rebuild from mtc_log_entries for log_id='%s'.\n", log_id);
        printf("Type 'yes' to proceed: ");
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin) ||
            strncmp(buf, "yes", 3) != 0 ||
            (buf[3] != '\n' && buf[3] != '\0')) {
            printf("aborted\n");
            PQfinish(conn);
            return 1;
        }
    }

    res = PQexec(conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "rebuild: BEGIN failed: %s",
                PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    PQclear(res);
    res = NULL;
    in_txn = 1;

    if (mtc_tile_store_lock_for_append(conn, log_id) != 0) {
        fprintf(stderr, "rebuild: advisory lock failed\n");
        goto cleanup;
    }

    if (!g_dry_run) {
        printf("rebuild: TRUNCATE mtc_merkle_tiles, mtc_merkle_top_nodes\n");
        res = PQexec(conn,
            "TRUNCATE mtc_merkle_tiles, mtc_merkle_top_nodes");
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "rebuild: TRUNCATE failed: %s",
                    PQerrorMessage(conn));
            PQclear(res);
            res = NULL;
            goto cleanup;
        }
        PQclear(res);
        res = NULL;
    } else {
        printf("rebuild: [dry-run] would TRUNCATE both tile tables\n");
    }

    /* Load leaves into a legacy in-memory tree (it does the
     * compacting walk for us automatically). */
    mtc_tree_init(&legacy);
    legacy_inited = 1;

    leaf_count = load_leaves_into_legacy(conn, &legacy, &gap_count);
    if (leaf_count < 0) goto cleanup;
    printf("rebuild: loaded %d leaves into legacy tree (%d gap%s)\n",
           leaf_count, gap_count, gap_count == 1 ? "" : "s");

    /* Walk every complete subtree at every level, write to tiles /
     * top_nodes. */
    if (!g_dry_run) {
        if (write_inner_nodes(conn, &legacy, &tile_writes, &top_writes) != 0)
            goto cleanup;
        printf("rebuild: wrote %d tile rows + %d top-node rows\n",
               tile_writes, top_writes);
    } else {
        printf("rebuild: [dry-run] would walk inner nodes\n");
    }

    /* Compare rebuilt root against the latest checkpoint. */
    {
        uint8_t rebuilt_root[MTC_HASH_SIZE];
        uint8_t cp_root[MTC_HASH_SIZE];
        char rebuilt_hex[MTC_HASH_SIZE * 2 + 1];
        char cp_hex[MTC_HASH_SIZE * 2 + 1];
        int k;

        mtc_tree_root_hash(&legacy, legacy.size, rebuilt_root);
        for (k = 0; k < MTC_HASH_SIZE; k++)
            snprintf(rebuilt_hex + k * 2, 3, "%02x", rebuilt_root[k]);

        if (g_skip_cp) {
            printf("rebuild: skipping checkpoint compare (--skip-checkpoint-compare)\n");
            printf("rebuild: rebuilt root = %s\n", rebuilt_hex);
        } else {
            if (load_checkpoint_root(conn, log_id, cp_root) != 0)
                goto cleanup;
            for (k = 0; k < MTC_HASH_SIZE; k++)
                snprintf(cp_hex + k * 2, 3, "%02x", cp_root[k]);
            if (memcmp(rebuilt_root, cp_root, MTC_HASH_SIZE) != 0) {
                fprintf(stderr,
                    "rebuild: ROOT MISMATCH — refusing to commit.\n"
                    "  rebuilt   = %s\n"
                    "  checkpoint= %s\n"
                    "  (if the dataset is known-inconsistent, e.g. after\n"
                    "   cleanup-tpm runs, re-run with --skip-checkpoint-compare)\n",
                    rebuilt_hex, cp_hex);
                goto cleanup;
            }
            printf("rebuild: root matches checkpoint (%s)\n", rebuilt_hex);
        }
    }

    if (g_dry_run) {
        rc_main = 0;
        goto cleanup;
    }

    res = PQexec(conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "rebuild: COMMIT failed: %s",
                PQerrorMessage(conn));
        PQclear(res);
        res = NULL;
        goto cleanup;
    }
    PQclear(res);
    res = NULL;
    in_txn = 0;

    printf("rebuild: %d leaves processed; tile tables live for log_id='%s'\n",
           leaf_count, log_id);
    rc_main = 0;

cleanup:
    if (res) PQclear(res);
    if (in_txn) {
        PGresult *r = PQexec(conn, "ROLLBACK");
        PQclear(r);
    }
    if (legacy_inited) mtc_tree_free(&legacy);
    if (conn) PQfinish(conn);
    return rc_main;
}
