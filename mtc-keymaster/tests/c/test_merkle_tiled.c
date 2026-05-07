/**
 * @file test_merkle_tiled.c
 * @brief Equivalence tests: legacy mtc_merkle vs mtc_merkle_tiled.
 *
 * For a battery of tree sizes N, builds the same N synthetic leaves
 * in both implementations and asserts:
 *   - root_hash(N) matches.
 *   - inclusion_proof(i, 0, N) matches for every i.
 *   - consistency_proof(old, new) matches for representative pairs.
 *
 * The tiled tree runs against the in-process mock store
 * (mtc_tile_store_mock.c), so this test does not require a live
 * Postgres connection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "../../server2/c/mtc_merkle.h"
#include "../../server2/c/mtc_merkle_tiled.h"

void mtc_tile_store_mock_reset(void);
void mtc_tile_store_mock_set_leaf(int64_t idx, const uint8_t hash[32]);

static int g_pass = 0;
static int g_fail = 0;

static void synth_entry(int i, uint8_t *buf, int *sz)
{
    /* Deterministic synthetic entry for index i. */
    int n = snprintf((char *)buf, 64, "entry-%010d", i);
    *sz = n;
}

static int hashes_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, MTC_HASH_SIZE) == 0;
}

static void hex(const uint8_t *h, char out[65])
{
    int i;
    for (i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", h[i]);
}

static int run_size(int N)
{
    MtcMerkleTree legacy;
    MtcTiledTree  tiled;
    int i, fail_local = 0;

    /* Build legacy tree. */
    mtc_tree_init(&legacy);

    /* Build tiled tree on a fresh mock store. */
    mtc_tile_store_mock_reset();
    if (mtc_tiled_tree_open(&tiled, /*conn=*/NULL, "test-log") != 0) {
        fprintf(stderr, "[N=%d] tiled_tree_open failed\n", N);
        mtc_tree_free(&legacy);
        return -1;
    }

    /* Append N synthetic leaves to both. */
    for (i = 0; i < N; i++) {
        uint8_t buf[64];
        int sz;
        uint8_t leaf[MTC_HASH_SIZE];
        int legacy_idx, tiled_idx;

        synth_entry(i, buf, &sz);
        mtc_hash_leaf(buf, sz, leaf);

        legacy_idx = mtc_tree_append(&legacy, buf, sz);
        if (legacy_idx != i) {
            fprintf(stderr, "[N=%d] legacy idx mismatch at %d\n", N, i);
            fail_local++;
        }

        /* Tiled append: mock leaf store row first, then walk inner. */
        mtc_tile_store_mock_set_leaf(i, leaf);
        tiled_idx = mtc_tiled_tree_append_leaf(&tiled, leaf);
        if (tiled_idx != i) {
            fprintf(stderr, "[N=%d] tiled idx mismatch at %d\n", N, i);
            fail_local++;
        }
    }

    if (legacy.size != N || tiled.size != N) {
        fprintf(stderr, "[N=%d] size mismatch: legacy=%d tiled=%d\n",
                N, legacy.size, tiled.size);
        fail_local++;
    }

    /* Root hash. */
    {
        uint8_t lroot[MTC_HASH_SIZE], troot[MTC_HASH_SIZE];
        mtc_tree_root_hash(&legacy, N, lroot);
        if (mtc_tiled_tree_root_hash(&tiled, N, troot) != 0) {
            fprintf(stderr, "[N=%d] tiled root_hash failed\n", N);
            fail_local++;
        } else if (!hashes_eq(lroot, troot)) {
            char a[65], b[65];
            hex(lroot, a); hex(troot, b);
            fprintf(stderr, "[N=%d] root mismatch\n  legacy=%s\n  tiled =%s\n",
                    N, a, b);
            fail_local++;
        }
    }

    /* Subtree hash for representative ranges (only when N >= 2). */
    if (N >= 2) {
        int starts[3] = {0, 0,        N / 2};
        int ends[3]   = {N, N / 2,    N};
        int p;
        for (p = 0; p < 3; p++) {
            uint8_t lh[MTC_HASH_SIZE], th[MTC_HASH_SIZE];
            int s = starts[p], e = ends[p];
            if (s >= e) continue;
            if (mtc_tree_subtree_hash(&legacy, s, e, lh) != 0) continue;
            if (mtc_tiled_tree_subtree_hash(&tiled, s, e, th) != 0) {
                fprintf(stderr, "[N=%d] tiled subtree_hash(%d,%d) failed\n",
                        N, s, e);
                fail_local++;
                continue;
            }
            if (!hashes_eq(lh, th)) {
                fprintf(stderr,
                        "[N=%d] subtree(%d,%d) hash mismatch\n", N, s, e);
                fail_local++;
            }
        }
    }

    /* Inclusion proof for every leaf (full subtree [0, N)). */
    for (i = 0; i < N; i++) {
        uint8_t *lprf = NULL, *tprf = NULL;
        int lcnt = 0, tcnt = 0;

        if (mtc_tree_inclusion_proof(&legacy, i, 0, N, &lprf, &lcnt) != 0) {
            fprintf(stderr, "[N=%d] legacy incl_proof(%d) failed\n", N, i);
            fail_local++;
            continue;
        }
        if (mtc_tiled_tree_inclusion_proof(&tiled, i, 0, N, &tprf, &tcnt) != 0) {
            fprintf(stderr, "[N=%d] tiled incl_proof(%d) failed\n", N, i);
            free(lprf);
            fail_local++;
            continue;
        }
        if (lcnt != tcnt ||
            (lcnt > 0 && memcmp(lprf, tprf,
                                (size_t)lcnt * MTC_HASH_SIZE) != 0)) {
            fprintf(stderr,
                    "[N=%d] incl_proof(%d) mismatch (lcnt=%d tcnt=%d)\n",
                    N, i, lcnt, tcnt);
            fail_local++;
        }
        free(lprf);
        free(tprf);
    }

    /* Consistency proofs for representative (old, new) pairs. */
    if (N >= 2) {
        int pairs[][2] = {
            {1, N},
            {N / 2, N},
            {N - 1, N},
            {1, 1},        /* trivial: same size */
        };
        int npairs = sizeof(pairs) / sizeof(pairs[0]);
        int p;
        for (p = 0; p < npairs; p++) {
            int oldn = pairs[p][0], newn = pairs[p][1];
            uint8_t *lprf = NULL, *tprf = NULL;
            int lcnt = 0, tcnt = 0;

            if (oldn < 1 || newn > N || oldn > newn) continue;
            if (mtc_tree_consistency_proof(&legacy, oldn, newn,
                                           &lprf, &lcnt) != 0) {
                fprintf(stderr,
                        "[N=%d] legacy cons_proof(%d,%d) failed\n",
                        N, oldn, newn);
                fail_local++;
                continue;
            }
            if (mtc_tiled_tree_consistency_proof(&tiled, oldn, newn,
                                                  &tprf, &tcnt) != 0) {
                fprintf(stderr,
                        "[N=%d] tiled cons_proof(%d,%d) failed\n",
                        N, oldn, newn);
                free(lprf);
                fail_local++;
                continue;
            }
            if (lcnt != tcnt ||
                (lcnt > 0 && memcmp(lprf, tprf,
                                    (size_t)lcnt * MTC_HASH_SIZE) != 0)) {
                fprintf(stderr,
                        "[N=%d] cons_proof(%d,%d) mismatch (lcnt=%d tcnt=%d)\n",
                        N, oldn, newn, lcnt, tcnt);
                fail_local++;
            }
            free(lprf);
            free(tprf);
        }
    }

    mtc_tree_free(&legacy);
    mtc_tiled_tree_close(&tiled);

    if (fail_local == 0) {
        printf("[PASS] N=%d\n", N);
        g_pass++;
        return 0;
    } else {
        printf("[FAIL] N=%d (%d sub-failures)\n", N, fail_local);
        g_fail++;
        return -1;
    }
}

int main(void)
{
    int sizes[] = {0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33,
                   255, 256, 257, 1024, 10000};
    int n_sizes = sizeof(sizes) / sizeof(sizes[0]);
    int i;

    printf("=== test_merkle_tiled: equivalence vs legacy mtc_merkle ===\n");

    for (i = 0; i < n_sizes; i++) {
        run_size(sizes[i]);
    }

    printf("\n=== summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
