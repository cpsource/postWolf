/* mtc_merkle.c — Merkle tree implementation for MTC CA server.
 *
 * RFC 9162 Section 2.1 hashing + inclusion/consistency proofs.
 * Uses wolfcrypt SHA-256. */

#include "mtc_merkle.h"
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

void mtc_hash_leaf(const uint8_t *data, int dataSz, uint8_t *out)
{
    wc_Sha256 sha;
    uint8_t prefix = 0x00;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, data, (word32)dataSz);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

void mtc_hash_node(const uint8_t *left, const uint8_t *right, uint8_t *out)
{
    wc_Sha256 sha;
    uint8_t prefix = 0x01;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, left, MTC_HASH_SIZE);
    wc_Sha256Update(&sha, right, MTC_HASH_SIZE);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

void mtc_tree_init(MtcMerkleTree *tree)
{
    memset(tree, 0, sizeof(*tree));
    tree->capacity = 64;
    tree->leaf_hashes = (uint8_t**)calloc((size_t)tree->capacity, sizeof(uint8_t*));
    tree->entries = (uint8_t**)calloc((size_t)tree->capacity, sizeof(uint8_t*));
    tree->entry_sizes = (int*)calloc((size_t)tree->capacity, sizeof(int));
}

void mtc_tree_free(MtcMerkleTree *tree)
{
    int i;
    for (i = 0; i < tree->size; i++) {
        free(tree->leaf_hashes[i]);
        free(tree->entries[i]);
    }
    free(tree->leaf_hashes);
    free(tree->entries);
    free(tree->entry_sizes);
    memset(tree, 0, sizeof(*tree));
}

static void mtc_tree_grow(MtcMerkleTree *tree)
{
    if (tree->size >= tree->capacity) {
        int newcap = tree->capacity * 2;
        tree->leaf_hashes = (uint8_t**)realloc(tree->leaf_hashes,
            (size_t)newcap * sizeof(uint8_t*));
        tree->entries = (uint8_t**)realloc(tree->entries,
            (size_t)newcap * sizeof(uint8_t*));
        tree->entry_sizes = (int*)realloc(tree->entry_sizes,
            (size_t)newcap * sizeof(int));
        tree->capacity = newcap;
    }
}

int mtc_tree_append(MtcMerkleTree *tree, const uint8_t *entry, int entrySz)
{
    int idx = tree->size;
    uint8_t *lh, *ent;

    mtc_tree_grow(tree);

    lh = (uint8_t*)malloc(MTC_HASH_SIZE);
    mtc_hash_leaf(entry, entrySz, lh);

    ent = (uint8_t*)malloc((size_t)entrySz);
    memcpy(ent, entry, (size_t)entrySz);

    tree->leaf_hashes[idx] = lh;
    tree->entries[idx] = ent;
    tree->entry_sizes[idx] = entrySz;
    tree->size++;

    return idx;
}

/* Compute MTH(D[start:end]) recursively */
static void mth(MtcMerkleTree *tree, int start, int end, uint8_t *out)
{
    int n = end - start;
    int k;
    uint8_t left[MTC_HASH_SIZE], right[MTC_HASH_SIZE];

    if (n == 1) {
        memcpy(out, tree->leaf_hashes[start], MTC_HASH_SIZE);
        return;
    }

    /* k = largest power of 2 less than n */
    k = 1;
    while (k * 2 < n) k *= 2;

    mth(tree, start, start + k, left);
    mth(tree, start + k, end, right);
    mtc_hash_node(left, right, out);
}

int mtc_tree_root_hash(MtcMerkleTree *tree, int tree_size, uint8_t *out)
{
    if (tree_size <= 0 || tree_size > tree->size) {
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        wc_Sha256Final(&sha, out); /* SHA-256("") */
        wc_Sha256Free(&sha);
        return 0;
    }
    mth(tree, 0, tree_size, out);
    return 0;
}

int mtc_tree_subtree_hash(MtcMerkleTree *tree, int start, int end, uint8_t *out)
{
    if (start < 0 || end > tree->size || start >= end)
        return -1;
    mth(tree, start, end, out);
    return 0;
}

/* PATH(m, D_n) per RFC 9162 Section 2.1.3 */
static void inclusion_path(MtcMerkleTree *tree, int m, int n, int offset,
                           uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (n == 1)
        return;

    k = 1;
    while (k * 2 < n) k *= 2;

    if (m < k) {
        inclusion_path(tree, m, k, offset, proof, count);
        mth(tree, offset + k, offset + n, h);
    }
    else {
        inclusion_path(tree, m - k, n - k, offset + k, proof, count);
        mth(tree, offset, offset + k, h);
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
}

int mtc_tree_inclusion_proof(MtcMerkleTree *tree, int index, int start, int end,
                             uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (index < start || index >= end || end > tree->size)
        return -1;

    /* Max proof depth is log2(end-start) + 1 */
    max_depth = 0;
    { int tmp = end - start; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t*)malloc((size_t)max_depth * MTC_HASH_SIZE);

    inclusion_path(tree, index - start, end - start, start, proof, &count);

    *proof_out = proof;
    *proof_count = count;
    return 0;
}

/* Consistency subproof per RFC 9162 Section 2.1.4 */
static void consistency_subproof(MtcMerkleTree *tree, int m, int n, int offset,
                                 int start_from_old, uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (m == n) {
        if (!start_from_old) {
            mth(tree, offset, offset + n, h);
            memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
            (*count)++;
        }
        return;
    }

    k = 1;
    while (k * 2 < n) k *= 2;

    if (m <= k) {
        consistency_subproof(tree, m, k, offset, start_from_old, proof, count);
        mth(tree, offset + k, offset + n, h);
    }
    else {
        consistency_subproof(tree, m - k, n - k, offset + k, 0, proof, count);
        mth(tree, offset, offset + k, h);
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
}

int mtc_tree_consistency_proof(MtcMerkleTree *tree, int old_size, int new_size,
                               uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (old_size < 1 || new_size > tree->size || old_size > new_size)
        return -1;

    max_depth = 0;
    { int tmp = new_size; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t*)malloc((size_t)max_depth * MTC_HASH_SIZE);
    consistency_subproof(tree, old_size, new_size, 0, 1, proof, &count);

    *proof_out = proof;
    *proof_count = count;
    return 0;
}
