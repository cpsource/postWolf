/******************************************************************************
 * File:        mtc_merkle.c
 * Purpose:     Merkle tree implementation for the MTC CA server.
 *
 * Description:
 *   Implements an append-only Merkle hash tree following RFC 9162
 *   Section 2.1 (Certificate Transparency v2) conventions:
 *
 *     Leaf hash:  SHA-256(0x00 || data)
 *     Node hash:  SHA-256(0x01 || left || right)
 *
 *   Tree hashes are computed on demand (no internal cache).  Inclusion
 *   proofs follow RFC 9162 Section 2.1.3 (PATH) and consistency proofs
 *   follow Section 2.1.4 (SUBPROOF).
 *
 * Dependencies:
 *   mtc_merkle.h
 *   stdlib.h, string.h
 *   wolfssl/options.h
 *   wolfssl/wolfcrypt/sha256.h
 *
 * Notes:
 *   - NOT thread-safe.  All tree operations must be serialised.
 *   - The tree owns all memory in its arrays.  mtc_tree_free() releases
 *     everything.
 *   - Proof buffers returned by inclusion/consistency functions are
 *     malloc'd; the caller must free().
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_merkle.h"
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

/******************************************************************************
 * Function:    mtc_hash_leaf
 *
 * Description:
 *   Computes the leaf hash per RFC 9162 Section 2.1:
 *   SHA-256(0x00 || data).  The 0x00 prefix distinguishes leaf hashes
 *   from interior node hashes, preventing second-preimage attacks.
 *
 * Input Arguments:
 *   data    - Leaf data bytes.
 *   dataSz  - Size of data in bytes.
 *   out     - Caller-owned buffer for the 32-byte hash.
 ******************************************************************************/
void mtc_hash_leaf(const uint8_t *data, int dataSz, uint8_t *out)
{
    wc_Sha256 sha;
    uint8_t prefix = 0x00;  /* RFC 9162 leaf domain separator */
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, data, (word32)dataSz);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

/******************************************************************************
 * Function:    mtc_hash_node
 *
 * Description:
 *   Computes an interior node hash per RFC 9162 Section 2.1:
 *   SHA-256(0x01 || left || right).  The 0x01 prefix distinguishes node
 *   hashes from leaf hashes.
 *
 * Input Arguments:
 *   left   - Left child hash (MTC_HASH_SIZE bytes).
 *   right  - Right child hash (MTC_HASH_SIZE bytes).
 *   out    - Caller-owned buffer for the 32-byte hash.
 ******************************************************************************/
void mtc_hash_node(const uint8_t *left, const uint8_t *right, uint8_t *out)
{
    wc_Sha256 sha;
    uint8_t prefix = 0x01;  /* RFC 9162 node domain separator */
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, left, MTC_HASH_SIZE);
    wc_Sha256Update(&sha, right, MTC_HASH_SIZE);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

/******************************************************************************
 * Function:    mtc_tree_init
 *
 * Description:
 *   Initialises an empty Merkle tree with an initial capacity of 64 slots.
 *
 * Input Arguments:
 *   tree  - Tree struct to initialise.  Zeroed and allocated on return.
 *
 * Side Effects:
 *   Allocates three arrays (leaf_hashes, entries, entry_sizes).
 ******************************************************************************/
void mtc_tree_init(MtcMerkleTree *tree)
{
    memset(tree, 0, sizeof(*tree));
    tree->capacity = 64;
    tree->leaf_hashes = (uint8_t**)calloc((size_t)tree->capacity, sizeof(uint8_t*));
    tree->entries = (uint8_t**)calloc((size_t)tree->capacity, sizeof(uint8_t*));
    tree->entry_sizes = (int*)calloc((size_t)tree->capacity, sizeof(int));
}

/******************************************************************************
 * Function:    mtc_tree_free
 *
 * Description:
 *   Frees all memory owned by the tree: each leaf hash, each entry buffer,
 *   the three top-level arrays, and zeros the struct.  Safe to re-init
 *   after this call.
 *
 * Input Arguments:
 *   tree  - Tree to free.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_tree_grow
 *
 * Description:
 *   Doubles the capacity of the tree's internal arrays when full.
 *
 * Input Arguments:
 *   tree  - Tree to grow (only reallocates if size >= capacity).
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mtc_tree_append
 *
 * Description:
 *   Appends an entry to the tree.  Copies the entry data, computes the
 *   leaf hash, and stores both.  Grows arrays if at capacity.
 *
 * Input Arguments:
 *   tree     - Target tree.
 *   entry    - Serialised entry bytes (copied; caller retains ownership).
 *   entrySz  - Size of entry in bytes.
 *
 * Returns:
 *   0-based index of the newly appended entry.
 *
 * Side Effects:
 *   Allocates MTC_HASH_SIZE bytes for the leaf hash and entrySz bytes
 *   for the entry copy.  Both are owned by the tree.
 ******************************************************************************/
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

/******************************************************************************
 * Function:    mth
 *
 * Description:
 *   Computes MTH(D[start:end]) — the Merkle Tree Hash over a contiguous
 *   range of leaves, per RFC 9162 Section 2.1.  Recurses by splitting
 *   at the largest power of 2 less than (end - start).
 *
 * Input Arguments:
 *   tree   - Merkle tree.
 *   start  - First leaf index (inclusive).
 *   end    - One past the last leaf (exclusive).  Must satisfy end > start.
 *   out    - Caller-owned buffer for the MTC_HASH_SIZE-byte result.
 *
 * Notes:
 *   For a single leaf (n == 1), returns the precomputed leaf hash directly.
 ******************************************************************************/
static void mth(MtcMerkleTree *tree, int start, int end, uint8_t *out)
{
    int n = end - start;
    int k;
    uint8_t left[MTC_HASH_SIZE], right[MTC_HASH_SIZE];

    if (n == 1) {
        memcpy(out, tree->leaf_hashes[start], MTC_HASH_SIZE);
        return;
    }

    /* k = largest power of 2 less than n (RFC 9162 split point) */
    k = 1;
    while (k * 2 < n) k *= 2;

    mth(tree, start, start + k, left);
    mth(tree, start + k, end, right);
    mtc_hash_node(left, right, out);
}

/******************************************************************************
 * Function:    mtc_tree_root_hash
 *
 * Description:
 *   Computes the root hash of the first tree_size leaves.  If tree_size
 *   is invalid (<= 0 or > tree->size), returns SHA-256("") — the
 *   conventional empty-tree hash.
 *
 * Input Arguments:
 *   tree       - Merkle tree.
 *   tree_size  - Number of leaves to include.
 *   out        - Caller-owned buffer for the MTC_HASH_SIZE-byte hash.
 *
 * Returns:
 *   0 always.
 ******************************************************************************/
int mtc_tree_root_hash(MtcMerkleTree *tree, int tree_size, uint8_t *out)
{
    if (tree_size <= 0 || tree_size > tree->size) {
        /* Empty tree: SHA-256 of the empty string */
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        wc_Sha256Final(&sha, out);
        wc_Sha256Free(&sha);
        return 0;
    }
    mth(tree, 0, tree_size, out);
    return 0;
}

/******************************************************************************
 * Function:    mtc_tree_subtree_hash
 *
 * Description:
 *   Computes the hash of the contiguous subtree [start, end).
 *
 * Input Arguments:
 *   tree   - Merkle tree.
 *   start  - First leaf index (inclusive).
 *   end    - One past the last leaf (exclusive).
 *   out    - Caller-owned buffer for the MTC_HASH_SIZE-byte hash.
 *
 * Returns:
 *    0  on success.
 *   -1  if start/end are out of range or start >= end.
 ******************************************************************************/
int mtc_tree_subtree_hash(MtcMerkleTree *tree, int start, int end, uint8_t *out)
{
    if (start < 0 || end > tree->size || start >= end)
        return -1;
    mth(tree, start, end, out);
    return 0;
}

/******************************************************************************
 * Function:    inclusion_path
 *
 * Description:
 *   Recursive helper implementing PATH(m, D_n) per RFC 9162 Section 2.1.3.
 *   Builds the inclusion proof by appending sibling hashes to the proof
 *   buffer as it recurses.
 *
 * Input Arguments:
 *   tree    - Merkle tree.
 *   m       - Leaf index relative to the current subtree (0-based).
 *   n       - Size of the current subtree.
 *   offset  - Absolute offset of the current subtree within the tree.
 *   proof   - Pre-allocated output buffer for sibling hashes.
 *   count   - Pointer to the current proof element count (updated in place).
 *
 * Notes:
 *   Base case: n == 1 (single leaf) — no siblings to add.
 *   Split point k is the largest power of 2 less than n.
 ******************************************************************************/
static void inclusion_path(MtcMerkleTree *tree, int m, int n, int offset,
                           uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (n == 1)
        return;

    /* RFC 9162 split point: largest power of 2 less than n */
    k = 1;
    while (k * 2 < n) k *= 2;

    if (m < k) {
        /* Target is in the left subtree — recurse left, hash right sibling */
        inclusion_path(tree, m, k, offset, proof, count);
        mth(tree, offset + k, offset + n, h);
    }
    else {
        /* Target is in the right subtree — recurse right, hash left sibling */
        inclusion_path(tree, m - k, n - k, offset + k, proof, count);
        mth(tree, offset, offset + k, h);
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
}

/******************************************************************************
 * Function:    mtc_tree_inclusion_proof
 *
 * Description:
 *   Generates a Merkle inclusion proof for leaf 'index' within the
 *   subtree [start, end).  Allocates a proof buffer and returns it.
 *
 * Input Arguments:
 *   tree         - Merkle tree.
 *   index        - Leaf index to prove (absolute, within [start, end)).
 *   start        - Subtree start (inclusive).
 *   end          - Subtree end (exclusive).
 *   proof_out    - Receives a malloc'd array of sibling hashes.
 *   proof_count  - Receives the number of hashes in the proof.
 *
 * Returns:
 *    0  on success.
 *   -1  if index is out of [start, end) or end > tree->size.
 *
 * Notes:
 *   Caller must free(*proof_out).
 ******************************************************************************/
int mtc_tree_inclusion_proof(MtcMerkleTree *tree, int index, int start, int end,
                             uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (index < start || index >= end || end > tree->size)
        return -1;

    /* Conservative upper bound on proof depth: ceil(log2(n)) + 2 */
    max_depth = 0;
    { int tmp = end - start; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t*)malloc((size_t)max_depth * MTC_HASH_SIZE);

    inclusion_path(tree, index - start, end - start, start, proof, &count);

    *proof_out = proof;
    *proof_count = count;
    return 0;
}

/******************************************************************************
 * Function:    consistency_subproof
 *
 * Description:
 *   Recursive helper implementing SUBPROOF(m, D_n) per RFC 9162
 *   Section 2.1.4.  Builds the consistency proof by appending hashes
 *   to the proof buffer.
 *
 * Input Arguments:
 *   tree            - Merkle tree.
 *   m               - Old tree size relative to the current subtree.
 *   n               - Current subtree size.
 *   offset          - Absolute offset of the current subtree.
 *   start_from_old  - 1 if this is the initial call (m == old_size),
 *                     0 for recursive calls.  When 1 and m == n, the
 *                     subtree hash is omitted (RFC 9162 optimisation).
 *   proof           - Pre-allocated output buffer for hashes.
 *   count           - Pointer to the current proof element count.
 *
 * Notes:
 *   Base case: m == n.  If start_from_old is true, no hash is emitted
 *   (the verifier already knows the old root).
 ******************************************************************************/
static void consistency_subproof(MtcMerkleTree *tree, int m, int n, int offset,
                                 int start_from_old, uint8_t *proof, int *count)
{
    int k;
    uint8_t h[MTC_HASH_SIZE];

    if (m == n) {
        if (!start_from_old) {
            /* Emit the subtree hash for the verifier */
            mth(tree, offset, offset + n, h);
            memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
            (*count)++;
        }
        return;
    }

    /* RFC 9162 split point: largest power of 2 less than n */
    k = 1;
    while (k * 2 < n) k *= 2;

    if (m <= k) {
        /* Old tree fits entirely in the left subtree */
        consistency_subproof(tree, m, k, offset, start_from_old, proof, count);
        mth(tree, offset + k, offset + n, h);
    }
    else {
        /* Old tree straddles the split — recurse into the right half */
        consistency_subproof(tree, m - k, n - k, offset + k, 0, proof, count);
        mth(tree, offset, offset + k, h);
    }
    memcpy(proof + (*count) * MTC_HASH_SIZE, h, MTC_HASH_SIZE);
    (*count)++;
}

/******************************************************************************
 * Function:    mtc_tree_consistency_proof
 *
 * Description:
 *   Generates a Merkle consistency proof from old_size to new_size,
 *   per RFC 9162 Section 2.1.4.  Allocates a proof buffer and returns it.
 *
 * Input Arguments:
 *   tree         - Merkle tree.
 *   old_size     - Smaller tree size (>= 1).
 *   new_size     - Larger tree size (<= tree->size).
 *   proof_out    - Receives a malloc'd array of hashes.
 *   proof_count  - Receives the number of hashes in the proof.
 *
 * Returns:
 *    0  on success.
 *   -1  if old_size < 1, new_size > tree->size, or old_size > new_size.
 *
 * Notes:
 *   Caller must free(*proof_out).
 ******************************************************************************/
int mtc_tree_consistency_proof(MtcMerkleTree *tree, int old_size, int new_size,
                               uint8_t **proof_out, int *proof_count)
{
    int max_depth, count = 0;
    uint8_t *proof;

    if (old_size < 1 || new_size > tree->size || old_size > new_size)
        return -1;

    /* Conservative upper bound on proof depth: ceil(log2(n)) + 2 */
    max_depth = 0;
    { int tmp = new_size; while (tmp > 1) { max_depth++; tmp /= 2; } max_depth += 2; }

    proof = (uint8_t*)malloc((size_t)max_depth * MTC_HASH_SIZE);
    consistency_subproof(tree, old_size, new_size, 0, 1, proof, &count);

    *proof_out = proof;
    *proof_count = count;
    return 0;
}
