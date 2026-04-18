/**
 * @file mtc_merkle.h
 * @brief Merkle tree for the MTC CA server (RFC 9162).
 *
 * @details
 * Implements an append-only Merkle hash tree with SHA-256, following
 * RFC 9162 Section 2.1 (Certificate Transparency v2) hashing conventions:
 *   - Leaf hash:  SHA-256(0x00 || data)
 *   - Node hash:  SHA-256(0x01 || left || right)
 *
 * Provides root hash computation, subtree hashing, inclusion proofs, and
 * consistency proofs.
 *
 * Thread safety: NOT thread-safe.  All operations on an MtcMerkleTree
 * must be serialised by the caller.
 *
 * @date 2026-04-13
 */

#ifndef MTC_MERKLE_H
#define MTC_MERKLE_H

#include <stdint.h>

/** SHA-256 digest size in bytes (used for all tree hashes). */
#define MTC_HASH_SIZE 32

/**
 * @brief Append-only Merkle hash tree.
 *
 * @details
 * Stores leaf hashes and raw entry data in parallel dynamic arrays.
 * The tree structure is computed on demand (not cached) — all proof
 * and hash operations walk the arrays directly.
 *
 * Ownership: the tree owns all allocated memory in its arrays.
 * Call mtc_tree_free() to release.
 */
typedef struct {
    uint8_t  **leaf_hashes;  /**< Array of MTC_HASH_SIZE-byte leaf hashes
                                  (tree owns each allocation)              */
    uint8_t  **entries;      /**< Array of serialised entry byte buffers
                                  (tree owns each allocation)              */
    int       *entry_sizes;  /**< Size of each entry in bytes              */
    int        size;         /**< Number of entries currently in the tree   */
    int        capacity;     /**< Allocated slots in the arrays            */
} MtcMerkleTree;

/**
 * @brief    Initialise an empty Merkle tree.
 *
 * @param[out] tree  Tree to initialise.  Must not be NULL.
 *                    Allocates internal arrays with an initial capacity of 64.
 */
void     mtc_tree_init(MtcMerkleTree *tree);

/**
 * @brief    Free all memory owned by the tree and zero the struct.
 *
 * @param[in,out] tree  Tree to free.  Safe to re-init after this call.
 */
void     mtc_tree_free(MtcMerkleTree *tree);

/**
 * @brief    Append an entry to the tree.
 *
 * @details
 * Copies the entry data, computes the leaf hash (SHA-256(0x00 || entry)),
 * and stores both.  Grows the internal arrays if needed.
 *
 * @param[in,out] tree     Target tree.
 * @param[in]     entry    Serialised entry bytes.
 * @param[in]     entrySz  Size of entry in bytes.
 *
 * @return  Index of the newly appended entry (0-based).
 *
 * @note  The entry data is copied; the caller retains ownership of the
 *        input buffer.
 */
int      mtc_tree_append(MtcMerkleTree *tree, const uint8_t *entry, int entrySz);

/**
 * @brief    Compute the root hash of the first @p tree_size leaves.
 *
 * @param[in]  tree       Merkle tree.
 * @param[in]  tree_size  Number of leaves to include (1..tree->size).
 *                         If <= 0 or > tree->size, returns SHA-256("").
 * @param[out] out        Buffer for the MTC_HASH_SIZE-byte root hash.
 *
 * @return  0 always.
 */
int      mtc_tree_root_hash(MtcMerkleTree *tree, int tree_size, uint8_t *out);

/**
 * @brief    Compute the hash of a contiguous subtree [start, end).
 *
 * @param[in]  tree   Merkle tree.
 * @param[in]  start  First leaf index (inclusive).
 * @param[in]  end    One past the last leaf index (exclusive).
 * @param[out] out    Buffer for the MTC_HASH_SIZE-byte subtree hash.
 *
 * @return
 *   0   on success.
 *  -1   if start/end are out of range.
 */
int      mtc_tree_subtree_hash(MtcMerkleTree *tree, int start, int end, uint8_t *out);

/**
 * @brief    Generate an inclusion proof for a leaf.
 *
 * @details
 * Computes the Merkle inclusion path for leaf @p index within the
 * subtree [start, end), per RFC 9162 Section 2.1.3.
 *
 * @param[in]  tree         Merkle tree.
 * @param[in]  index        Leaf index to prove.
 * @param[in]  start        Subtree start (inclusive).
 * @param[in]  end          Subtree end (exclusive).
 * @param[out] proof_out    Receives a malloc'd buffer of sibling hashes
 *                           (each MTC_HASH_SIZE bytes).  Caller must free().
 * @param[out] proof_count  Receives the number of sibling hashes.
 *
 * @return
 *   0   on success.
 *  -1   if index is out of [start, end) or end > tree->size.
 */
int      mtc_tree_inclusion_proof(MtcMerkleTree *tree, int index, int start, int end,
                                   uint8_t **proof_out, int *proof_count);

/**
 * @brief    Generate a consistency proof between two tree sizes.
 *
 * @details
 * Computes the Merkle consistency proof from @p old_size to @p new_size,
 * per RFC 9162 Section 2.1.4.
 *
 * @param[in]  tree         Merkle tree.
 * @param[in]  old_size     Smaller tree size (>= 1).
 * @param[in]  new_size     Larger tree size (<= tree->size).
 * @param[out] proof_out    Receives a malloc'd buffer of hashes
 *                           (each MTC_HASH_SIZE bytes).  Caller must free().
 * @param[out] proof_count  Receives the number of hashes in the proof.
 *
 * @return
 *   0   on success.
 *  -1   if old_size < 1, new_size > tree->size, or old_size > new_size.
 */
int      mtc_tree_consistency_proof(MtcMerkleTree *tree, int old_size, int new_size,
                                     uint8_t **proof_out, int *proof_count);

/**
 * @brief    Compute a leaf hash per RFC 9162: SHA-256(0x00 || data).
 *
 * @param[in]  data    Leaf data bytes.
 * @param[in]  dataSz  Size of data in bytes.
 * @param[out] out     Buffer for the MTC_HASH_SIZE-byte hash.
 */
void     mtc_hash_leaf(const uint8_t *data, int dataSz, uint8_t *out);

/**
 * @brief    Compute an interior node hash per RFC 9162:
 *           SHA-256(0x01 || left || right).
 *
 * @param[in]  left   Left child hash (MTC_HASH_SIZE bytes).
 * @param[in]  right  Right child hash (MTC_HASH_SIZE bytes).
 * @param[out] out    Buffer for the MTC_HASH_SIZE-byte hash.
 */
void     mtc_hash_node(const uint8_t *left, const uint8_t *right, uint8_t *out);

#endif
