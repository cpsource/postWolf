/* mtc_merkle.h — Merkle tree for MTC CA server (RFC 9162) */

#ifndef MTC_MERKLE_H
#define MTC_MERKLE_H

#include <stdint.h>

#define MTC_HASH_SIZE 32

typedef struct {
    uint8_t  **leaf_hashes;   /* Array of 32-byte leaf hashes */
    uint8_t  **entries;       /* Array of serialized entry bytes */
    int       *entry_sizes;   /* Size of each entry */
    int        size;          /* Number of entries */
    int        capacity;      /* Allocated slots */
} MtcMerkleTree;

void     mtc_tree_init(MtcMerkleTree *tree);
void     mtc_tree_free(MtcMerkleTree *tree);
int      mtc_tree_append(MtcMerkleTree *tree, const uint8_t *entry, int entrySz);
int      mtc_tree_root_hash(MtcMerkleTree *tree, int tree_size, uint8_t *out);
int      mtc_tree_subtree_hash(MtcMerkleTree *tree, int start, int end, uint8_t *out);
int      mtc_tree_inclusion_proof(MtcMerkleTree *tree, int index, int start, int end,
                                   uint8_t **proof_out, int *proof_count);
int      mtc_tree_consistency_proof(MtcMerkleTree *tree, int old_size, int new_size,
                                     uint8_t **proof_out, int *proof_count);

/* Leaf/node hashing (RFC 9162 Section 2.1) */
void     mtc_hash_leaf(const uint8_t *data, int dataSz, uint8_t *out);
void     mtc_hash_node(const uint8_t *left, const uint8_t *right, uint8_t *out);

#endif
