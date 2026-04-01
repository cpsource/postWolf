/* wolfssl/wolfcrypt/mtc.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * Merkle Tree Certificate proof verification (RFC 9162 / draft-ietf-plants-merkle-tree-certs).
 */

#ifndef WOLF_CRYPT_MTC_H
#define WOLF_CRYPT_MTC_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef HAVE_MTC

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 digest size used for all Merkle tree hashes (RFC 9162 Section 2) */
#define MTC_HASH_SZ  WC_SHA256_DIGEST_SIZE  /* 32 */

/* Maximum inclusion proof depth (log2 of max tree size) */
#define MTC_MAX_PROOF_DEPTH  64

/* Domain separation prefix for cosignatures (MTC draft Section 5.4.1) */
#define MTC_COSIGN_LABEL     "MTC SubtreeSign v1"
#define MTC_COSIGN_LABEL_SZ  18

/* Parsed Merkle Tree Certificate proof (from X.509 signatureValue) */
typedef struct MtcProof {
    word64   start;                 /* Subtree start index */
    word64   end;                   /* Subtree end index (exclusive) */
    byte*    inclusionPath;         /* Concatenated SHA-256 hashes */
    word16   inclusionPathSz;       /* Total bytes in inclusionPath */
    word16   pathCount;             /* Number of hashes (inclusionPathSz / 32) */
    byte*    subtreeHash;           /* Expected subtree root hash (32 bytes) */
} MtcProof;

/* Trusted cosigner public key */
typedef struct MtcCosigner {
    byte*    id;                    /* Cosigner identifier */
    word16   idSz;
    byte*    pubKey;                /* Ed25519 or ECDSA public key (DER) */
    word16   pubKeySz;
    int      sigAlg;                /* e.g., CTC_ED25519 */
} MtcCosigner;

/* RFC 9162 Section 2.1: Hash a leaf node.
 * out = SHA-256(0x00 || data[0..dataSz-1])
 * out must be at least MTC_HASH_SZ bytes. */
WOLFSSL_API int wc_MtcHashLeaf(byte* out, const byte* data, word32 dataSz);

/* RFC 9162 Section 2.1: Hash an internal node.
 * out = SHA-256(0x01 || left[0..31] || right[0..31])
 * out must be at least MTC_HASH_SZ bytes. */
WOLFSSL_API int wc_MtcHashNode(byte* out, const byte* left, const byte* right);

/* Verify a Merkle inclusion proof.
 * Given a leaf hash, an inclusion path (array of sibling hashes), a leaf
 * index within [start, end), and the expected subtree root hash, verify
 * that the proof is correct.
 *
 * leafHash:     SHA-256 hash of the leaf entry (32 bytes)
 * proof:        parsed MtcProof with inclusionPath and subtreeHash
 * leafIndex:    index of the leaf in the log
 *
 * Returns 0 on success (proof valid), negative on error. */
WOLFSSL_API int wc_MtcVerifyInclusionProof(const byte* leafHash,
    const MtcProof* proof, word64 leafIndex);

/* Verify an Ed25519 cosignature over a subtree.
 *
 * subtreeHash:  the subtree root hash (32 bytes)
 * start:        subtree start index
 * end:          subtree end index
 * signature:    Ed25519 signature bytes
 * signatureSz:  signature length
 * pubKey:       cosigner Ed25519 public key (DER)
 * pubKeySz:     public key length
 *
 * Returns 0 on success, negative on error. */
WOLFSSL_API int wc_MtcVerifyCosignature(const byte* subtreeHash,
    word64 start, word64 end,
    const byte* signature, word32 signatureSz,
    const byte* pubKey, word32 pubKeySz);

/* Parse an MTCProof structure from DER bytes (X.509 signatureValue field).
 *
 * input:   raw proof bytes
 * inputSz: length of input
 * proof:   output structure (caller allocates, inclusionPath is allocated
 *          internally and must be freed with wc_MtcFreeProof)
 *
 * Returns 0 on success, negative on error. */
WOLFSSL_API int wc_MtcParseProof(const byte* input, word32 inputSz,
    MtcProof* proof);

/* Free dynamically allocated fields in an MtcProof. */
WOLFSSL_API void wc_MtcFreeProof(MtcProof* proof);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_MTC */
#endif /* WOLF_CRYPT_MTC_H */
