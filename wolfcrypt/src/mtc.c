/* wolfcrypt/src/mtc.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * Merkle Tree Certificate proof verification.
 * Implements RFC 9162 Section 2.1 Merkle tree hashing and
 * draft-ietf-plants-merkle-tree-certs inclusion proof verification.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_MTC

#include <wolfssl/wolfcrypt/mtc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

/* RFC 9162 Section 2.1: leaf hash = SHA-256(0x00 || data) */
int wc_MtcHashLeaf(byte* out, const byte* data, word32 dataSz)
{
    wc_Sha256 sha;
    byte prefix = 0x00;
    int ret;

    if (out == NULL || (data == NULL && dataSz > 0))
        return BAD_FUNC_ARG;

    ret = wc_InitSha256(&sha);
    if (ret != 0)
        return ret;

    ret = wc_Sha256Update(&sha, &prefix, 1);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, data, dataSz);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, out);

    wc_Sha256Free(&sha);
    return ret;
}

/* RFC 9162 Section 2.1: node hash = SHA-256(0x01 || left || right) */
int wc_MtcHashNode(byte* out, const byte* left, const byte* right)
{
    wc_Sha256 sha;
    byte prefix = 0x01;
    int ret;

    if (out == NULL || left == NULL || right == NULL)
        return BAD_FUNC_ARG;

    ret = wc_InitSha256(&sha);
    if (ret != 0)
        return ret;

    ret = wc_Sha256Update(&sha, &prefix, 1);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, left, MTC_HASH_SZ);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, right, MTC_HASH_SZ);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, out);

    wc_Sha256Free(&sha);
    return ret;
}

/* Verify Merkle inclusion proof per RFC 9162 Section 2.1.3.
 *
 * Walk up the tree from the leaf to the root, combining with sibling
 * hashes from the inclusion path. If the leaf index bit is 0 at a given
 * level, the sibling is on the right; otherwise on the left.
 *
 * The subtree covers indices [start, end). The leaf's position within
 * the subtree is (leafIndex - start). The subtree size is (end - start).
 */
int wc_MtcVerifyInclusionProof(const byte* leafHash,
    const MtcProof* proof, word64 leafIndex)
{
    byte current[MTC_HASH_SZ];
    byte combined[MTC_HASH_SZ];
    word64 idx;
    word64 subtreeSize;
    int i;
    int ret;

    if (leafHash == NULL || proof == NULL || proof->subtreeHash == NULL)
        return BAD_FUNC_ARG;

    if (leafIndex < proof->start || leafIndex >= proof->end)
        return BAD_FUNC_ARG;

    subtreeSize = proof->end - proof->start;
    idx = leafIndex - proof->start;

    /* Start with the leaf hash */
    XMEMCPY(current, leafHash, MTC_HASH_SZ);

    /* Walk up the tree using each sibling in the inclusion path */
    for (i = 0; i < proof->pathCount; i++) {
        const byte* sibling = proof->inclusionPath + (i * MTC_HASH_SZ);

        if (idx & 1) {
            /* Leaf is on the right, sibling is on the left */
            ret = wc_MtcHashNode(combined, sibling, current);
        }
        else {
            /* Leaf is on the left, sibling is on the right */
            ret = wc_MtcHashNode(combined, current, sibling);
        }
        if (ret != 0)
            return ret;

        XMEMCPY(current, combined, MTC_HASH_SZ);
        idx >>= 1;
    }

    /* Verify computed root matches expected subtree hash */
    if (XMEMCMP(current, proof->subtreeHash, MTC_HASH_SZ) != 0)
        return SIG_VERIFY_E;

    (void)subtreeSize;
    return 0;
}

/* Verify Ed25519 cosignature over a subtree.
 *
 * The signed message is:
 *   MTC_COSIGN_LABEL (18 bytes) || start (8 bytes BE) || end (8 bytes BE)
 *   || subtreeHash (32 bytes)
 */
int wc_MtcVerifyCosignature(const byte* subtreeHash,
    word64 start, word64 end,
    const byte* signature, word32 signatureSz,
    const byte* pubKey, word32 pubKeySz)
{
#ifdef HAVE_ED25519
    ed25519_key key;
    byte msg[MTC_COSIGN_LABEL_SZ + 8 + 8 + MTC_HASH_SZ];
    int verified = 0;
    int ret;

    if (subtreeHash == NULL || signature == NULL || pubKey == NULL)
        return BAD_FUNC_ARG;

    /* Build signed message:
     *   label || start (big-endian) || end (big-endian) || subtreeHash */
    XMEMCPY(msg, MTC_COSIGN_LABEL, MTC_COSIGN_LABEL_SZ);

    msg[MTC_COSIGN_LABEL_SZ + 0] = (byte)(start >> 56);
    msg[MTC_COSIGN_LABEL_SZ + 1] = (byte)(start >> 48);
    msg[MTC_COSIGN_LABEL_SZ + 2] = (byte)(start >> 40);
    msg[MTC_COSIGN_LABEL_SZ + 3] = (byte)(start >> 32);
    msg[MTC_COSIGN_LABEL_SZ + 4] = (byte)(start >> 24);
    msg[MTC_COSIGN_LABEL_SZ + 5] = (byte)(start >> 16);
    msg[MTC_COSIGN_LABEL_SZ + 6] = (byte)(start >> 8);
    msg[MTC_COSIGN_LABEL_SZ + 7] = (byte)(start);

    msg[MTC_COSIGN_LABEL_SZ + 8]  = (byte)(end >> 56);
    msg[MTC_COSIGN_LABEL_SZ + 9]  = (byte)(end >> 48);
    msg[MTC_COSIGN_LABEL_SZ + 10] = (byte)(end >> 40);
    msg[MTC_COSIGN_LABEL_SZ + 11] = (byte)(end >> 32);
    msg[MTC_COSIGN_LABEL_SZ + 12] = (byte)(end >> 24);
    msg[MTC_COSIGN_LABEL_SZ + 13] = (byte)(end >> 16);
    msg[MTC_COSIGN_LABEL_SZ + 14] = (byte)(end >> 8);
    msg[MTC_COSIGN_LABEL_SZ + 15] = (byte)(end);

    XMEMCPY(msg + MTC_COSIGN_LABEL_SZ + 16, subtreeHash, MTC_HASH_SZ);

    ret = wc_ed25519_init(&key);
    if (ret != 0)
        return ret;

    ret = wc_ed25519_import_public(pubKey, pubKeySz, &key);
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(signature, signatureSz,
            msg, (word32)sizeof(msg), &verified, &key);
    }

    wc_ed25519_free(&key);

    if (ret == 0 && !verified)
        return SIG_VERIFY_E;

    return ret;
#else
    (void)subtreeHash; (void)start; (void)end;
    (void)signature; (void)signatureSz;
    (void)pubKey; (void)pubKeySz;
    return NOT_COMPILED_IN;
#endif
}

/* Parse an MTCProof from raw bytes.
 *
 * Wire format (draft-ietf-plants-merkle-tree-certs Section 5.3):
 *   start:          8 bytes (big-endian uint64)
 *   end:            8 bytes (big-endian uint64)
 *   pathCount:      2 bytes (big-endian uint16)
 *   inclusionPath:  pathCount * 32 bytes
 *   subtreeHash:    32 bytes
 */
int wc_MtcParseProof(const byte* input, word32 inputSz, MtcProof* proof)
{
    word32 idx = 0;
    word16 pathCount;
    word32 pathBytes;

    if (input == NULL || proof == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(proof, 0, sizeof(MtcProof));

    /* Need at least: start(8) + end(8) + pathCount(2) + subtreeHash(32) */
    if (inputSz < 50)
        return BUFFER_E;

    /* start (8 bytes big-endian) */
    proof->start = ((word64)input[idx] << 56) | ((word64)input[idx+1] << 48) |
                   ((word64)input[idx+2] << 40) | ((word64)input[idx+3] << 32) |
                   ((word64)input[idx+4] << 24) | ((word64)input[idx+5] << 16) |
                   ((word64)input[idx+6] << 8)  | (word64)input[idx+7];
    idx += 8;

    /* end (8 bytes big-endian) */
    proof->end = ((word64)input[idx] << 56) | ((word64)input[idx+1] << 48) |
                 ((word64)input[idx+2] << 40) | ((word64)input[idx+3] << 32) |
                 ((word64)input[idx+4] << 24) | ((word64)input[idx+5] << 16) |
                 ((word64)input[idx+6] << 8)  | (word64)input[idx+7];
    idx += 8;

    if (proof->end <= proof->start)
        return ASN_PARSE_E;

    /* pathCount (2 bytes big-endian) */
    pathCount = ((word16)input[idx] << 8) | input[idx+1];
    idx += 2;

    if (pathCount > MTC_MAX_PROOF_DEPTH)
        return ASN_PARSE_E;

    pathBytes = (word32)pathCount * MTC_HASH_SZ;

    /* Remaining: pathBytes + subtreeHash(32) */
    if (idx + pathBytes + MTC_HASH_SZ > inputSz)
        return BUFFER_E;

    proof->pathCount = pathCount;
    proof->inclusionPathSz = (word16)pathBytes;

    if (pathBytes > 0) {
        proof->inclusionPath = (byte*)XMALLOC(pathBytes, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (proof->inclusionPath == NULL)
            return MEMORY_E;
        XMEMCPY(proof->inclusionPath, input + idx, pathBytes);
    }
    idx += pathBytes;

    proof->subtreeHash = (byte*)XMALLOC(MTC_HASH_SZ, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (proof->subtreeHash == NULL) {
        if (proof->inclusionPath != NULL)
            XFREE(proof->inclusionPath, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        proof->inclusionPath = NULL;
        return MEMORY_E;
    }
    XMEMCPY(proof->subtreeHash, input + idx, MTC_HASH_SZ);

    return 0;
}

/* Free dynamically allocated fields in an MtcProof. */
void wc_MtcFreeProof(MtcProof* proof)
{
    if (proof == NULL)
        return;

    if (proof->inclusionPath != NULL) {
        XFREE(proof->inclusionPath, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        proof->inclusionPath = NULL;
    }
    if (proof->subtreeHash != NULL) {
        XFREE(proof->subtreeHash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        proof->subtreeHash = NULL;
    }
}

#endif /* HAVE_MTC */
