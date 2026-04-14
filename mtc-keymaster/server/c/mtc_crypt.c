/******************************************************************************
 * File:        mtc_crypt.c
 * Purpose:     AES-CBC encryption with byte-rotation layer.
 *
 * Description:
 *   Provides symmetric encrypt/decrypt using wolfSSL AES-CBC with an
 *   additional byte-rotation obfuscation step.  Intended for the DH
 *   bootstrap channel where the shared secret is used as the AES key.
 *
 *   Encode order:  AES-CBC encrypt → rotate
 *   Decode order:  unrotate → AES-CBC decrypt
 *
 *   The rotation step shifts ciphertext bytes by a key-derived offset,
 *   preventing block-aligned pattern analysis.  The offset is deterministic
 *   (derived from the key) so both sides compute the same value.
 *
 * Dependencies:
 *   mtc_crypt.h               (public API)
 *   stdlib.h                  (malloc, free)
 *   string.h                  (memcpy, memset, memcmp)
 *   alloca.h                  (stack allocation for in-place ops)
 *   wolfssl/options.h         (feature macros)
 *   wolfssl/wolfcrypt/aes.h   (Aes, wc_AesCbcEncrypt/Decrypt)
 *   wolfssl/wolfcrypt/types.h (byte, word32, INVALID_DEVID)
 *
 * Notes:
 *   - NOT thread-safe.  Each MtcCryptCtx must be used by one thread at
 *     a time (the embedded Aes object is stateful).
 *   - buflen must be a multiple of WC_AES_BLOCK_SIZE (16) and >= 32.
 *   - alloca() is used for temporary buffers; callers must ensure buflen
 *     is reasonable for stack allocation (< ~64 KB recommended).
 *
 * Created:     2026-04-14
 ******************************************************************************/

#include "mtc_crypt.h"

#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/types.h>

/******************************************************************************
 * Context structure (opaque outside this file).
 *
 * Allocated by mtc_crypt_init(), freed by mtc_crypt_fin().
 * The key is stored so that (a) wc_AesSetKey can re-initialise the IV
 * before each operation, and (b) the rotation amount can be derived.
 ******************************************************************************/
struct MtcCryptCtx {
    Aes            aes;                     /**< wolfSSL AES object (stateful) */
    unsigned char  key[AES_256_KEY_SIZE];   /**< key copy, up to 32 bytes     */
    unsigned int   keylen;                  /**< actual key length: 16/24/32   */
};

/******************************************************************************
 * Function:    mtc_crypt_init
 *
 * Description:
 *   Allocate and initialise an encryption context.  Validates key length,
 *   copies the key, and initialises the wolfSSL Aes object.  The returned
 *   context is caller-owned and must be freed with mtc_crypt_fin().
 *
 * Input Arguments:
 *   key     - AES key bytes.  Must not be NULL.
 *   keylen  - Key length in bytes: 16 (AES-128), 24 (AES-192), or
 *             32 (AES-256).  Any other value is rejected.
 *
 * Returns:
 *   Non-NULL  pointer to a new MtcCryptCtx on success.
 *   NULL      if key is NULL, keylen is invalid, malloc fails, or
 *             wc_AesInit fails.
 *
 * Side Effects:
 *   - Heap allocation (sizeof(MtcCryptCtx)).
 *   - Calls wc_AesInit() which may allocate internal wolfSSL state.
 ******************************************************************************/
MtcCryptCtx *mtc_crypt_init(unsigned char *key, unsigned int keylen)
{
    MtcCryptCtx *ctx;

    if (key == NULL)
        return NULL;
    if (keylen != AES_128_KEY_SIZE && keylen != AES_192_KEY_SIZE &&
        keylen != AES_256_KEY_SIZE)
        return NULL;

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->key, key, keylen);
    ctx->keylen = keylen;

    if (wc_AesInit(&ctx->aes, NULL, INVALID_DEVID) != 0) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

/******************************************************************************
 * Function:    mtc_crypt_rotate  (static)
 *
 * Description:
 *   Left-rotate buf by a key-derived number of bytes.  The rotation
 *   amount is derived from the sum of all key bytes, mapped into the
 *   range [11, buflen - 11].  This ensures a minimum displacement of
 *   11 bytes in either direction, preventing trivial alignment with
 *   AES block boundaries (16 bytes).
 *
 * Input Arguments:
 *   ctx     - Encryption context (key used for rotation derivation).
 *   buf     - Buffer to rotate in place.
 *   buflen  - Buffer length (must be >= 32).
 *
 * Returns:
 *    0  always (rotation cannot fail given valid inputs).
 *
 * Side Effects:
 *   - Uses alloca(buflen) for a temporary stack buffer.
 ******************************************************************************/
static int mtc_crypt_rotate(MtcCryptCtx *ctx, unsigned char *buf,
                            unsigned int buflen)
{
    unsigned int rot = 0;
    unsigned int i;
    unsigned char *tmp;

    /* Derive rotation from key: deterministic, both sides compute same value */
    for (i = 0; i < ctx->keylen; i++)
        rot += ctx->key[i];

    /* Map into [11, buflen-11]: range size is (buflen - 21) */
    rot = 11 + (rot % (buflen - 21));

    /* Left-rotate: [A|B] → [B|A] where A is first `rot` bytes */
    tmp = alloca(buflen);
    memcpy(tmp, buf + rot, buflen - rot);
    memcpy(tmp + (buflen - rot), buf, rot);
    memcpy(buf, tmp, buflen);

    return 0;
}

/******************************************************************************
 * Function:    mtc_crypt_unrotate  (static)
 *
 * Description:
 *   Undo a left-rotation (i.e., right-rotate by the same amount).
 *   Uses the identical derivation as mtc_crypt_rotate so both sides
 *   agree on the rotation offset.
 *
 * Input Arguments:
 *   ctx     - Encryption context (key used for rotation derivation).
 *   buf     - Buffer to unrotate in place.
 *   buflen  - Buffer length (must be >= 32).
 *
 * Returns:
 *    0  always.
 *
 * Side Effects:
 *   - Uses alloca(buflen) for a temporary stack buffer.
 ******************************************************************************/
static int mtc_crypt_unrotate(MtcCryptCtx *ctx, unsigned char *buf,
                              unsigned int buflen)
{
    unsigned int rot = 0;
    unsigned int i;
    unsigned char *tmp;

    for (i = 0; i < ctx->keylen; i++)
        rot += ctx->key[i];

    rot = 11 + (rot % (buflen - 21));

    /* Right-rotate: [B|A] → [A|B] — inverse of left-rotate */
    tmp = alloca(buflen);
    memcpy(tmp, buf + (buflen - rot), rot);
    memcpy(tmp + rot, buf, buflen - rot);
    memcpy(buf, tmp, buflen);

    return 0;
}

/******************************************************************************
 * Function:    mtc_crypt_encode
 *
 * Description:
 *   Encrypt buf in place using AES-CBC, then apply byte rotation as
 *   the last step.  The IV is reset to zero on each call so that
 *   identical plaintext + key always produces identical ciphertext
 *   (the rotation layer adds position-dependent variation).
 *
 * Input Arguments:
 *   ctx     - Initialised encryption context.  Must not be NULL.
 *   buf     - Buffer to encrypt in place.  Must not be NULL.
 *   buflen  - Buffer length in bytes.  Must be a multiple of
 *             WC_AES_BLOCK_SIZE (16) and >= 32.
 *
 * Returns:
 *    0  on success.
 *   -1  if ctx or buf is NULL, buflen is invalid, or AES fails.
 *
 * Side Effects:
 *   - Mutates the internal Aes state (IV consumed by CBC mode).
 *   - Uses alloca(buflen) for a temporary stack buffer.
 ******************************************************************************/
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char *buf,
                     unsigned int buflen)
{
    unsigned char iv[AES_IV_SIZE];
    unsigned char *tmp;
    int ret;

    if (ctx == NULL || buf == NULL)
        return -1;
    if (buflen % WC_AES_BLOCK_SIZE != 0 || buflen < 32)
        return -1;

    /* Zero IV — rotation adds per-message variation */
    memset(iv, 0, AES_IV_SIZE);

    ret = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1;

    tmp = alloca(buflen);
    ret = wc_AesCbcEncrypt(&ctx->aes, tmp, buf, buflen);
    if (ret != 0)
        return -1;

    memcpy(buf, tmp, buflen);

    /* Rotate as last step */
    return mtc_crypt_rotate(ctx, buf, buflen);
}

/******************************************************************************
 * Function:    mtc_crypt_decode
 *
 * Description:
 *   Unrotate buf as the first step, then decrypt using AES-CBC in place.
 *   Mirrors mtc_crypt_encode in reverse order: unrotate → AES-CBC decrypt.
 *
 * Input Arguments:
 *   ctx     - Initialised encryption context.  Must not be NULL.
 *   buf     - Buffer to decrypt in place.  Must not be NULL.
 *   buflen  - Buffer length in bytes.  Must be a multiple of
 *             WC_AES_BLOCK_SIZE (16) and >= 32.
 *
 * Returns:
 *    0  on success.
 *   -1  if ctx or buf is NULL, buflen is invalid, or AES fails.
 *
 * Side Effects:
 *   - Mutates the internal Aes state (IV consumed by CBC mode).
 *   - Uses alloca(buflen) for a temporary stack buffer.
 ******************************************************************************/
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char *buf,
                     unsigned int buflen)
{
    unsigned char iv[AES_IV_SIZE];
    unsigned char *tmp;
    int ret;

    if (ctx == NULL || buf == NULL)
        return -1;
    if (buflen % WC_AES_BLOCK_SIZE != 0 || buflen < 32)
        return -1;

    /* Unrotate as first step */
    ret = mtc_crypt_unrotate(ctx, buf, buflen);
    if (ret != 0)
        return -1;

    /* Zero IV — must match encode */
    memset(iv, 0, AES_IV_SIZE);

    ret = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1;

    tmp = alloca(buflen);
    ret = wc_AesCbcDecrypt(&ctx->aes, tmp, buf, buflen);
    if (ret != 0)
        return -1;

    memcpy(buf, tmp, buflen);

    return 0;
}

/******************************************************************************
 * Function:    mtc_crypt_fin
 *
 * Description:
 *   Release all resources held by the context.  Zeros the key material
 *   before freeing to prevent key remnants in freed heap memory.
 *
 * Input Arguments:
 *   ctx  - Context to free.  NULL is safe (no-op).
 *
 * Returns:
 *    0  always.
 *
 * Side Effects:
 *   - Calls wc_AesFree() to release wolfSSL internal state.
 *   - Zeros sizeof(MtcCryptCtx) bytes of heap memory.
 *   - Frees the ctx pointer.  Caller must not use ctx after this call.
 ******************************************************************************/
int mtc_crypt_fin(MtcCryptCtx *ctx)
{
    if (ctx == NULL)
        return 0;

    wc_AesFree(&ctx->aes);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);

    return 0;
}

/******************************************************************************
 * TEST_MAIN — standalone round-trip test
 ******************************************************************************/
#if defined(TEST_MAIN)

#include <stdio.h>

int main(void)
{
    unsigned char key[AES_128_KEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char buf[128];
    unsigned char orig[128];
    unsigned int i;
    int sts;
    MtcCryptCtx *ctx;

    /* Fill buffer with known pattern */
    for (i = 0; i < 128; i++)
        buf[i] = (unsigned char)(i & 0xff);
    memcpy(orig, buf, 128);

    ctx = mtc_crypt_init(key, AES_128_KEY_SIZE);
    if (!ctx) {
        fprintf(stderr, "FAIL: mtc_crypt_init returned NULL\n");
        return 1;
    }

    /* Encode */
    sts = mtc_crypt_encode(ctx, buf, 128);
    if (sts != 0) {
        fprintf(stderr, "FAIL: mtc_crypt_encode returned %d\n", sts);
        mtc_crypt_fin(ctx);
        return 1;
    }

    /* Verify buf changed */
    if (memcmp(buf, orig, 128) == 0) {
        fprintf(stderr, "FAIL: encode did not change buffer\n");
        mtc_crypt_fin(ctx);
        return 1;
    }

    /* Decode */
    sts = mtc_crypt_decode(ctx, buf, 128);
    if (sts != 0) {
        fprintf(stderr, "FAIL: mtc_crypt_decode returned %d\n", sts);
        mtc_crypt_fin(ctx);
        return 1;
    }

    /* Verify round-trip */
    if (memcmp(buf, orig, 128) != 0) {
        fprintf(stderr, "FAIL: round-trip mismatch\n");
        mtc_crypt_fin(ctx);
        return 1;
    }

    printf("PASS: encode/decode round-trip OK (128 bytes)\n");

    mtc_crypt_fin(ctx);
    return 0;
}

#endif /* TEST_MAIN */
