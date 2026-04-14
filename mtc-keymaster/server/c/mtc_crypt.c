/******************************************************************************
 * File:        mtc_crypt.c
 * Purpose:     AES-CBC encryption with byte-rotation layer.
 *
 * Description:
 *   Provides symmetric encrypt/decrypt using wolfSSL AES-CBC with an
 *   additional byte-rotation obfuscation step.  Intended for the DH
 *   bootstrap channel where the shared secret is used as the AES key.
 *
 *   Encode order:  pad (random bit-7 noise + tail padding) → AES-CBC encrypt → rotate
 *   Decode order:  unrotate → AES-CBC decrypt → strip bit 7 + remove pad
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
#include <wolfssl/wolfcrypt/random.h>
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
 * Function:    mtc_crypt_add_pad  (static)
 *
 * Description:
 *   Pad a JSON buffer (ending with '}') to a multiple of WC_AES_BLOCK_SIZE
 *   (16) and at least 32 bytes.  Random bytes are appended after the
 *   closing '}' to fill the padded length.  The caller provides the
 *   output buffer and its size.
 *
 * Input Arguments:
 *   ctx        - Encryption context (unused currently, reserved).
 *   inbuf      - Input JSON buffer.  Must end with '}'.
 *   inbuflen   - Length of inbuf in bytes (not including any NUL).
 *   outbuf     - Output buffer.  Must be large enough for the padded result.
 *   outbuflen  - On entry: capacity of outbuf.
 *                On exit:  actual padded length written.
 *
 * Returns:
 *    0  on success.
 *   -1  if arguments are invalid, outbuf is too small, or RNG fails.
 ******************************************************************************/
static int mtc_crypt_add_pad(MtcCryptCtx *ctx, unsigned char *inbuf,
                             unsigned int inbuflen, unsigned char *outbuf,
                             unsigned int *outbuflen)
{
    unsigned int padded;
    unsigned int pad_bytes;
    unsigned char *mask;
    unsigned int i;
    WC_RNG rng;

    (void)ctx;

    if (inbuf == NULL || outbuf == NULL || outbuflen == NULL || inbuflen == 0)
        return -1;

    /* Round up to multiple of 16, minimum 32 */
    padded = (inbuflen + (WC_AES_BLOCK_SIZE - 1)) & ~(WC_AES_BLOCK_SIZE - 1);
    if (padded < 32)
        padded = 32;

    if (*outbuflen < padded)
        return -1;

    if (wc_InitRng(&rng) != 0)
        return -1;

    /* Copy original data */
    memcpy(outbuf, inbuf, inbuflen);

    /* Randomly set bit 7 on ASCII bytes to add noise.
     * JSON is pure ASCII (bits 0-6), so bit 7 is always spare.
     * Generate a random mask byte per character; if its low bit is set,
     * flip bit 7 on that output byte. */
    mask = alloca(inbuflen);
    if (wc_RNG_GenerateBlock(&rng, mask, inbuflen) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    for (i = 0; i < inbuflen; i++) {
        if (mask[i] & 0x01)
            outbuf[i] |= 0x80;
    }

    /* Fill tail padding with random bytes.
     * Ensure no pad byte looks like '}' (0x7D) after bit-7 stripping,
     * otherwise remove_pad would find a false end-of-JSON marker. */
    pad_bytes = padded - inbuflen;
    if (pad_bytes > 0) {
        if (wc_RNG_GenerateBlock(&rng, outbuf + inbuflen, pad_bytes) != 0) {
            wc_FreeRng(&rng);
            return -1;
        }
        for (i = inbuflen; i < padded; i++) {
            while ((outbuf[i] & 0x7F) == '}') {
                if (wc_RNG_GenerateBlock(&rng, &outbuf[i], 1) != 0) {
                    wc_FreeRng(&rng);
                    return -1;
                }
            }
        }
    }

    wc_FreeRng(&rng);
    *outbuflen = padded;
    return 0;
}

/******************************************************************************
 * Function:    mtc_crypt_remove_pad  (static)
 *
 * Description:
 *   Strip bit 7 from all bytes (reverting the noise added by add_pad),
 *   then locate the last '}' to find the end of the JSON content.
 *   Truncates everything after it and returns the original JSON length.
 *
 * Input Arguments:
 *   ctx     - Encryption context (unused currently, reserved).
 *   buf     - Decrypted buffer containing JSON (with bit-7 noise) followed
 *             by random pad bytes.  Modified in place (bit 7 cleared).
 *   buflen  - Total buffer length (padded).
 *   outlen  - On exit: length of the actual JSON content (up to and
 *             including the last '}').
 *
 * Returns:
 *    0  on success.
 *   -1  if no '}' is found in buf.
 ******************************************************************************/
static int mtc_crypt_remove_pad(MtcCryptCtx *ctx, unsigned char *buf,
                                unsigned int buflen, unsigned int *outlen)
{
    unsigned int i;

    (void)ctx;

    if (buf == NULL || outlen == NULL || buflen == 0)
        return -1;

    /* Strip bit 7 from every byte — restores original ASCII */
    for (i = 0; i < buflen; i++)
        buf[i] &= 0x7F;

    /* Scan backwards for the last '}' */
    for (i = buflen; i > 0; i--) {
        if (buf[i - 1] == '}') {
            *outlen = i;
            return 0;
        }
    }

    return -1;
}

/******************************************************************************
 * Function:    mtc_crypt_encode
 *
 * Description:
 *   Pad a JSON buffer to AES block alignment, encrypt using AES-CBC,
 *   then apply byte rotation.  The padded/encrypted result is written
 *   to outbuf and its length to *outbuflen.
 *
 * Input Arguments:
 *   ctx        - Initialised encryption context.  Must not be NULL.
 *   inbuf      - JSON input buffer (must end with '}').  Must not be NULL.
 *   inbuflen   - Length of inbuf in bytes.
 *   outbuf     - Output buffer for the encrypted result.  Must not be NULL.
 *   outbuflen  - On entry: capacity of outbuf.
 *                On exit: actual encrypted length (padded to block size).
 *
 * Returns:
 *    0  on success.
 *   -1  if any argument is invalid, outbuf is too small, or AES fails.
 *
 * Side Effects:
 *   - Mutates the internal Aes state (IV consumed by CBC mode).
 *   - Uses alloca for a temporary stack buffer.
 *   - Initialises/frees a WC_RNG for random pad bytes.
 ******************************************************************************/
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char *inbuf,
                     unsigned int inbuflen, unsigned char *outbuf,
                     unsigned int *outbuflen)
{
    unsigned char iv[AES_IV_SIZE];
    unsigned char *tmp;
    unsigned int padded_len;
    int ret;

    if (ctx == NULL || inbuf == NULL || outbuf == NULL || outbuflen == NULL)
        return -1;
    if (inbuflen == 0)
        return -1;

    /* Pad JSON to block-aligned length */
    padded_len = *outbuflen;
    ret = mtc_crypt_add_pad(ctx, inbuf, inbuflen, outbuf, &padded_len);
    if (ret != 0)
        return -1;

    /* Zero IV — rotation adds per-message variation */
    memset(iv, 0, AES_IV_SIZE);

    ret = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1;

    tmp = alloca(padded_len);
    ret = wc_AesCbcEncrypt(&ctx->aes, tmp, outbuf, padded_len);
    if (ret != 0)
        return -1;

    memcpy(outbuf, tmp, padded_len);
    *outbuflen = padded_len;

    /* Rotate as last step */
    return mtc_crypt_rotate(ctx, outbuf, padded_len);
}

/******************************************************************************
 * Function:    mtc_crypt_decode
 *
 * Description:
 *   Unrotate, decrypt using AES-CBC, then remove padding by locating
 *   the last '}' in the decrypted buffer.  The original JSON is written
 *   to outbuf and its length to *outbuflen.
 *
 * Input Arguments:
 *   ctx        - Initialised encryption context.  Must not be NULL.
 *   inbuf      - Encrypted input buffer.  Must not be NULL.
 *   inbuflen   - Length of inbuf (must be multiple of 16, >= 32).
 *   outbuf     - Output buffer for decrypted JSON.  Must not be NULL.
 *   outbuflen  - On entry: capacity of outbuf.
 *                On exit: actual JSON length (up to last '}').
 *
 * Returns:
 *    0  on success.
 *   -1  if arguments are invalid, AES fails, or no '}' found.
 *
 * Side Effects:
 *   - Mutates the internal Aes state (IV consumed by CBC mode).
 *   - Uses alloca for a temporary stack buffer.
 ******************************************************************************/
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char *inbuf,
                     unsigned int inbuflen, unsigned char *outbuf,
                     unsigned int *outbuflen)
{
    unsigned char iv[AES_IV_SIZE];
    unsigned char *tmp;
    unsigned int json_len;
    int ret;

    if (ctx == NULL || inbuf == NULL || outbuf == NULL || outbuflen == NULL)
        return -1;
    if (inbuflen % WC_AES_BLOCK_SIZE != 0 || inbuflen < 32)
        return -1;
    if (*outbuflen < inbuflen)
        return -1;

    /* Copy to outbuf for in-place operations */
    memcpy(outbuf, inbuf, inbuflen);

    /* Unrotate as first step */
    ret = mtc_crypt_unrotate(ctx, outbuf, inbuflen);
    if (ret != 0)
        return -1;

    /* Zero IV — must match encode */
    memset(iv, 0, AES_IV_SIZE);

    ret = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, iv, AES_DECRYPTION);
    if (ret != 0)
        return -1;

    tmp = alloca(inbuflen);
    ret = wc_AesCbcDecrypt(&ctx->aes, tmp, outbuf, inbuflen);
    if (ret != 0)
        return -1;

    memcpy(outbuf, tmp, inbuflen);

    /* Remove padding by finding last '}' */
    ret = mtc_crypt_remove_pad(ctx, outbuf, inbuflen, &json_len);
    if (ret != 0)
        return -1;

    *outbuflen = json_len;
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
 * TEST_MAIN — standalone round-trip tests
 ******************************************************************************/
#if defined(TEST_MAIN)

#include <stdio.h>

static int test_json(MtcCryptCtx *ctx, const char *json, const char *label)
{
    unsigned int inlen = (unsigned int)strlen(json);
    unsigned char enc[512];
    unsigned int  enc_len = sizeof(enc);
    unsigned char dec[512];
    unsigned int  dec_len = sizeof(dec);
    int sts;

    /* Encode */
    sts = mtc_crypt_encode(ctx, (unsigned char *)json, inlen, enc, &enc_len);
    if (sts != 0) {
        fprintf(stderr, "FAIL [%s]: mtc_crypt_encode returned %d\n", label, sts);
        return 1;
    }

    /* Verify ciphertext differs from plaintext */
    if (enc_len == inlen && memcmp(enc, json, inlen) == 0) {
        fprintf(stderr, "FAIL [%s]: encode did not change buffer\n", label);
        return 1;
    }

    /* Decode */
    sts = mtc_crypt_decode(ctx, enc, enc_len, dec, &dec_len);
    if (sts != 0) {
        fprintf(stderr, "FAIL [%s]: mtc_crypt_decode returned %d\n", label, sts);
        return 1;
    }

    /* Verify round-trip: length and content must match original */
    if (dec_len != inlen) {
        fprintf(stderr, "FAIL [%s]: length mismatch: got %u, expected %u\n",
                label, dec_len, inlen);
        return 1;
    }
    if (memcmp(dec, json, inlen) != 0) {
        fprintf(stderr, "FAIL [%s]: content mismatch\n", label);
        return 1;
    }

    printf("PASS [%s]: %u bytes JSON → %u bytes encrypted → %u bytes recovered\n",
           label, inlen, enc_len, dec_len);
    return 0;
}

int main(void)
{
    unsigned char key[AES_128_KEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    MtcCryptCtx *ctx;
    int fail = 0;

    ctx = mtc_crypt_init(key, AES_128_KEY_SIZE);
    if (!ctx) {
        fprintf(stderr, "FAIL: mtc_crypt_init returned NULL\n");
        return 1;
    }

    /* Test various irregular JSON lengths */
    fail |= test_json(ctx, "{\"key\":\"v\"}", "11 bytes");
    fail |= test_json(ctx, "{\"a\":1}", "7 bytes");
    fail |= test_json(ctx, "{\"name\":\"alice\",\"age\":30}", "24 bytes");
    fail |= test_json(ctx, "{\"x\":\"abcdefghijklmnop\"}", "22 bytes");
    fail |= test_json(ctx,
        "{\"public_key\":\"04b7a2...\",\"nonce\":\"f8c3d1e9\"}",
        "49 bytes");
    fail |= test_json(ctx,
        "{\"subject\":\"urn:ajax-inc:employee:joe.bosfitch\","
        "\"public_key_pem\":\"-----BEGIN PUBLIC KEY-----\\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\","
        "\"nonce\":\"a1b2c3d4e5f6\"}",
        "193 bytes");

    mtc_crypt_fin(ctx);

    if (fail) {
        fprintf(stderr, "\nSome tests FAILED\n");
        return 1;
    }
    printf("\nAll tests PASSED\n");
    return 0;
}

#endif /* TEST_MAIN */
