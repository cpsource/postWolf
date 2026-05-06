/******************************************************************************
 * File:        mtc_crypt.c
 * Purpose:     AES-256-GCM AEAD for the DH-bootstrap channel (port 8445).
 *
 * Description:
 *   Per-direction AES-256-GCM with random 96-bit nonces and a fixed 29-byte
 *   AAD that binds the protocol label, direction byte, and plaintext length.
 *
 *   Wire format per AEAD frame:
 *
 *       [12-byte nonce][N-byte ciphertext][16-byte tag]
 *
 *   AAD bound into every tag:
 *
 *       "mtc-bootstrap-aead/v1\n\x00"   (24 bytes incl. NUL)
 *       || direction_byte                (1 byte: 0x01 c2s, 0x02 s2c)
 *       || plaintext_length              (4 bytes BE)
 *
 *   Two 256-bit keys are required at init — one per direction.  Caller
 *   derives them from the X25519 shared secret + bootstrap salt via
 *   HKDF-SHA256.  Encode/decode select the key by direction parameter.
 *
 *   Replaces the historical AES-CBC + zero-IV + byte-rotation design.
 *   See README-bugsandtodo.md TODO #62 for the rationale.
 *
 * Dependencies:
 *   wolfssl/wolfcrypt/aes.h     (AES-GCM)
 *   wolfssl/wolfcrypt/random.h  (RNG for nonces)
 *
 * Created:     2026-04-14 (original AES-CBC version)
 * Rewritten:   2026-05-06 (AES-256-GCM; flag-day cutover for TODO #62)
 ******************************************************************************/

#include "mtc_crypt.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

/* AAD label.  23 bytes incl. trailing NUL (22 visible chars + the
 * compiler-added NUL terminator).  Must NEVER change without a
 * coordinated wire-format bump (CLAUDE.md guardrail). */
static const unsigned char MTC_BOOTSTRAP_AAD_LABEL[] =
    "mtc-bootstrap-aead/v1\n";
#define MTC_AAD_LABEL_LEN sizeof(MTC_BOOTSTRAP_AAD_LABEL)   /* 23 */

/* Total AAD length: label + dir byte + 4-byte plaintext_len BE. */
#define MTC_AAD_TOTAL_LEN (MTC_AAD_LABEL_LEN + 1 + 4)

/******************************************************************************
 * Function:    secure_zero  (static)
 *
 * Description:
 *   Zero a buffer using a volatile pointer so the compiler cannot
 *   optimise the write away.
 ******************************************************************************/
static void secure_zero(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
}

/******************************************************************************
 * Context structure (opaque outside this file).
 ******************************************************************************/
struct MtcCryptCtx {
    Aes           aes_c2s;
    Aes           aes_s2c;
    int           c2s_inited;
    int           s2c_inited;
    unsigned char c2s_key[MTC_CRYPT_KEY_SIZE];
    unsigned char s2c_key[MTC_CRYPT_KEY_SIZE];
};

/******************************************************************************
 * Function:    build_aad  (static)
 *
 * Description:
 *   Construct the per-frame AAD: fixed label || direction || plaintext_len_be.
 *   Output is exactly MTC_AAD_TOTAL_LEN bytes; caller-provided buffer must
 *   be at least that size.
 ******************************************************************************/
static void build_aad(unsigned char *aad, unsigned char dir,
                      unsigned int plaintext_len)
{
    memcpy(aad, MTC_BOOTSTRAP_AAD_LABEL, MTC_AAD_LABEL_LEN);
    aad[MTC_AAD_LABEL_LEN] = dir;
    aad[MTC_AAD_LABEL_LEN + 1] = (unsigned char)((plaintext_len >> 24) & 0xff);
    aad[MTC_AAD_LABEL_LEN + 2] = (unsigned char)((plaintext_len >> 16) & 0xff);
    aad[MTC_AAD_LABEL_LEN + 3] = (unsigned char)((plaintext_len >>  8) & 0xff);
    aad[MTC_AAD_LABEL_LEN + 4] = (unsigned char)( plaintext_len        & 0xff);
}

/******************************************************************************
 * Function:    mtc_crypt_init
 *
 * Description:
 *   Allocate and initialise an AEAD context.  Stores the per-direction
 *   keys and runs wc_AesInit / wc_AesGcmSetKey on each.
 *
 * Returns:
 *   Non-NULL pointer to a new MtcCryptCtx on success.
 *   NULL     if either key is NULL, malloc fails, or wolfSSL returns
 *            an error.
 ******************************************************************************/
MtcCryptCtx *mtc_crypt_init(const unsigned char *c2s_key,
                            const unsigned char *s2c_key)
{
    MtcCryptCtx *ctx;

    if (!c2s_key || !s2c_key)
        return NULL;

    ctx = (MtcCryptCtx *)malloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));

    memcpy(ctx->c2s_key, c2s_key, MTC_CRYPT_KEY_SIZE);
    memcpy(ctx->s2c_key, s2c_key, MTC_CRYPT_KEY_SIZE);

    if (wc_AesInit(&ctx->aes_c2s, NULL, INVALID_DEVID) != 0) {
        secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return NULL;
    }
    ctx->c2s_inited = 1;

    if (wc_AesInit(&ctx->aes_s2c, NULL, INVALID_DEVID) != 0) {
        wc_AesFree(&ctx->aes_c2s);
        secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return NULL;
    }
    ctx->s2c_inited = 1;

    if (wc_AesGcmSetKey(&ctx->aes_c2s, ctx->c2s_key,
                        MTC_CRYPT_KEY_SIZE) != 0 ||
        wc_AesGcmSetKey(&ctx->aes_s2c, ctx->s2c_key,
                        MTC_CRYPT_KEY_SIZE) != 0) {
        wc_AesFree(&ctx->aes_c2s);
        wc_AesFree(&ctx->aes_s2c);
        secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return NULL;
    }

    return ctx;
}

/******************************************************************************
 * Function:    pick_aes  (static)
 *
 * Description:
 *   Return the per-direction AES context for the given direction byte.
 *   Returns NULL if dir is invalid.
 ******************************************************************************/
static Aes *pick_aes(MtcCryptCtx *ctx, unsigned char dir)
{
    if (!ctx) return NULL;
    if (dir == MTC_DIR_C2S) return &ctx->aes_c2s;
    if (dir == MTC_DIR_S2C) return &ctx->aes_s2c;
    return NULL;
}

/******************************************************************************
 * Function:    mtc_crypt_encode
 *
 * Description:
 *   AES-256-GCM seal `inbuf` into `outbuf`.  Generates a fresh 96-bit
 *   nonce per call from wolfCrypt's RNG.
 *
 *   Output layout:
 *       [12-byte nonce][inbuflen-byte ciphertext][16-byte tag]
 *   Total output size = inbuflen + 28.
 *
 * Returns:
 *   0 on success.
 *  -1 on any error (NULL pointer, invalid dir, outbuf too small,
 *     RNG failure, GCM encrypt failure).
 ******************************************************************************/
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char dir,
                     const unsigned char *inbuf, unsigned int inbuflen,
                     unsigned char *outbuf, unsigned int *outbuflen)
{
    Aes *aes;
    WC_RNG rng;
    unsigned char aad[MTC_AAD_TOTAL_LEN];
    unsigned char *nonce;
    unsigned char *ct;
    unsigned char *tag;
    int rc, ret = -1;
    unsigned int needed;

    if (!ctx || !inbuf || !outbuf || !outbuflen)
        return -1;
    aes = pick_aes(ctx, dir);
    if (!aes) return -1;

    needed = inbuflen + MTC_CRYPT_OVERHEAD;
    if (*outbuflen < needed)
        return -1;

    nonce = outbuf;
    ct    = outbuf + MTC_CRYPT_NONCE_SIZE;
    tag   = ct + inbuflen;

    if (wc_InitRng(&rng) != 0)
        return -1;
    rc = wc_RNG_GenerateBlock(&rng, nonce, MTC_CRYPT_NONCE_SIZE);
    wc_FreeRng(&rng);
    if (rc != 0)
        return -1;

    build_aad(aad, dir, inbuflen);

    rc = wc_AesGcmEncrypt(aes,
                          ct, inbuf, inbuflen,
                          nonce, MTC_CRYPT_NONCE_SIZE,
                          tag, MTC_CRYPT_TAG_SIZE,
                          aad, sizeof(aad));
    if (rc == 0) {
        *outbuflen = needed;
        ret = 0;
    } else {
        secure_zero(outbuf, needed);
    }
    secure_zero(aad, sizeof(aad));
    return ret;
}

/******************************************************************************
 * Function:    mtc_crypt_decode
 *
 * Description:
 *   AES-256-GCM open + authenticate.  Verifies the tag against the
 *   reconstructed AAD (label + dir + plaintext_len BE).  Mismatch on
 *   ANY field — including the implicit plaintext-length binding —
 *   fails decryption.
 *
 *   Input layout:
 *       [12-byte nonce][N-byte ciphertext][16-byte tag]
 *   Plaintext length = inbuflen - 28.
 *
 * Returns:
 *   0 on success; outbuflen is set to the plaintext length.
 *  -1 on any failure: too-small input, NULL pointer, invalid dir,
 *     output buffer too small, GCM tag mismatch, plaintext-length
 *     overflow.  On failure outbuf is zeroed where wolfSSL touched it.
 ******************************************************************************/
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char dir,
                     const unsigned char *inbuf, unsigned int inbuflen,
                     unsigned char *outbuf, unsigned int *outbuflen)
{
    Aes *aes;
    unsigned char aad[MTC_AAD_TOTAL_LEN];
    const unsigned char *nonce;
    const unsigned char *ct;
    const unsigned char *tag;
    unsigned int ct_len;
    int rc, ret = -1;

    if (!ctx || !inbuf || !outbuf || !outbuflen)
        return -1;
    aes = pick_aes(ctx, dir);
    if (!aes) return -1;

    if (inbuflen < MTC_CRYPT_OVERHEAD)
        return -1;
    ct_len = inbuflen - MTC_CRYPT_OVERHEAD;
    if (*outbuflen < ct_len)
        return -1;

    nonce = inbuf;
    ct    = inbuf + MTC_CRYPT_NONCE_SIZE;
    tag   = ct + ct_len;

    build_aad(aad, dir, ct_len);

    rc = wc_AesGcmDecrypt(aes,
                          outbuf, ct, ct_len,
                          nonce, MTC_CRYPT_NONCE_SIZE,
                          tag, MTC_CRYPT_TAG_SIZE,
                          aad, sizeof(aad));
    if (rc == 0) {
        *outbuflen = ct_len;
        ret = 0;
    } else {
        secure_zero(outbuf, ct_len);
    }
    secure_zero(aad, sizeof(aad));
    return ret;
}

/******************************************************************************
 * Function:    mtc_crypt_fin
 *
 * Description:
 *   Free the AEAD context and securely zero key material.
 ******************************************************************************/
int mtc_crypt_fin(MtcCryptCtx *ctx)
{
    if (!ctx) return 0;
    if (ctx->c2s_inited) wc_AesFree(&ctx->aes_c2s);
    if (ctx->s2c_inited) wc_AesFree(&ctx->aes_s2c);
    secure_zero(ctx, sizeof(*ctx));
    free(ctx);
    return 0;
}
