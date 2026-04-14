/**
 * @file mtc_crypt.h
 * @brief AES-CBC encryption with byte-rotation layer.
 *
 * @details
 * Provides symmetric encrypt/decrypt using wolfSSL AES-CBC with an
 * additional byte-rotation step for the DH bootstrap channel.
 *
 * @date 2026-04-14
 */

#ifndef MTC_CRYPT_H
#define MTC_CRYPT_H

typedef struct MtcCryptCtx MtcCryptCtx;

/**
 * @brief  Allocate and initialise an encryption context.
 *
 * @param[in] key     AES key (16, 24, or 32 bytes).
 * @param[in] keylen  Key length in bytes.
 * @return  Context pointer, or NULL on failure.
 */
MtcCryptCtx *mtc_crypt_init(unsigned char *key, unsigned int keylen);

/**
 * @brief  Encrypt buf in place (AES-CBC then rotate).
 *
 * @param[in]     ctx     Context from mtc_crypt_init().
 * @param[in,out] buf     Buffer to encrypt (modified in place).
 * @param[in]     buflen  Buffer length (must be multiple of 16, >= 32).
 * @return  0 on success, -1 on error.
 */
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char *buf,
                     unsigned int buflen);

/**
 * @brief  Decrypt buf in place (unrotate then AES-CBC).
 *
 * @param[in]     ctx     Context from mtc_crypt_init().
 * @param[in,out] buf     Buffer to decrypt (modified in place).
 * @param[in]     buflen  Buffer length (must be multiple of 16, >= 32).
 * @return  0 on success, -1 on error.
 */
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char *buf,
                     unsigned int buflen);

/**
 * @brief  Free the encryption context and zero key material.
 *
 * @param[in] ctx  Context to free (NULL is safe).
 * @return  0 always.
 */
int mtc_crypt_fin(MtcCryptCtx *ctx);

#endif /* MTC_CRYPT_H */
