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
 * @brief  Encrypt a JSON buffer (pad, AES-CBC, then rotate).
 *
 * @param[in]     ctx        Context from mtc_crypt_init().
 * @param[in]     inbuf      JSON input (must end with '}').
 * @param[in]     inbuflen   Length of inbuf in bytes.
 * @param[out]    outbuf     Output buffer for encrypted data.
 * @param[in,out] outbuflen  On entry: capacity of outbuf.
 *                           On exit: actual encrypted length (padded).
 * @return  0 on success, -1 on error.
 */
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char *inbuf,
                     unsigned int inbuflen, unsigned char *outbuf,
                     unsigned int *outbuflen);

/**
 * @brief  Decrypt a buffer and remove padding (unrotate, AES-CBC, unpad).
 *
 * @param[in]     ctx        Context from mtc_crypt_init().
 * @param[in]     inbuf      Encrypted input buffer.
 * @param[in]     inbuflen   Length of inbuf (must be multiple of 16, >= 32).
 * @param[out]    outbuf     Output buffer for decrypted JSON.
 * @param[in,out] outbuflen  On entry: capacity of outbuf.
 *                           On exit: actual JSON length (up to last '}').
 * @return  0 on success, -1 on error.
 */
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char *inbuf,
                     unsigned int inbuflen, unsigned char *outbuf,
                     unsigned int *outbuflen);

/**
 * @brief  Free the encryption context and zero key material.
 *
 * @param[in] ctx  Context to free (NULL is safe).
 * @return  0 always.
 */
int mtc_crypt_fin(MtcCryptCtx *ctx);

#endif /* MTC_CRYPT_H */
