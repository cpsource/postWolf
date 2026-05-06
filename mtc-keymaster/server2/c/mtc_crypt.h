/**
 * @file mtc_crypt.h
 * @brief AES-256-GCM AEAD for the DH-bootstrap channel (port 8445).
 *
 * @details
 * Per-direction AES-256-GCM with random 96-bit nonces and 31-byte AAD.
 * Wire format per AEAD frame:
 *
 *     [12-byte nonce][N-byte ciphertext][16-byte GCM tag]
 *
 * Total output size = plaintext length + 28.
 *
 * AAD bound into every tag:
 *
 *     "mtc-bootstrap-aead/v1\n"     (23 bytes incl. compiler NUL)
 *     || direction_byte              (1 byte: 0x01 c2s, 0x02 s2c)
 *     || plaintext_length            (4 bytes BE)
 *
 * (28 bytes total, referred to as the "bootstrap AAD".)
 *
 * Two independent 256-bit keys — one per direction — are derived from
 * the X25519 shared secret + bootstrap salt via HKDF-SHA256.  Caller
 * passes both at init time.  Encode/decode take a direction parameter
 * that selects the key AND is bound into the AAD so a MitM cannot
 * cross-replay a request frame as a response (or vice versa).
 *
 * Replaces the historical AES-CBC + zero-IV + byte-rotation +
 * find-last-`}` design in commits prior to phase-25.  Closes
 * TODO #62 in `README-bugsandtodo.md`.
 *
 * @date 2026-05-06
 */

#ifndef MTC_CRYPT_H
#define MTC_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#define MTC_CRYPT_KEY_SIZE   32   /**< AES-256 key size                  */
#define MTC_CRYPT_NONCE_SIZE 12   /**< GCM standard nonce size           */
#define MTC_CRYPT_TAG_SIZE   16   /**< GCM authentication tag size       */
#define MTC_CRYPT_OVERHEAD   (MTC_CRYPT_NONCE_SIZE + MTC_CRYPT_TAG_SIZE)
                                  /**< per-frame wire overhead = 28 B    */

#define MTC_DIR_C2S          0x01 /**< Client → Server                   */
#define MTC_DIR_S2C          0x02 /**< Server → Client                   */

typedef struct MtcCryptCtx MtcCryptCtx;

/**
 * @brief  Allocate and initialise an AEAD context.
 *
 * @param[in] c2s_key   32-byte key for client→server direction.
 * @param[in] s2c_key   32-byte key for server→client direction.
 *
 * @return  Context pointer, or NULL if either key is NULL or
 *          allocation fails.
 *
 * @note    Both keys MUST be 32 bytes each (AES-256).  The caller is
 *          expected to derive them via HKDF — see callers in
 *          mtc_bootstrap.c / bootstrap_leaf.c / bootstrap_ca.c.
 */
MtcCryptCtx *mtc_crypt_init(const unsigned char *c2s_key,
                            const unsigned char *s2c_key);

/**
 * @brief  AEAD encrypt one frame.
 *
 * @param[in]     ctx        Context from mtc_crypt_init().
 * @param[in]     dir        MTC_DIR_C2S or MTC_DIR_S2C — bound into AAD,
 *                           selects the encryption key.
 * @param[in]     inbuf      Plaintext bytes (any binary content).
 * @param[in]     inbuflen   Length of inbuf in bytes.
 * @param[out]    outbuf     Output buffer; needs inbuflen + 28 bytes.
 * @param[in,out] outbuflen  On entry: capacity of outbuf.
 *                           On exit: actual frame length (= inbuflen + 28).
 *
 * @return  0 on success; -1 if any pointer is NULL, dir is invalid,
 *          outbuf too small, or wolfSSL returns an error.
 *
 * @details Output layout:
 *          @code
 *          [12-byte nonce][inbuflen-byte ciphertext][16-byte tag]
 *          @endcode
 *          Nonce is freshly RNG-generated per call.
 */
int mtc_crypt_encode(MtcCryptCtx *ctx, unsigned char dir,
                     const unsigned char *inbuf, unsigned int inbuflen,
                     unsigned char *outbuf, unsigned int *outbuflen);

/**
 * @brief  AEAD decrypt + authenticate one frame.
 *
 * @param[in]     ctx        Context from mtc_crypt_init().
 * @param[in]     dir        MTC_DIR_C2S or MTC_DIR_S2C — must match the
 *                           direction used at encode time.
 * @param[in]     inbuf      Ciphertext frame: [nonce][ct][tag].
 * @param[in]     inbuflen   Total frame length (>= 28; ciphertext bytes
 *                           = inbuflen - 28).
 * @param[out]    outbuf     Plaintext output; needs (inbuflen - 28) bytes.
 * @param[in,out] outbuflen  On entry: capacity of outbuf.
 *                           On exit: actual plaintext length.
 *
 * @return  0 on success; -1 on any failure (length too small, AAD
 *          mismatch, GCM tag mismatch, etc.).  On failure outbuf is
 *          left zeroed where wolfSSL touched it.
 */
int mtc_crypt_decode(MtcCryptCtx *ctx, unsigned char dir,
                     const unsigned char *inbuf, unsigned int inbuflen,
                     unsigned char *outbuf, unsigned int *outbuflen);

/**
 * @brief  Free the AEAD context and zero key material.
 *
 * @param[in] ctx  Context to free (NULL is safe).
 * @return  0 always.
 */
int mtc_crypt_fin(MtcCryptCtx *ctx);

#endif /* MTC_CRYPT_H */
