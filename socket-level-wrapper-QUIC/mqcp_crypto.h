/* mqcp_crypto.h — Crypto wrappers for MQCP
 *
 * AES-256-GCM encrypt/decrypt, HKDF-SHA256 key derivation,
 * nonce construction. Adapted from MQC (mqc.c) patterns.
 */

#ifndef MQCP_CRYPTO_H
#define MQCP_CRYPTO_H

#include "mqcp_types.h"

/* Derive session keys from ML-KEM shared secret.
 * Produces: client_key[32], server_key[32], client_pn_mask[4], server_pn_mask[4].
 * Returns 0 on success, -1 on error. */
int mqcp_derive_keys(const uint8_t shared_secret[32],
                     uint8_t client_key[MQCP_AES_KEY_SZ],
                     uint8_t server_key[MQCP_AES_KEY_SZ],
                     uint8_t client_pn_mask[MQCP_PN_MASK_SZ],
                     uint8_t server_pn_mask[MQCP_PN_MASK_SZ]);

/* Derive a single key via HKDF-SHA256 with given info string.
 * Returns 0 on success, -1 on error. */
int mqcp_hkdf(const uint8_t *secret, size_t secret_len,
              const char *info,
              uint8_t *out, size_t out_len);

/* Build 12-byte nonce from packet number and 4-byte mask.
 * nonce[0..3] = mask XOR 0, nonce[4..11] = big-endian packet number. */
void mqcp_make_nonce(uint64_t pn, const uint8_t pn_mask[MQCP_PN_MASK_SZ],
                     uint8_t nonce[MQCP_GCM_IV_SZ]);

/* AES-256-GCM encrypt.
 * aad/aad_len: additional authenticated data (header bytes).
 * ct must be at least pt_len bytes. tag must be 16 bytes.
 * Returns 0 on success, -1 on error. */
int mqcp_aes_gcm_encrypt(const uint8_t key[MQCP_AES_KEY_SZ],
                         const uint8_t nonce[MQCP_GCM_IV_SZ],
                         const uint8_t *pt, size_t pt_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ct,
                         uint8_t tag[MQCP_GCM_TAG_SZ]);

/* AES-256-GCM decrypt.
 * Returns 0 on success, -1 on auth failure or error. */
int mqcp_aes_gcm_decrypt(const uint8_t key[MQCP_AES_KEY_SZ],
                         const uint8_t nonce[MQCP_GCM_IV_SZ],
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t tag[MQCP_GCM_TAG_SZ],
                         uint8_t *pt);

/* Zero sensitive memory. */
void mqcp_secure_zero(void *buf, size_t len);

#endif /* MQCP_CRYPTO_H */
