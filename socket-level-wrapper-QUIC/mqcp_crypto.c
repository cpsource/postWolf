/* mqcp_crypto.c — Crypto wrappers for MQCP
 *
 * Uses wolfSSL for AES-256-GCM and HKDF-SHA256.
 * Adapted from MQC (mqc.c) nonce/key derivation patterns.
 */

#include "mqcp_crypto.h"

#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>

void mqcp_secure_zero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;
    for (size_t i = 0; i < len; i++)
        p[i] = 0;
}

int mqcp_hkdf(const uint8_t *secret, size_t secret_len,
              const char *info,
              uint8_t *out, size_t out_len) {
    int ret = wc_HKDF(WC_SHA256,
                      secret, (word32)secret_len,
                      NULL, 0,
                      (const byte *)info, (word32)strlen(info),
                      out, (word32)out_len);
    return ret == 0 ? 0 : -1;
}

int mqcp_derive_keys(const uint8_t shared_secret[32],
                     uint8_t client_key[MQCP_AES_KEY_SZ],
                     uint8_t server_key[MQCP_AES_KEY_SZ],
                     uint8_t client_pn_mask[MQCP_PN_MASK_SZ],
                     uint8_t server_pn_mask[MQCP_PN_MASK_SZ]) {
    if (mqcp_hkdf(shared_secret, 32, "mqcp-client-key",
                  client_key, MQCP_AES_KEY_SZ) != 0)
        return -1;
    if (mqcp_hkdf(shared_secret, 32, "mqcp-server-key",
                  server_key, MQCP_AES_KEY_SZ) != 0)
        return -1;
    if (mqcp_hkdf(shared_secret, 32, "mqcp-client-pn",
                  client_pn_mask, MQCP_PN_MASK_SZ) != 0)
        return -1;
    if (mqcp_hkdf(shared_secret, 32, "mqcp-server-pn",
                  server_pn_mask, MQCP_PN_MASK_SZ) != 0)
        return -1;
    return 0;
}

void mqcp_make_nonce(uint64_t pn, const uint8_t pn_mask[MQCP_PN_MASK_SZ],
                     uint8_t nonce[MQCP_GCM_IV_SZ]) {
    memset(nonce, 0, MQCP_GCM_IV_SZ);
    /* First 4 bytes: XOR with per-connection mask */
    nonce[0] = pn_mask[0];
    nonce[1] = pn_mask[1];
    nonce[2] = pn_mask[2];
    nonce[3] = pn_mask[3];
    /* Last 8 bytes: big-endian packet number */
    nonce[4]  = (uint8_t)(pn >> 56);
    nonce[5]  = (uint8_t)(pn >> 48);
    nonce[6]  = (uint8_t)(pn >> 40);
    nonce[7]  = (uint8_t)(pn >> 32);
    nonce[8]  = (uint8_t)(pn >> 24);
    nonce[9]  = (uint8_t)(pn >> 16);
    nonce[10] = (uint8_t)(pn >> 8);
    nonce[11] = (uint8_t)(pn);
}

int mqcp_aes_gcm_encrypt(const uint8_t key[MQCP_AES_KEY_SZ],
                         const uint8_t nonce[MQCP_GCM_IV_SZ],
                         const uint8_t *pt, size_t pt_len,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ct,
                         uint8_t tag[MQCP_GCM_TAG_SZ]) {
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return -1;

    ret = wc_AesGcmSetKey(&aes, key, MQCP_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); return -1; }

    ret = wc_AesGcmEncrypt(&aes, ct, pt, (word32)pt_len,
                           nonce, MQCP_GCM_IV_SZ,
                           tag, MQCP_GCM_TAG_SZ,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);
    return ret == 0 ? 0 : -1;
}

int mqcp_aes_gcm_decrypt(const uint8_t key[MQCP_AES_KEY_SZ],
                         const uint8_t nonce[MQCP_GCM_IV_SZ],
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t tag[MQCP_GCM_TAG_SZ],
                         uint8_t *pt) {
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return -1;

    ret = wc_AesGcmSetKey(&aes, key, MQCP_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); return -1; }

    ret = wc_AesGcmDecrypt(&aes, pt, ct, (word32)ct_len,
                           nonce, MQCP_GCM_IV_SZ,
                           tag, MQCP_GCM_TAG_SZ,
                           aad, (word32)aad_len);
    wc_AesFree(&aes);
    return ret == 0 ? 0 : -1;
}
