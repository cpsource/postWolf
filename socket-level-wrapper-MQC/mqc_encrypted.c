/******************************************************************************
 * File:        mqc_encrypted.c
 * Purpose:     Encrypted-identity-mode handshake bodies for MQC.
 *
 * Description:
 *   The 4-frame encrypted-identity handshake (spec §7).  A passive
 *   observer learns ML-KEM public bytes only; both peers' cert_index
 *   and signature are AEAD-sealed under an "early secret" derived
 *   from the anonymous KEM exchange.
 *
 *     Phase 1 (plaintext):
 *       client → server: { version, suite, mode:"encrypted", kem_pub }
 *       server → client: { version, suite, mode:"encrypted", kem_pub }
 *       both compute transcript_hash_phase1 (with C_c=C_s=0)
 *       both derive early_c2s/s2c keys+IVs from SS + that hash
 *
 *     Phase 2 (encrypted, sealed with early keys at sequence 0):
 *       client → server: AEAD( { cert_index, signature_over_full_txn } )
 *       server → client: AEAD( { cert_index, signature_over_full_txn } )
 *       both compute transcript_hash_full (both cert_index populated)
 *       both derive data_*_key / iv / finished from SS + that hash
 *
 *     Then: Finished frame each direction at sequence 0 of the data
 *     keys (per spec §8.1, identical to clear-mode).  Application
 *     data starts at sequence 1.
 *
 *   Public API: mqc_connect / mqc_accept in mqc.c dispatch here when
 *   ctx->encrypt_identity != 0.
 *
 *   All shared machinery (transcript hash, key schedule, AEAD seal,
 *   Finished frame, JSON parsers, peer verify, rate limits) lives in
 *   mqc_common.c and is reached via mqc_internal.h.
 *
 * Created:     2026-05-03  (Phase 7 commit 2 — replaces the stubs
 *              that landed in commit 1)
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>

#include <json-c/json.h>

/* Maximum size of the AEAD-sealed phase-2 identity blob's plaintext.
 * The plaintext is JSON of the form
 *   {"cert_index":<int>,"signature":"<9254 hex chars>"}
 * — under 9300 bytes by a wide margin even with maximum json-c
 * formatting overhead.  Round to 16 KiB. */
#define MQC_PHASE2_PLAINTEXT_MAX  (16 * 1024)

mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port)
{
    int fd = -1;
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t encaps_key[MQC_MLKEM768_PUB_SZ];
    word32 encaps_key_sz;
    uint8_t sig[MQC_MLDSA87_SIG_SZ];
    word32 sig_sz = sizeof(sig);
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t early_c2s_key[MQC_AES_KEY_SZ], early_s2c_key[MQC_AES_KEY_SZ];
    uint8_t early_c2s_iv [MQC_GCM_IV_SZ],   early_s2c_iv[MQC_GCM_IV_SZ];
    uint64_t early_c2s_seq = 0, early_s2c_seq = 0;
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_phase1[WC_SHA256_DIGEST_SIZE];
    uint8_t th_sign  [WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf   [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;
    uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
    int ct_sz = MQC_MLKEM768_CT_SZ;

    /* ---- TCP connect ---------------------------------------------- */
    {
        struct addrinfo hints, *res, *rp;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;
        for (rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) {
            MQC_TRACE("[mqc-enc] TCP connect to %s:%d failed\n", host, port);
            return NULL;
        }
    }
    MQC_TRACE("[mqc-enc] connected to %s:%d\n", host, port);

    if (wc_InitRng(&rng) != 0) goto fail;
    rng_ok = 1;

    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) { fprintf(stderr, "[mqc-enc] ML-KEM init: %d\n", ret); goto fail; }
    mlkem_ok = 1;
    ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc-enc] ML-KEM keygen: %d\n", ret); goto fail; }
    wc_MlKemKey_PublicKeySize(&mlkem, &encaps_key_sz);
    if (encaps_key_sz != MQC_MLKEM768_PUB_SZ) {
        fprintf(stderr, "[mqc-enc] ML-KEM pub size %u != %u\n",
                encaps_key_sz, MQC_MLKEM768_PUB_SZ);
        goto fail;
    }
    ret = wc_MlKemKey_EncodePublicKey(&mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) { fprintf(stderr, "[mqc-enc] ML-KEM encode pub: %d\n", ret); goto fail; }

    /* ---- Phase 1: send ClientHello (KEM only, no signature) ------ */
    {
        char *ek_hex = malloc(encaps_key_sz * 2 + 1);
        int json_len;
        if (!ek_hex) goto fail;
        mqc_to_hex(encaps_key, (int)encaps_key_sz, ek_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"encrypted\","
            "\"kem_pub\":\"%s\"}",
            MQC_PROTOCOL_VERSION, MQC_SUITE_STRING, ek_hex);
        free(ek_hex);
        if (mqc_write_handshake_frame(fd, json_buf,
                                      (unsigned int)json_len) != 0) goto fail;
    }
    MQC_TRACE("[mqc-enc] sent phase-1 ClientHello\n");

    /* ---- Phase 1: receive ServerHello (KEM only, no signature) -- */
    ret = mqc_read_handshake_frame(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;
    {
        struct json_object *resp = NULL;
        int dummy_version;
        static const char *const phase1_fields[] = {
            "version", "suite", "mode", "kem_pub"
        };

        resp = mqc_json_parse_strict("ServerHello-phase1", json_buf, ret);
        if (!resp) goto fail;
        if (mqc_json_no_duplicates("ServerHello-phase1", json_buf, ret,
                phase1_fields, 4) != 0 ||
            mqc_json_no_unknown_keys("ServerHello-phase1", resp,
                phase1_fields, 4) != 0 ||
            mqc_json_get_int_strict("ServerHello-phase1", resp, "version",
                MQC_PROTOCOL_VERSION, MQC_PROTOCOL_VERSION,
                &dummy_version) != 0 ||
            mqc_json_get_string_exact("ServerHello-phase1", resp, "suite",
                MQC_SUITE_STRING) != 0 ||
            mqc_json_get_string_exact("ServerHello-phase1", resp, "mode",
                "encrypted") != 0 ||
            mqc_json_get_hex_strict("ServerHello-phase1", resp, "kem_pub",
                MQC_MLKEM768_CT_SZ, ciphertext) != 0) {
            json_object_put(resp);
            goto fail;
        }
        json_object_put(resp);
    }
    MQC_TRACE("[mqc-enc] received phase-1 ServerHello\n");

    /* ---- ML-KEM decapsulate -> shared secret -------------------- */
    ret = wc_MlKemKey_Decapsulate(&mlkem, shared_secret,
                                  ciphertext, (word32)ct_sz);
    if (ret != 0) {
        fprintf(stderr, "[mqc-enc] ML-KEM decapsulate: %d\n", ret);
        goto fail;
    }

    /* ---- Phase-1 transcript hash (C_c=C_s=0) + early-key schedule */
    ret = mqc_transcript_hash_kdf(th_phase1, MQC_MODE_ENCRYPTED,
        encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
        0, 0);
    if (ret != 0) goto fail;
    ret = mqc_derive_early_keys(shared_secret, th_phase1,
                                early_c2s_key, early_s2c_key,
                                early_c2s_iv,  early_s2c_iv);
    if (ret != 0) goto fail;

    /* ---- Sign client's view of the FULL transcript (C_c populated,
     *      C_s=0).  This is what the spec §10.2 / §6.0 requires:
     *      every signature covers transcript_hash_sig(role) over the
     *      full transcript, NOT the phase-1 transcript.            */
    ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_ENCRYPTED,
        encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
        ctx->our_cert_index, 0, MQC_ROLE_CLIENT);
    if (ret != 0) goto fail;

    wc_dilithium_init(&dil);
    dil_ok = 1;
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    {
        word32 dil_idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx,
            &dil, (word32)ctx->privkey_der_sz);
    }
    if (ret != 0) { fprintf(stderr, "[mqc-enc] DSA import: %d\n", ret); goto fail; }
    ret = wc_dilithium_sign_ctx_msg(
        (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
        th_sign, WC_SHA256_DIGEST_SIZE,
        sig, &sig_sz, &dil, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc-enc] DSA sign: %d\n", ret); goto fail; }

    /* ---- Phase 2: send AEAD-sealed { cert_index, signature } ---- */
    {
        char *sig_hex = malloc(sig_sz * 2 + 1);
        char inner[MQC_PHASE2_PLAINTEXT_MAX];
        int inner_len;
        if (!sig_hex) goto fail;
        mqc_to_hex(sig, (int)sig_sz, sig_hex);
        inner_len = snprintf(inner, sizeof(inner),
            "{\"cert_index\":%d,\"signature\":\"%s\"}",
            ctx->our_cert_index, sig_hex);
        free(sig_hex);
        if (inner_len <= 0 || inner_len >= (int)sizeof(inner)) goto fail;

        if (mqc_enc_send(fd, early_c2s_key, early_c2s_iv,
                         &early_c2s_seq,
                         MQC_DIR_C2S, MQC_FRAME_TYPE_PHASE2_IDENTITY,
                         inner, inner_len) != 0) goto fail;
    }
    MQC_TRACE("[mqc-enc] sent phase-2 client identity (cert_index=%d)\n",
              ctx->our_cert_index);

    /* ---- Phase 2: receive AEAD-sealed server identity ----------- */
    {
        char inner[MQC_PHASE2_PLAINTEXT_MAX];
        int  inner_len;
        struct json_object *resp = NULL;
        uint8_t resp_sig[MQC_MLDSA87_SIG_SZ];
        int resp_sig_sz = MQC_MLDSA87_SIG_SZ;
        int peer_index = -1;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;
        static const char *const phase2_fields[] = {
            "cert_index", "signature"
        };

        inner_len = mqc_enc_recv(fd, early_s2c_key, early_s2c_iv,
                                 &early_s2c_seq,
                                 MQC_DIR_S2C, MQC_FRAME_TYPE_PHASE2_IDENTITY,
                                 inner, sizeof(inner) - 1);
        if (inner_len <= 0) {
            MQC_SECURITY("phase-2 server identity: AEAD decrypt failed");
            goto fail;
        }
        inner[inner_len] = '\0';

        resp = mqc_json_parse_strict("ServerHello-phase2", inner, inner_len);
        if (!resp) goto fail;
        if (mqc_json_no_duplicates("ServerHello-phase2", inner, inner_len,
                phase2_fields, 2) != 0 ||
            mqc_json_no_unknown_keys("ServerHello-phase2", resp,
                phase2_fields, 2) != 0 ||
            mqc_json_get_int_strict("ServerHello-phase2", resp, "cert_index",
                0, INT_MAX, &peer_index) != 0 ||
            mqc_json_get_hex_strict("ServerHello-phase2", resp, "signature",
                MQC_MLDSA87_SIG_SZ, resp_sig) != 0) {
            json_object_put(resp);
            goto fail;
        }
        json_object_put(resp);

        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, mqc_rt_cfg()->revocation_policy,
                              &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d", peer_index);
            goto fail;
        }

        /* Server signed the FULL transcript with both cert_index values. */
        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_ENCRYPTED,
            encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
            ctx->our_cert_index, peer_index, MQC_ROLE_SERVER);
        if (ret != 0) { free(peer_pubkey); goto fail; }

        {
            dilithium_key peer_dil;
            int verified = 0;
            wc_dilithium_init(&peer_dil);
            wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
            {
                word32 peer_idx = 0;
                ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &peer_idx,
                    &peer_dil, (word32)peer_pubkey_sz);
            }
            if (ret == 0) {
                ret = wc_dilithium_verify_ctx_msg(
                    resp_sig, (word32)resp_sig_sz,
                    (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
                    th_sign, WC_SHA256_DIGEST_SIZE,
                    &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);
            if (ret != 0 || !verified) {
                MQC_SECURITY("SIG_VERIFY_FAILED: server signature invalid (encrypted mode)");
                goto fail;
            }
        }
        MQC_TRACE("[mqc-enc] peer %d verified + signature OK\n", peer_index);

        /* Issue #9: expected-identity check (same logic as clear). */
        {
            char subject[256];
            const char *expected = ctx->expected_name;
            int do_check = 1;

            if (expected && expected[0] == '\0') {
                do_check = 0;
            } else if (!expected) {
                if (mqc_is_ip_literal(host)) {
                    MQC_SECURITY("NAME_CHECK_FAILED: dialed IP literal '%s' "
                        "with no expected name; call mqc_ctx_set_expected_name() "
                        "or mqc_ctx_disable_name_check()", host);
                    goto fail;
                }
                expected = host;
            }
            if (do_check) {
                if (mqc_peer_get_cached_subject(peer_index, subject,
                                                sizeof(subject)) != 0) {
                    MQC_SECURITY("NAME_CHECK_FAILED: no cached subject for verified cert %d",
                                 peer_index);
                    goto fail;
                }
                if (!mqc_cert_name_matches(subject, expected)) {
                    MQC_SECURITY("NAME_CHECK_FAILED: cert subject '%s' does not match expected '%s'",
                                 subject, expected);
                    goto fail;
                }
                MQC_TRACE("[mqc-enc] subject '%s' matches expected '%s'\n",
                          subject, expected);
            }
        }

        /* ---- Full-transcript KDF + data key schedule ------------ */
        ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_ENCRYPTED,
            encaps_key, encaps_key_sz, ciphertext, (size_t)ct_sz,
            ctx->our_cert_index, peer_index);
        if (ret != 0) goto fail;
        ret = mqc_derive_data_keys(shared_secret, th_kdf,
                                   c2s_key, s2c_key, c2s_iv, s2c_iv,
                                   c2s_finished, s2c_finished);
        if (ret != 0) goto fail;

        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->send_key, c2s_key, MQC_AES_KEY_SZ);
        memcpy(conn->recv_key, s2c_key, MQC_AES_KEY_SZ);
        memcpy(conn->send_iv,  c2s_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->recv_iv,  s2c_iv,  MQC_GCM_IV_SZ);
        memcpy(conn->send_finished_key, c2s_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->recv_finished_key, s2c_finished, MQC_FINISHED_MAC_SZ);
        memcpy(conn->transcript_hash_full, th_kdf, WC_SHA256_DIGEST_SIZE);
        conn->peer_index = peer_index;
        {
            char subj[256];
            if (mqc_peer_get_cached_subject(peer_index, subj,
                                            sizeof(subj)) == 0)
                conn->peer_subject = strdup(subj);
        }
        conn->is_client = 1;
        conn->send_seq = 0;
        conn->recv_seq = 0;
        conn->finished_verified = 0;

        if (mqc_send_finished(conn) != 0) goto fail;
        if (mqc_recv_finished(conn) != 0) goto fail;
        MQC_TRACE("[mqc-enc] session established with peer %d (Finished verified)\n",
                  peer_index);
    }

    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(early_c2s_key, sizeof(early_c2s_key));
    mqc_secure_zero(early_s2c_key, sizeof(early_s2c_key));
    mqc_secure_zero(early_c2s_iv,  sizeof(early_c2s_iv));
    mqc_secure_zero(early_s2c_iv,  sizeof(early_s2c_iv));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_phase1, sizeof(th_phase1));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    MQC_TRACE("[mqc-enc] connect to %s:%d failed (handshake)\n", host, port);
    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(early_c2s_key, sizeof(early_c2s_key));
    mqc_secure_zero(early_s2c_key, sizeof(early_s2c_key));
    mqc_secure_zero(early_c2s_iv,  sizeof(early_c2s_iv));
    mqc_secure_zero(early_s2c_iv,  sizeof(early_s2c_iv));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_phase1, sizeof(th_phase1));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn->peer_subject); free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

/* Continuation: caller has already done the prologue (abuse / RL /
 * RL_fail / socket timeout), armed HANDSHAKE_DEADLINE_ACTIVE, and
 * read the FIRST handshake frame (the phase-1 ClientHello with KEM
 * pubkey).  We own the fd from here; close it on any failure path.
 * Direct entry: mqc_accept_encrypted (this file).  Mode-dispatched
 * entry: mqc_accept_auto in mqc.c. */
mqc_conn_t *mqc_accept_encrypted_continue(mqc_ctx_t *ctx, int fd,
                                           const char *client_ip,
                                           const char *first_frame,
                                           int first_frame_len)
{
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t encaps_key[MQC_MLKEM768_PUB_SZ];
    int ek_sz = MQC_MLKEM768_PUB_SZ;
    uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
    word32 ct_sz;
    uint8_t sig[MQC_MLDSA87_SIG_SZ];
    word32 sig_sz = sizeof(sig);
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t early_c2s_key[MQC_AES_KEY_SZ], early_s2c_key[MQC_AES_KEY_SZ];
    uint8_t early_c2s_iv [MQC_GCM_IV_SZ],   early_s2c_iv[MQC_GCM_IV_SZ];
    uint64_t early_c2s_seq = 0, early_s2c_seq = 0;
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_phase1[WC_SHA256_DIGEST_SIZE];
    uint8_t th_sign  [WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf   [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;
    int peer_index = -1;
    MQC_LOG("encrypted-mode handshake from %s", client_ip);

    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    rng_ok = 1;

    /* ---- Phase 1 ClientHello already read by caller ------------ */
    if (first_frame_len <= 0 ||
        first_frame_len > (int)sizeof(json_buf) - 1) {
        MQC_SECURITY("encrypted continuation: invalid first_frame_len=%d",
                     first_frame_len);
        goto fail;
    }
    memcpy(json_buf, first_frame, (size_t)first_frame_len);
    json_buf[first_frame_len] = '\0';
    ret = first_frame_len;
    {
        struct json_object *req = NULL;
        int dummy_version;
        static const char *const phase1_fields[] = {
            "version", "suite", "mode", "kem_pub"
        };

        req = mqc_json_parse_strict("ClientHello-phase1", json_buf, ret);
        if (!req) goto fail;
        if (mqc_json_no_duplicates("ClientHello-phase1", json_buf, ret,
                phase1_fields, 4) != 0 ||
            mqc_json_no_unknown_keys("ClientHello-phase1", req,
                phase1_fields, 4) != 0 ||
            mqc_json_get_int_strict("ClientHello-phase1", req, "version",
                MQC_PROTOCOL_VERSION, MQC_PROTOCOL_VERSION,
                &dummy_version) != 0 ||
            mqc_json_get_string_exact("ClientHello-phase1", req, "suite",
                MQC_SUITE_STRING) != 0 ||
            mqc_json_get_string_exact("ClientHello-phase1", req, "mode",
                "encrypted") != 0 ||
            mqc_json_get_hex_strict("ClientHello-phase1", req, "kem_pub",
                MQC_MLKEM768_PUB_SZ, encaps_key) != 0) {
            json_object_put(req);
            goto fail;
        }
        json_object_put(req);
    }

    /* ---- ML-KEM encapsulate against client's public key -------- */
    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) goto fail;
    mlkem_ok = 1;
    ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key,
                                      (word32)ek_sz);
    if (ret != 0) {
        fprintf(stderr, "[mqc-enc] ML-KEM decode pub: %d\n", ret);
        goto fail;
    }
    ct_sz = sizeof(ciphertext);
    wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
    if (ct_sz != MQC_MLKEM768_CT_SZ) {
        fprintf(stderr, "[mqc-enc] ML-KEM ct size %u != %u\n",
                ct_sz, MQC_MLKEM768_CT_SZ);
        goto fail;
    }
    ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
    if (ret != 0) {
        fprintf(stderr, "[mqc-enc] ML-KEM encapsulate: %d\n", ret);
        goto fail;
    }

    /* ---- Phase 1: send ServerHello (KEM only) ----------------- */
    {
        char *ct_hex = malloc(ct_sz * 2 + 1);
        int json_len;
        if (!ct_hex) goto fail;
        mqc_to_hex(ciphertext, (int)ct_sz, ct_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"encrypted\","
            "\"kem_pub\":\"%s\"}",
            MQC_PROTOCOL_VERSION, MQC_SUITE_STRING, ct_hex);
        free(ct_hex);
        if (mqc_write_handshake_frame(fd, json_buf,
                                      (unsigned int)json_len) != 0) goto fail;
    }
    MQC_TRACE("[mqc-enc] sent phase-1 ServerHello\n");

    /* ---- Phase-1 transcript hash + early-key schedule --------- */
    ret = mqc_transcript_hash_kdf(th_phase1, MQC_MODE_ENCRYPTED,
        encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
        0, 0);
    if (ret != 0) goto fail;
    ret = mqc_derive_early_keys(shared_secret, th_phase1,
                                early_c2s_key, early_s2c_key,
                                early_c2s_iv,  early_s2c_iv);
    if (ret != 0) goto fail;

    /* ---- Phase 2: receive AEAD-sealed { cert_index, signature } */
    {
        char inner[MQC_PHASE2_PLAINTEXT_MAX];
        int  inner_len;
        struct json_object *req = NULL;
        uint8_t req_sig[MQC_MLDSA87_SIG_SZ];
        int req_sig_sz = MQC_MLDSA87_SIG_SZ;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;
        static const char *const phase2_fields[] = {
            "cert_index", "signature"
        };

        inner_len = mqc_enc_recv(fd, early_c2s_key, early_c2s_iv,
                                 &early_c2s_seq,
                                 MQC_DIR_C2S, MQC_FRAME_TYPE_PHASE2_IDENTITY,
                                 inner, sizeof(inner) - 1);
        if (inner_len <= 0) {
            MQC_SECURITY("phase-2 client identity: AEAD decrypt failed");
            goto fail;
        }
        inner[inner_len] = '\0';

        req = mqc_json_parse_strict("ClientHello-phase2", inner, inner_len);
        if (!req) goto fail;
        if (mqc_json_no_duplicates("ClientHello-phase2", inner, inner_len,
                phase2_fields, 2) != 0 ||
            mqc_json_no_unknown_keys("ClientHello-phase2", req,
                phase2_fields, 2) != 0 ||
            mqc_json_get_int_strict("ClientHello-phase2", req, "cert_index",
                0, INT_MAX, &peer_index) != 0 ||
            mqc_json_get_hex_strict("ClientHello-phase2", req, "signature",
                MQC_MLDSA87_SIG_SZ, req_sig) != 0) {
            json_object_put(req);
            goto fail;
        }
        json_object_put(req);

        /* Per-IP distinct-cert_index throttle (same as clear). */
        if (mqc_ratelimit_cert_check(client_ip, peer_index) != 0) goto fail;

        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, mqc_rt_cfg()->revocation_policy,
                              &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d", peer_index);
            goto fail;
        }

        /* Client's signature covers the FULL transcript with C_c
         * populated and C_s=0 (mirror of clear-mode §6.0). */
        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_ENCRYPTED,
            encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
            peer_index, 0, MQC_ROLE_CLIENT);
        if (ret != 0) { free(peer_pubkey); goto fail; }

        {
            dilithium_key peer_dil;
            int verified = 0;
            wc_dilithium_init(&peer_dil);
            wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
            {
                word32 peer_idx = 0;
                ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &peer_idx,
                    &peer_dil, (word32)peer_pubkey_sz);
            }
            if (ret == 0) {
                ret = wc_dilithium_verify_ctx_msg(
                    req_sig, (word32)req_sig_sz,
                    (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
                    th_sign, WC_SHA256_DIGEST_SIZE,
                    &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);
            if (ret != 0 || !verified) {
                MQC_SECURITY("SIG_VERIFY_FAILED: client signature invalid (encrypted mode)");
                goto fail;
            }
        }
        MQC_TRACE("[mqc-enc] peer %d verified + signature OK\n", peer_index);
    }

    /* ---- Server signs FULL transcript with both cert_index ---- */
    ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_ENCRYPTED,
        encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
        peer_index, ctx->our_cert_index, MQC_ROLE_SERVER);
    if (ret != 0) goto fail;
    wc_dilithium_init(&dil);
    dil_ok = 1;
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    {
        word32 dil_idx2 = 0;
        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx2,
            &dil, (word32)ctx->privkey_der_sz);
    }
    if (ret != 0) { fprintf(stderr, "[mqc-enc] server DSA import: %d\n", ret); goto fail; }
    ret = wc_dilithium_sign_ctx_msg(
        (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
        th_sign, WC_SHA256_DIGEST_SIZE,
        sig, &sig_sz, &dil, &rng);
    if (ret != 0) goto fail;

    /* ---- Phase 2: send AEAD-sealed server identity ------------ */
    {
        char *sig_hex = malloc(sig_sz * 2 + 1);
        char inner[MQC_PHASE2_PLAINTEXT_MAX];
        int inner_len;
        if (!sig_hex) goto fail;
        mqc_to_hex(sig, (int)sig_sz, sig_hex);
        inner_len = snprintf(inner, sizeof(inner),
            "{\"cert_index\":%d,\"signature\":\"%s\"}",
            ctx->our_cert_index, sig_hex);
        free(sig_hex);
        if (inner_len <= 0 || inner_len >= (int)sizeof(inner)) goto fail;

        if (mqc_enc_send(fd, early_s2c_key, early_s2c_iv,
                         &early_s2c_seq,
                         MQC_DIR_S2C, MQC_FRAME_TYPE_PHASE2_IDENTITY,
                         inner, inner_len) != 0) goto fail;
    }
    MQC_TRACE("[mqc-enc] sent phase-2 server identity (cert_index=%d)\n",
              ctx->our_cert_index);

    /* ---- Full-transcript KDF + data key schedule ------------- */
    ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_ENCRYPTED,
        encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
        peer_index, ctx->our_cert_index);
    if (ret != 0) goto fail;
    ret = mqc_derive_data_keys(shared_secret, th_kdf,
                               c2s_key, s2c_key, c2s_iv, s2c_iv,
                               c2s_finished, s2c_finished);
    if (ret != 0) goto fail;

    conn = calloc(1, sizeof(*conn));
    if (!conn) goto fail;
    conn->fd = fd;
    /* Server: send-direction is S2C, receive-direction is C2S. */
    memcpy(conn->send_key, s2c_key, MQC_AES_KEY_SZ);
    memcpy(conn->recv_key, c2s_key, MQC_AES_KEY_SZ);
    memcpy(conn->send_iv,  s2c_iv,  MQC_GCM_IV_SZ);
    memcpy(conn->recv_iv,  c2s_iv,  MQC_GCM_IV_SZ);
    memcpy(conn->send_finished_key, s2c_finished, MQC_FINISHED_MAC_SZ);
    memcpy(conn->recv_finished_key, c2s_finished, MQC_FINISHED_MAC_SZ);
    memcpy(conn->transcript_hash_full, th_kdf, WC_SHA256_DIGEST_SIZE);
    conn->peer_index = peer_index;
    {
        char subj[256];
        if (mqc_peer_get_cached_subject(peer_index, subj,
                                        sizeof(subj)) == 0)
            conn->peer_subject = strdup(subj);
    }
    conn->is_client = 0;
    conn->send_seq = 0;
    conn->recv_seq = 0;
    conn->finished_verified = 0;

    if (mqc_recv_finished(conn) != 0) {
        MQC_SECURITY("FINISHED_VERIFY_FAILED: client Finished MAC invalid");
        goto fail;
    }
    if (mqc_send_finished(conn) != 0) goto fail;
    MQC_TRACE("[mqc-enc] session established with peer %d (Finished verified)\n",
              peer_index);

    mqc_clear_socket_timeout(fd);
    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(early_c2s_key, sizeof(early_c2s_key));
    mqc_secure_zero(early_s2c_key, sizeof(early_s2c_key));
    mqc_secure_zero(early_c2s_iv,  sizeof(early_c2s_iv));
    mqc_secure_zero(early_s2c_iv,  sizeof(early_s2c_iv));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_phase1, sizeof(th_phase1));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    mqc_ratelimit_fail_record(client_ip);
    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(early_c2s_key, sizeof(early_c2s_key));
    mqc_secure_zero(early_s2c_key, sizeof(early_s2c_key));
    mqc_secure_zero(early_c2s_iv,  sizeof(early_c2s_iv));
    mqc_secure_zero(early_s2c_iv,  sizeof(early_s2c_iv));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_phase1, sizeof(th_phase1));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn->peer_subject); free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

/* Public API: callers with an explicit encrypted-mode commitment
 * (cfg.encrypt_identity == 1) call this directly, bypassing the
 * mqc_accept_auto mode-dispatch.  Drives accept + prologue + slow-
 * loris deadline + first-frame read itself, then hands off to
 * mqc_accept_encrypted_continue. */
mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd)
{
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char client_ip[64] = "unknown";
    char first_frame[64000];
    int  first_frame_len;
    int  fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;
    inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
    MQC_LOG("accepted encrypted-mode connection from %s:%d",
            client_ip, ntohs(cli_addr.sin_port));

    if (mqc_accept_prologue(fd, client_ip) != 0) {
        close(fd); return NULL;
    }

    HANDSHAKE_DEADLINE_ACTIVE();

    first_frame_len = mqc_read_handshake_frame(fd, first_frame,
                                               sizeof(first_frame));
    if (first_frame_len <= 0) {
        MQC_SECURITY("encrypted-mode first-frame read failed (fd=%d)", fd);
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }
    return mqc_accept_encrypted_continue(ctx, fd, client_ip,
                                         first_frame, first_frame_len);
}
