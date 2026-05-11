/******************************************************************************
 * File:        mqc_clear.c
 * Purpose:     Clear-identity-mode handshake bodies for MQC.
 *
 * Description:
 *   The 2-frame clear-identity handshake (spec §6).  Both peers'
 *   `cert_index` is sent in the plaintext handshake JSON; passive
 *   observers can read who is talking to whom but cannot read the
 *   conversation.  This is the default mode.
 *
 *   Public API: mqc_connect / mqc_accept in mqc.c dispatch here when
 *   ctx->encrypt_identity == 0.
 *
 *   All shared machinery (transcript hash, key schedule, AEAD seal,
 *   Finished frame, JSON parsers, rate limits) lives in mqc_common.c
 *   and is reached via mqc_internal.h prototypes.
 *
 * Created:     2026-05-03  (split out of mqc.c during Phase 7 commit 1)
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

/* --- Handshake (clear-identity mode) --- */

mqc_conn_t *mqc_connect_clear(mqc_ctx_t *ctx, const char *host, int port)
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
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_sign[WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

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
            MQC_TRACE("[mqc] TCP connect to %s:%d failed\n", host, port);
            return NULL;
        }
    }

    MQC_TRACE("[mqc] connected to %s:%d\n", host, port);

    if (wc_InitRng(&rng) != 0) goto fail;
    rng_ok = 1;

    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM init: %d\n", ret); goto fail; }
    mlkem_ok = 1;
    ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM keygen: %d\n", ret); goto fail; }
    wc_MlKemKey_PublicKeySize(&mlkem, &encaps_key_sz);
    if (encaps_key_sz != MQC_MLKEM768_PUB_SZ) {
        fprintf(stderr, "[mqc] ML-KEM pub size %u != %u\n",
                encaps_key_sz, MQC_MLKEM768_PUB_SZ);
        goto fail;
    }
    ret = wc_MlKemKey_EncodePublicKey(&mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM encode pub: %d\n", ret); goto fail; }

    /* Sign client transcript (C_s=0; client doesn't yet know server's index). */
    ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
        encaps_key, encaps_key_sz, NULL, 0,
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
    if (ret != 0) { fprintf(stderr, "[mqc] DSA import: %d\n", ret); goto fail; }

    ret = wc_dilithium_sign_ctx_msg(
        (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
        th_sign, WC_SHA256_DIGEST_SIZE,
        sig, &sig_sz, &dil, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] DSA sign: %d\n", ret); goto fail; }

    {
        char *ek_hex  = malloc(encaps_key_sz * 2 + 1);
        char *sig_hex = malloc(sig_sz * 2 + 1);
        int json_len;
        if (!ek_hex || !sig_hex) { free(ek_hex); free(sig_hex); goto fail; }
        mqc_to_hex(encaps_key, (int)encaps_key_sz, ek_hex);
        mqc_to_hex(sig,        (int)sig_sz,        sig_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"clear\","
            "\"kem_pub\":\"%s\",\"cert_index\":%d,\"signature\":\"%s\"}",
            MQC_PROTOCOL_VERSION, MQC_SUITE_STRING,
            ek_hex, ctx->our_cert_index, sig_hex);
        free(ek_hex); free(sig_hex);
        if (mqc_write_handshake_frame(fd, json_buf, (unsigned int)json_len) != 0)
            goto fail;
    }

    MQC_TRACE("[mqc] sent ClientHello (cert_index=%d)\n", ctx->our_cert_index);

    ret = mqc_read_handshake_frame(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;

    {
        struct json_object *resp = NULL;
        uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
        int ct_sz = MQC_MLKEM768_CT_SZ;
        uint8_t resp_sig[MQC_MLDSA87_SIG_SZ];
        int resp_sig_sz = MQC_MLDSA87_SIG_SZ;
        int peer_index = -1;
        int dummy_version;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;
        static const char *const hello_fields[] = {
            "version", "suite", "mode", "kem_pub", "cert_index", "signature"
        };

        resp = mqc_json_parse_strict("ServerHello", json_buf, ret);
        if (!resp) goto fail;
        if (mqc_json_no_duplicates("ServerHello", json_buf, ret,
                hello_fields,
                (int)(sizeof(hello_fields)/sizeof(hello_fields[0]))) != 0 ||
            mqc_json_no_unknown_keys("ServerHello", resp,
                hello_fields,
                (int)(sizeof(hello_fields)/sizeof(hello_fields[0]))) != 0 ||
            mqc_json_get_int_strict("ServerHello", resp, "version",
                MQC_PROTOCOL_VERSION, MQC_PROTOCOL_VERSION,
                &dummy_version) != 0 ||
            mqc_json_get_string_exact("ServerHello", resp, "suite",
                MQC_SUITE_STRING) != 0 ||
            mqc_json_get_string_exact("ServerHello", resp, "mode",
                "clear") != 0 ||
            mqc_json_get_int_strict("ServerHello", resp, "cert_index",
                0, INT_MAX, &peer_index) != 0 ||
            mqc_json_get_hex_strict("ServerHello", resp, "kem_pub",
                MQC_MLKEM768_CT_SZ, ciphertext) != 0 ||
            mqc_json_get_hex_strict("ServerHello", resp, "signature",
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

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
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
                MQC_SECURITY("SIG_VERIFY_FAILED: server signature invalid");
                goto fail;
            }
        }

        MQC_TRACE("[mqc] peer %d verified + signature OK\n", peer_index);

        /* Issue #9: expected-identity check.  We've cryptographically
         * proven the peer holds the private key for cert at peer_index;
         * confirm that cert names the identity we *intended* to talk to.
         * Defends against a verified-but-unexpected peer (a compromised
         * sibling identity in the same log, or a wrong-but-valid index
         * supplied by a hostile resolver).  Resolution order:
         *   1. ctx->expected_name == ""  → check explicitly disabled
         *      (mqc_ctx_disable_name_check; opt-out for callers that
         *      have an out-of-band reason to trust the peer index).
         *   2. ctx->expected_name set    → use that string verbatim
         *      (mqc_ctx_set_expected_name; required when dialing by IP).
         *   3. ctx->expected_name == NULL→ derive from `host`, but
         *      fail closed if `host` is an IP literal — an IP names a
         *      location, not an MTC subject. */
        {
            char subject[256];
            const char *expected = ctx->expected_name;
            int do_check = 1;

            if (expected && expected[0] == '\0') {
                do_check = 0;
            } else if (!expected) {
                if (mqc_is_ip_literal(host)) {
                    MQC_SECURITY("NAME_CHECK_FAILED: dialed IP literal "
                        "'%s' with no expected name; call "
                        "mqc_ctx_set_expected_name() or "
                        "mqc_ctx_disable_name_check()", host);
                    goto fail;
                }
                expected = host;
            }

            if (do_check) {
                if (mqc_peer_get_cached_subject(peer_index, subject,
                                                sizeof(subject)) != 0) {
                    MQC_SECURITY("NAME_CHECK_FAILED: no cached subject "
                        "for verified cert %d", peer_index);
                    goto fail;
                }
                if (!mqc_cert_name_matches(subject, expected)) {
                    MQC_SECURITY("NAME_CHECK_FAILED: cert subject '%s' "
                        "does not match expected '%s'", subject, expected);
                    goto fail;
                }
                MQC_TRACE("[mqc] subject '%s' matches expected '%s'\n",
                          subject, expected);
            }
        }

        ret = wc_MlKemKey_Decapsulate(&mlkem, shared_secret,
            ciphertext, (word32)ct_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM decapsulate: %d\n", ret);
            goto fail;
        }

        ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_CLEAR,
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

        MQC_TRACE("[mqc] session established with peer %d (Finished verified)\n",
                  peer_index);
    }

    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    MQC_TRACE("[mqc] connect to %s:%d failed (handshake)\n", host, port);
    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn->peer_subject); free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

/* Continuation: the prologue (abuse / RL / RL_fail / socket
 * timeout), HANDSHAKE_DEADLINE_ACTIVE, and the FIRST handshake
 * frame have all been done by the caller.  We own the fd from
 * here, parse the pre-read frame as the ClientHello, run the rest
 * of the handshake, and close fd on any failure.  See
 * mqc_internal.h for the full contract.
 *
 * Direct callers: mqc_accept_clear (this file) drives prologue +
 * first read itself before calling here.  mqc_accept_auto in mqc.c
 * does the same, plus a length-prefixed peek of the JSON body's
 * `mode` field to dispatch encrypted-vs-clear. */
mqc_conn_t *mqc_accept_clear_continue(mqc_ctx_t *ctx, int fd,
                                       const char *client_ip,
                                       const char *first_frame,
                                       int first_frame_len)
{
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t ciphertext[MQC_MLKEM768_CT_SZ];
    word32 ct_sz;
    uint8_t sig[MQC_MLDSA87_SIG_SZ];
    word32 sig_sz = sizeof(sig);
    uint8_t c2s_key[MQC_AES_KEY_SZ], s2c_key[MQC_AES_KEY_SZ];
    uint8_t c2s_iv[MQC_GCM_IV_SZ],   s2c_iv[MQC_GCM_IV_SZ];
    uint8_t c2s_finished[MQC_FINISHED_MAC_SZ];
    uint8_t s2c_finished[MQC_FINISHED_MAC_SZ];
    uint8_t th_sign[WC_SHA256_DIGEST_SIZE];
    uint8_t th_kdf [WC_SHA256_DIGEST_SIZE];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

    /* RNG init runs here (post-prologue, post-first-frame-read).
     * It is cheap (microseconds in the warm case) and the RNG isn't
     * used until ML-KEM encapsulate / ML-DSA sign later in the
     * function.  Kept inside MQC_TIME_BEGIN/END to preserve the
     * cold-start diagnostic that landed in Phase 2a. */
    MQC_TIME_BEGIN(rng);
    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    MQC_TIME_END(rng);
    rng_ok = 1;

    /* The first frame was read by the caller; copy into json_buf so
     * the existing parse path is unchanged.  Length is bounded by
     * mqc_read_handshake_frame's max_handshake_bytes ceiling +
     * sizeof(json_buf), so the bounds check is a belt-and-braces
     * sanity rather than a security gate. */
    if (first_frame_len <= 0 ||
        first_frame_len > (int)sizeof(json_buf) - 1) {
        MQC_SECURITY("clear continuation: invalid first_frame_len=%d",
                     first_frame_len);
        goto fail;
    }
    memcpy(json_buf, first_frame, (size_t)first_frame_len);
    json_buf[first_frame_len] = '\0';
    ret = first_frame_len;

    {
        struct json_object *req = NULL;
        uint8_t encaps_key[MQC_MLKEM768_PUB_SZ];
        int ek_sz = MQC_MLKEM768_PUB_SZ;
        uint8_t req_sig[MQC_MLDSA87_SIG_SZ];
        int req_sig_sz = MQC_MLDSA87_SIG_SZ;
        int peer_index = -1;
        int dummy_version;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;
        static const char *const hello_fields[] = {
            "version", "suite", "mode", "kem_pub", "cert_index", "signature"
        };

        req = mqc_json_parse_strict("ClientHello", json_buf, ret);
        if (!req) goto fail;
        if (mqc_json_no_duplicates("ClientHello", json_buf, ret,
                hello_fields,
                (int)(sizeof(hello_fields)/sizeof(hello_fields[0]))) != 0 ||
            mqc_json_no_unknown_keys("ClientHello", req,
                hello_fields,
                (int)(sizeof(hello_fields)/sizeof(hello_fields[0]))) != 0 ||
            mqc_json_get_int_strict("ClientHello", req, "version",
                MQC_PROTOCOL_VERSION, MQC_PROTOCOL_VERSION,
                &dummy_version) != 0 ||
            mqc_json_get_string_exact("ClientHello", req, "suite",
                MQC_SUITE_STRING) != 0 ||
            mqc_json_get_string_exact("ClientHello", req, "mode",
                "clear") != 0 ||
            mqc_json_get_int_strict("ClientHello", req, "cert_index",
                0, INT_MAX, &peer_index) != 0 ||
            mqc_json_get_hex_strict("ClientHello", req, "kem_pub",
                MQC_MLKEM768_PUB_SZ, encaps_key) != 0 ||
            mqc_json_get_hex_strict("ClientHello", req, "signature",
                MQC_MLDSA87_SIG_SZ, req_sig) != 0) {
            json_object_put(req);
            goto fail;
        }
        json_object_put(req);

        /* Issue #12: per-(IP, cert_index) throttle.  An attacker
         * inside the per-IP budget that rotates cert_index every
         * connect would force a fresh cert fetch + cosignature
         * verify per handshake.  Cap distinct cert_index values per
         * IP before that work runs. */
        if (mqc_ratelimit_cert_check(client_ip, peer_index) != 0)
            goto fail;

        MQC_TIME_BEGIN(peer_verify);
        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, mqc_rt_cfg()->revocation_policy,
                              &peer_pubkey, &peer_pubkey_sz);
        MQC_TIME_END(peer_verify);
        if (ret != 0) {
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d", peer_index);
            goto fail;
        }

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
            encaps_key, (size_t)ek_sz, NULL, 0,
            peer_index, 0, MQC_ROLE_CLIENT);
        if (ret != 0) { free(peer_pubkey); goto fail; }

        MQC_TIME_BEGIN(verify_sig);
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
                MQC_SECURITY("SIG_VERIFY_FAILED: client signature invalid");
                goto fail;
            }
        }
        MQC_TIME_END(verify_sig);

        MQC_TRACE("[mqc] peer %d verified + signature OK\n", peer_index);

        MQC_TIME_BEGIN(encapsulate);
        ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
        if (ret != 0) goto fail;
        mlkem_ok = 1;
        ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key, (word32)ek_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM decode pub: %d\n", ret);
            goto fail;
        }
        ct_sz = sizeof(ciphertext);
        wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
        if (ct_sz != MQC_MLKEM768_CT_SZ) {
            fprintf(stderr, "[mqc] ML-KEM ct size %u != %u\n",
                    ct_sz, MQC_MLKEM768_CT_SZ);
            goto fail;
        }
        ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM encapsulate: %d\n", ret);
            goto fail;
        }
        MQC_TIME_END(encapsulate);

        ret = mqc_compute_transcript_hash(th_sign, MQC_MODE_CLEAR,
            encaps_key, (size_t)ek_sz, ciphertext, (size_t)ct_sz,
            peer_index, ctx->our_cert_index, MQC_ROLE_SERVER);
        if (ret != 0) goto fail;

        MQC_TIME_BEGIN(server_sign);
        wc_dilithium_init(&dil);
        dil_ok = 1;
        wc_dilithium_set_level(&dil, WC_ML_DSA_87);
        {
            word32 dil_idx2 = 0;
            ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx2,
                &dil, (word32)ctx->privkey_der_sz);
        }
        if (ret != 0) { fprintf(stderr, "[mqc] server DSA import: %d\n", ret); goto fail; }

        ret = wc_dilithium_sign_ctx_msg(
            (const byte *)MQC_HANDSHAKE_LABEL, MQC_HANDSHAKE_LABEL_LEN,
            th_sign, WC_SHA256_DIGEST_SIZE,
            sig, &sig_sz, &dil, &rng);
        if (ret != 0) goto fail;
        MQC_TIME_END(server_sign);

        MQC_TIME_BEGIN(server_send);
        {
            char *ct_hex_str  = malloc(ct_sz * 2 + 1);
            char *sig_hex_str = malloc(sig_sz * 2 + 1);
            int json_len;
            if (!ct_hex_str || !sig_hex_str) {
                free(ct_hex_str); free(sig_hex_str); goto fail;
            }
            mqc_to_hex(ciphertext, (int)ct_sz, ct_hex_str);
            mqc_to_hex(sig,        (int)sig_sz, sig_hex_str);
            json_len = snprintf(json_buf, sizeof(json_buf),
                "{\"version\":%d,\"suite\":\"%s\",\"mode\":\"clear\","
                "\"kem_pub\":\"%s\",\"cert_index\":%d,\"signature\":\"%s\"}",
                MQC_PROTOCOL_VERSION, MQC_SUITE_STRING,
                ct_hex_str, ctx->our_cert_index, sig_hex_str);
            free(ct_hex_str); free(sig_hex_str);
            if (mqc_write_handshake_frame(fd, json_buf, (unsigned int)json_len) != 0)
                goto fail;
        }
        MQC_TIME_END(server_send);

        ret = mqc_transcript_hash_kdf(th_kdf, MQC_MODE_CLEAR,
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

        MQC_TIME_BEGIN(recv_finished);
        if (mqc_recv_finished(conn) != 0) {
            MQC_TIME_END(recv_finished);
            goto fail;
        }
        MQC_TIME_END(recv_finished);
        MQC_TIME_BEGIN(send_finished);
        if (mqc_send_finished(conn) != 0) goto fail;
        MQC_TIME_END(send_finished);

        mqc_clear_socket_timeout(fd);
        MQC_TRACE("[mqc] session established with peer %d (Finished verified)\n",
                  peer_index);
    }

    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    mqc_ratelimit_fail_record(client_ip);
    mqc_secure_zero(shared_secret, sizeof(shared_secret));
    mqc_secure_zero(c2s_key, sizeof(c2s_key));
    mqc_secure_zero(s2c_key, sizeof(s2c_key));
    mqc_secure_zero(c2s_iv,  sizeof(c2s_iv));
    mqc_secure_zero(s2c_iv,  sizeof(s2c_iv));
    mqc_secure_zero(c2s_finished, sizeof(c2s_finished));
    mqc_secure_zero(s2c_finished, sizeof(s2c_finished));
    mqc_secure_zero(th_sign, sizeof(th_sign));
    mqc_secure_zero(th_kdf,  sizeof(th_kdf));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (conn) { free(conn->peer_subject); free(conn); conn = NULL; }
    if (fd >= 0) close(fd);
    return NULL;
}

/* Public API: callers with an explicit clear-mode commitment
 * (cfg.encrypt_identity == 0) call this directly, bypassing the
 * mqc_accept_auto mode-dispatch.  Drives accept + prologue + slow-
 * loris deadline + first-frame read itself, then hands off to
 * mqc_accept_clear_continue.
 *
 * Note: mqc_accept_auto in mqc.c does the same flow but with the
 * additional length-prefixed JSON parse + `mode` peek before the
 * dispatch.  Both paths converge on the same continuation. */
mqc_conn_t *mqc_accept_clear(mqc_ctx_t *ctx, int listen_fd)
{
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char client_ip[64] = "unknown";
    char first_frame[64000];
    int  first_frame_len;
    int  fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;
    inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
    MQC_LOG("accepted connection from %s:%d",
            client_ip, ntohs(cli_addr.sin_port));

    if (mqc_accept_prologue(fd, client_ip) != 0) {
        close(fd); return NULL;
    }

    HANDSHAKE_DEADLINE_ACTIVE();

    first_frame_len = mqc_read_handshake_frame(fd, first_frame,
                                               sizeof(first_frame));
    if (first_frame_len <= 0) {
        MQC_SECURITY("clear-mode first-frame read failed (fd=%d)", fd);
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }
    return mqc_accept_clear_continue(ctx, fd, client_ip,
                                     first_frame, first_frame_len);
}
