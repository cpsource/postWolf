/******************************************************************************
 * File:        mqc.c
 * Purpose:     MQC (Merkle Quantum Connect) protocol implementation.
 *
 * Description:
 *   Post-quantum authenticated encrypted connections using ML-KEM-768
 *   key exchange, ML-DSA-87 signed authentication, and AES-256-GCM
 *   session encryption. Peer identity verified via Merkle transparency log.
 *
 *   Protocol: 1 round trip.
 *     Client -> Server: {cert_index, mlkem_encaps_key, signature}
 *     Server -> Client: {cert_index, mlkem_ciphertext, signature}
 *     Both derive AES-256-GCM key from ML-KEM shared secret.
 *
 * Dependencies:
 *   wolfSSL crypto (ML-KEM, ML-DSA, AES-GCM, HKDF, SHA-256)
 *   json-c          (JSON serialization)
 *   POSIX sockets   (TCP)
 *
 * Created:     2026-04-15
 ******************************************************************************/

#include "mqc.h"
#include "mqc_peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <json-c/json.h>

#define MQC_HKDF_INFO      "mqc-session"
#define MQC_AES_KEY_SZ      32
#define MQC_GCM_IV_SZ       12
#define MQC_GCM_TAG_SZ      16
#define MQC_MAX_MSG          (1024 * 1024)  /* 1MB max message */

/* --- Internal structures --- */

struct mqc_ctx {
    mqc_role_t   role;
    char        *tpm_path;
    int          our_cert_index;
    char        *mtc_server;
    uint8_t     *ca_pubkey;
    int          ca_pubkey_sz;
    uint8_t     *privkey_der;      /* ML-DSA-87 private key DER */
    int          privkey_der_sz;
    int          encrypt_identity; /* 1 = encrypt cert_index in handshake */
};

struct mqc_conn {
    int          fd;
    uint8_t      aes_key[MQC_AES_KEY_SZ];
    uint64_t     send_seq;
    uint64_t     recv_seq;
    int          peer_index;
};

/* --- Helpers --- */

static void secure_zero(void *buf, unsigned int len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    unsigned int i;
    for (i = 0; i < len; i++)
        p[i] = 0;
}

static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

static int hex_to_bytes(const char *hex, uint8_t *out, int out_sz)
{
    int len = (int)strlen(hex);
    int i;
    if (len % 2 != 0 || len / 2 > out_sz)
        return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1)
            return -1;
        out[i] = (uint8_t)b;
    }
    return len / 2;
}

static int write_all(int fd, const unsigned char *buf, unsigned int len)
{
    unsigned int sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += (unsigned int)n;
    }
    return 0;
}

static int read_all(int fd, unsigned char *buf, unsigned int len)
{
    unsigned int got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (unsigned int)n;
    }
    return 0;
}

static int read_json_block(int fd, char *buf, int bufsz)
{
    int pos = 0, depth = 0, started = 0;
    while (pos < bufsz - 1) {
        ssize_t n = read(fd, buf + pos, 1);
        if (n <= 0) return -1;
        if (buf[pos] == '{') { depth++; started = 1; }
        else if (buf[pos] == '}') { depth--; }
        pos++;
        if (started && depth == 0) {
            buf[pos] = '\0';
            return pos;
        }
    }
    return -1;
}

static int read_file_bytes(const char *path, uint8_t **out, int *out_sz)
{
    FILE *f;
    long sz;
    uint8_t *buf;

    f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    *out_sz = (int)sz;
    return 0;
}

/* Build GCM nonce from sequence number */
static void make_nonce(uint64_t seq, uint8_t nonce[MQC_GCM_IV_SZ])
{
    memset(nonce, 0, MQC_GCM_IV_SZ);
    /* Big-endian sequence in last 8 bytes */
    nonce[4]  = (uint8_t)(seq >> 56);
    nonce[5]  = (uint8_t)(seq >> 48);
    nonce[6]  = (uint8_t)(seq >> 40);
    nonce[7]  = (uint8_t)(seq >> 32);
    nonce[8]  = (uint8_t)(seq >> 24);
    nonce[9]  = (uint8_t)(seq >> 16);
    nonce[10] = (uint8_t)(seq >> 8);
    nonce[11] = (uint8_t)(seq);
}

/* --- Context --- */

mqc_ctx_t *mqc_ctx_new(const mqc_cfg_t *cfg)
{
    mqc_ctx_t *ctx;
    char path[512];

    if (!cfg || !cfg->tpm_path || !cfg->mtc_server ||
        !cfg->ca_pubkey || cfg->ca_pubkey_sz <= 0)
        return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->role = cfg->role;
    ctx->tpm_path = strdup(cfg->tpm_path);
    ctx->mtc_server = strdup(cfg->mtc_server);
    ctx->ca_pubkey = malloc((size_t)cfg->ca_pubkey_sz);
    if (!ctx->tpm_path || !ctx->mtc_server || !ctx->ca_pubkey) {
        mqc_ctx_free(ctx);
        return NULL;
    }
    memcpy(ctx->ca_pubkey, cfg->ca_pubkey, (size_t)cfg->ca_pubkey_sz);
    ctx->ca_pubkey_sz = cfg->ca_pubkey_sz;
    ctx->encrypt_identity = cfg->encrypt_identity;

    /* Load our cert_index from certificate.json */
    snprintf(path, sizeof(path), "%s/certificate.json", cfg->tpm_path);
    {
        uint8_t *json_buf;
        int json_sz;
        if (read_file_bytes(path, &json_buf, &json_sz) != 0) {
            fprintf(stderr, "[mqc] cannot read %s\n", path);
            mqc_ctx_free(ctx);
            return NULL;
        }
        {
            struct json_object *obj = json_tokener_parse((char *)json_buf);
            struct json_object *val;
            free(json_buf);
            if (!obj) {
                fprintf(stderr, "[mqc] invalid JSON in %s\n", path);
                mqc_ctx_free(ctx);
                return NULL;
            }
            if (json_object_object_get_ex(obj, "index", &val))
                ctx->our_cert_index = json_object_get_int(val);
            else {
                struct json_object *sc;
                if (json_object_object_get_ex(obj, "standalone_certificate", &sc) &&
                    json_object_object_get_ex(sc, "index", &val))
                    ctx->our_cert_index = json_object_get_int(val);
            }
            json_object_put(obj);
        }
    }

    /* Load our ML-DSA-87 private key PEM -> DER */
    snprintf(path, sizeof(path), "%s/private_key.pem", cfg->tpm_path);
    {
        uint8_t *pem;
        int pem_sz;
        uint8_t der[8192];
        int der_sz;

        if (read_file_bytes(path, &pem, &pem_sz) != 0) {
            fprintf(stderr, "[mqc] cannot read %s\n", path);
            mqc_ctx_free(ctx);
            return NULL;
        }

        der_sz = wc_KeyPemToDer(pem, pem_sz, der, (int)sizeof(der), NULL);
        free(pem);
        if (der_sz <= 0) {
            fprintf(stderr, "[mqc] PEM to DER failed: %d\n", der_sz);
            mqc_ctx_free(ctx);
            return NULL;
        }

        /* Store the full DER. We'll try multiple import strategies. */
        ctx->privkey_der = malloc((size_t)der_sz);
        if (!ctx->privkey_der) {
            mqc_ctx_free(ctx);
            return NULL;
        }
        memcpy(ctx->privkey_der, der, (size_t)der_sz);
        ctx->privkey_der_sz = der_sz;
        secure_zero(der, (unsigned int)der_sz);
    }

    fprintf(stderr, "[mqc] context ready: cert_index=%d role=%s\n",
            ctx->our_cert_index,
            ctx->role == MQC_CLIENT ? "client" : "server");

    return ctx;
}

void mqc_ctx_free(mqc_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->tpm_path);
    free(ctx->mtc_server);
    free(ctx->ca_pubkey);
    if (ctx->privkey_der) {
        secure_zero(ctx->privkey_der, (unsigned int)ctx->privkey_der_sz);
        free(ctx->privkey_der);
    }
    free(ctx);
}

/* --- Handshake --- */

mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)
{
    int fd = -1;
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t encaps_key[4096];
    word32 encaps_key_sz;
    uint8_t sig[8192];
    word32 sig_sz = sizeof(sig);
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t aes_key[MQC_AES_KEY_SZ];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

    /* TCP connect */
    {
        struct addrinfo hints, *res, *rp;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port_str, &hints, &res) != 0)
            return NULL;
        for (rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) return NULL;
    }

    fprintf(stderr, "[mqc] connected to %s:%d\n", host, port);

    /* Init crypto */
    if (wc_InitRng(&rng) != 0) goto fail;
    rng_ok = 1;

    /* Generate ephemeral ML-KEM-768 keypair */
    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM init: %d\n", ret); goto fail; }
    mlkem_ok = 1;

    ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM keygen: %d\n", ret); goto fail; }

    wc_MlKemKey_PublicKeySize(&mlkem, &encaps_key_sz);
    if (encaps_key_sz > sizeof(encaps_key)) {
        fprintf(stderr, "[mqc] ML-KEM pub key too large: %u\n", encaps_key_sz);
        goto fail;
    }
    ret = wc_MlKemKey_EncodePublicKey(&mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) { fprintf(stderr, "[mqc] ML-KEM encode pub: %d\n", ret); goto fail; }

    /* Sign encaps key with our ML-DSA-87 key */
    wc_dilithium_init(&dil);
    dil_ok = 1;
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    {
        word32 dil_idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx,
            &dil, (word32)ctx->privkey_der_sz);
    }
    if (ret != 0) { fprintf(stderr, "[mqc] DSA import: %d\n", ret); goto fail; }

    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
        encaps_key, encaps_key_sz, sig, &sig_sz, &dil, &rng);
    if (ret != 0) { fprintf(stderr, "[mqc] DSA sign: %d\n", ret); goto fail; }

    /* Build and send JSON */
    {
        char *ek_hex = malloc(encaps_key_sz * 2 + 1);
        char *sig_hex = malloc(sig_sz * 2 + 1);
        int json_len;

        to_hex(encaps_key, (int)encaps_key_sz, ek_hex);
        to_hex(sig, (int)sig_sz, sig_hex);

        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"cert_index\":%d,\"mlkem_encaps_key\":\"%s\",\"signature\":\"%s\"}",
            ctx->our_cert_index, ek_hex, sig_hex);

        free(ek_hex);
        free(sig_hex);

        if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0)
            goto fail;
    }

    fprintf(stderr, "[mqc] sent handshake (cert_index=%d)\n", ctx->our_cert_index);

    /* Receive server response */
    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;

    /* Parse response */
    {
        struct json_object *resp, *val;
        const char *ct_hex, *resp_sig_hex;
        uint8_t ciphertext[4096];
        int ct_sz;
        uint8_t resp_sig[8192];
        int resp_sig_sz;
        int peer_index;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;

        resp = json_tokener_parse(json_buf);
        if (!resp) goto fail;

        if (!json_object_object_get_ex(resp, "cert_index", &val)) {
            json_object_put(resp); goto fail;
        }
        peer_index = json_object_get_int(val);

        if (!json_object_object_get_ex(resp, "mlkem_ciphertext", &val)) {
            json_object_put(resp); goto fail;
        }
        ct_hex = json_object_get_string(val);
        ct_sz = hex_to_bytes(ct_hex, ciphertext, sizeof(ciphertext));

        if (!json_object_object_get_ex(resp, "signature", &val)) {
            json_object_put(resp); goto fail;
        }
        resp_sig_hex = json_object_get_string(val);
        resp_sig_sz = hex_to_bytes(resp_sig_hex, resp_sig, sizeof(resp_sig));

        json_object_put(resp);

        if (ct_sz <= 0 || resp_sig_sz <= 0) goto fail;

        /* Verify peer */
        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] peer verification failed for index %d\n",
                    peer_index);
            goto fail;
        }

        /* Verify server's signature over ciphertext */
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
                ret = wc_dilithium_verify_ctx_msg(resp_sig, (word32)resp_sig_sz,
                    NULL, 0, ciphertext, (word32)ct_sz, &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);

            if (ret != 0 || !verified) {
                fprintf(stderr, "[mqc] server signature verification failed\n");
                goto fail;
            }
        }

        fprintf(stderr, "[mqc] peer %d verified + signature OK\n", peer_index);

        /* Decapsulate */
        ret = wc_MlKemKey_Decapsulate(&mlkem, shared_secret,
            ciphertext, (word32)ct_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM decapsulate: %d\n", ret);
            goto fail;
        }

        /* Derive session key */
        ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ,
            NULL, 0, (const byte *)MQC_HKDF_INFO,
            (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
        if (ret != 0) goto fail;

        /* Build connection */
        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
        conn->peer_index = peer_index;
        conn->send_seq = 0;
        conn->recv_seq = 0;

        fprintf(stderr, "[mqc] session established with peer %d\n", peer_index);
    }

    /* Cleanup */
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    if (fd >= 0 && !conn) close(fd);
    return NULL;
}

mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd)
{
    int fd;
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    MlKemKey mlkem;
    dilithium_key dil;
    WC_RNG rng;
    uint8_t shared_secret[WC_ML_KEM_SS_SZ];
    uint8_t ciphertext[4096];
    word32 ct_sz;
    uint8_t sig[8192];
    word32 sig_sz = sizeof(sig);
    uint8_t aes_key[MQC_AES_KEY_SZ];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;

    fprintf(stderr, "[mqc] accepted connection\n");

    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    rng_ok = 1;

    /* Receive client's handshake */
    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;

    {
        struct json_object *req, *val;
        const char *ek_hex, *req_sig_hex;
        uint8_t encaps_key[4096];
        int ek_sz;
        uint8_t req_sig[8192];
        int req_sig_sz;
        int peer_index;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;

        req = json_tokener_parse(json_buf);
        if (!req) goto fail;

        if (!json_object_object_get_ex(req, "cert_index", &val)) {
            json_object_put(req); goto fail;
        }
        peer_index = json_object_get_int(val);

        if (!json_object_object_get_ex(req, "mlkem_encaps_key", &val)) {
            json_object_put(req); goto fail;
        }
        ek_hex = json_object_get_string(val);
        ek_sz = hex_to_bytes(ek_hex, encaps_key, sizeof(encaps_key));

        if (!json_object_object_get_ex(req, "signature", &val)) {
            json_object_put(req); goto fail;
        }
        req_sig_hex = json_object_get_string(val);
        req_sig_sz = hex_to_bytes(req_sig_hex, req_sig, sizeof(req_sig));

        json_object_put(req);

        if (ek_sz <= 0 || req_sig_sz <= 0) goto fail;

        /* Verify peer */
        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) {
            fprintf(stderr, "[mqc] peer verification failed for index %d\n",
                    peer_index);
            goto fail;
        }

        /* Verify client's signature over encaps_key */
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
                ret = wc_dilithium_verify_ctx_msg(req_sig, (word32)req_sig_sz,
                    NULL, 0, encaps_key, (word32)ek_sz, &verified, &peer_dil);
            }
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);

            if (ret != 0 || !verified) {
                fprintf(stderr, "[mqc] client signature verification failed\n");
                goto fail;
            }
        }

        fprintf(stderr, "[mqc] peer %d verified + signature OK\n", peer_index);

        /* Import client's encaps key and encapsulate */
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
        ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
        if (ret != 0) {
            fprintf(stderr, "[mqc] ML-KEM encapsulate: %d\n", ret);
            goto fail;
        }

        /* Sign ciphertext with our ML-DSA-87 key */
        wc_dilithium_init(&dil);
        dil_ok = 1;
        wc_dilithium_set_level(&dil, WC_ML_DSA_87);
        {
            word32 dil_idx2 = 0;
            ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx2,
                &dil, (word32)ctx->privkey_der_sz);
        }
        if (ret != 0) { fprintf(stderr, "[mqc] server DSA import: %d\n", ret); goto fail; }

        ret = wc_dilithium_sign_ctx_msg(NULL, 0,
            ciphertext, ct_sz, sig, &sig_sz, &dil, &rng);
        if (ret != 0) goto fail;

        /* Send response */
        {
            char *ct_hex_str = malloc(ct_sz * 2 + 1);
            char *sig_hex_str = malloc(sig_sz * 2 + 1);
            int json_len;

            to_hex(ciphertext, (int)ct_sz, ct_hex_str);
            to_hex(sig, (int)sig_sz, sig_hex_str);

            json_len = snprintf(json_buf, sizeof(json_buf),
                "{\"cert_index\":%d,\"mlkem_ciphertext\":\"%s\",\"signature\":\"%s\"}",
                ctx->our_cert_index, ct_hex_str, sig_hex_str);

            free(ct_hex_str);
            free(sig_hex_str);

            if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0)
                goto fail;
        }

        /* Derive session key */
        ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ,
            NULL, 0, (const byte *)MQC_HKDF_INFO,
            (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
        if (ret != 0) goto fail;

        /* Build connection */
        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
        conn->peer_index = peer_index;
        conn->send_seq = 0;
        conn->recv_seq = 0;

        fprintf(stderr, "[mqc] session established with peer %d\n", peer_index);
    }

    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    return conn;

fail:
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
    if (dil_ok) wc_dilithium_free(&dil);
    if (rng_ok) wc_FreeRng(&rng);
    close(fd);
    return NULL;
}

/* --- I/O --- */

int mqc_write(mqc_conn_t *conn, const void *buf, int sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t *ct;
    uint32_t net_len;
    int ret;

    if (!conn || !buf || sz <= 0) return -1;

    ct = malloc((size_t)sz);
    if (!ct) return -1;

    make_nonce(conn->send_seq++, nonce);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }

    ret = wc_AesGcmSetKey(&aes, conn->aes_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }

    ret = wc_AesGcmEncrypt(&aes, ct, (const byte *)buf, (word32)sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);

    if (ret != 0) { free(ct); return -1; }

    /* Send: [4-byte len] [ciphertext] [tag] */
    net_len = htonl((uint32_t)(sz + MQC_GCM_TAG_SZ));
    if (write_all(conn->fd, (unsigned char *)&net_len, 4) != 0 ||
        write_all(conn->fd, ct, (unsigned int)sz) != 0 ||
        write_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct);
        return -1;
    }

    free(ct);
    return sz;
}

int mqc_read(mqc_conn_t *conn, void *buf, int sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint32_t net_len;
    uint32_t total_len;
    int ct_sz;
    uint8_t *ct;
    int ret;

    if (!conn || !buf || sz <= 0) return -1;

    /* Read length prefix */
    if (read_all(conn->fd, (unsigned char *)&net_len, 4) != 0)
        return 0;  /* connection closed */

    total_len = ntohl(net_len);
    if (total_len < MQC_GCM_TAG_SZ || total_len > MQC_MAX_MSG)
        return -1;

    ct_sz = (int)(total_len - MQC_GCM_TAG_SZ);
    if (ct_sz > sz) return -1;  /* buffer too small */

    ct = malloc((size_t)ct_sz);
    if (!ct) return -1;

    /* Read ciphertext + tag */
    if (read_all(conn->fd, ct, (unsigned int)ct_sz) != 0 ||
        read_all(conn->fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct);
        return -1;
    }

    make_nonce(conn->recv_seq++, nonce);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }

    ret = wc_AesGcmSetKey(&aes, conn->aes_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }

    ret = wc_AesGcmDecrypt(&aes, (byte *)buf, ct, (word32)ct_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);
    free(ct);

    if (ret != 0) return -1;

    return ct_sz;
}

int mqc_recv(mqc_conn_t *conn, void *buf, int sz)
{
    return mqc_read(conn, buf, sz);
}

int mqc_send(mqc_conn_t *conn, const void *buf, int sz)
{
    return mqc_write(conn, buf, sz);
}

/* --- Listen / Close / Utility --- */

int mqc_listen(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd, opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    if (host && strcmp(host, "0.0.0.0") != 0) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        if (getaddrinfo(host, NULL, &hints, &res) == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
            addr.sin_addr = sin->sin_addr;
            freeaddrinfo(res);
        }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, 5) < 0) {
        close(fd); return -1;
    }
    return fd;
}

void mqc_close(mqc_conn_t *conn)
{
    if (!conn) return;
    if (conn->fd >= 0) close(conn->fd);
    secure_zero(conn->aes_key, MQC_AES_KEY_SZ);
    free(conn);
}

int mqc_get_fd(mqc_conn_t *conn)
{
    return conn ? conn->fd : -1;
}

int mqc_get_peer_index(mqc_conn_t *conn)
{
    return conn ? conn->peer_index : -1;
}
