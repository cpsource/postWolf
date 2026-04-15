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

#include <curl/curl.h>
#include <json-c/json.h>

#define MQC_HKDF_INFO      "mqc-session"
#define MQC_AES_KEY_SZ      32
#define MQC_GCM_IV_SZ       12
#define MQC_GCM_TAG_SZ      16
#define MQC_MAX_MSG          (1024 * 1024)  /* 1MB max message */
#define MQC_MAX_HANDSHAKE    (128 * 1024)   /* 128KB max handshake JSON */
#define MQC_HANDSHAKE_TIMEOUT 10            /* seconds to complete handshake */

#define MQC_ABUSE_THRESHOLD  25  /* reject if abuse score >= 25% */

/* --- Logging --- */

#define MQC_LOG(fmt, ...) \
    fprintf(stderr, "[MQC %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MQC_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQC-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

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

/* --- Socket timeout --- */

static void set_socket_timeout(int fd, int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void clear_socket_timeout(int fd)
{
    struct timeval tv = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* --- AbuseIPDB check --- */

struct abuse_buf { char *data; size_t sz; };

static size_t abuse_write_cb(void *ptr, size_t size, size_t nmemb, void *ud)
{
    struct abuse_buf *b = (struct abuse_buf *)ud;
    size_t total = size * nmemb;
    char *tmp = realloc(b->data, b->sz + total + 1);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->sz, ptr, total);
    b->sz += total;
    b->data[b->sz] = '\0';
    return total;
}

/* Read ABUSEIPDB_TOKEN from environment or ~/.env. Returns NULL if not found. */
static const char *get_abuseipdb_token(void)
{
    static char token[256] = {0};
    const char *env;
    FILE *f;
    char line[512];
    char path[512];
    const char *home;

    if (token[0]) return token;

    env = getenv("ABUSEIPDB_TOKEN");
    if (env && *env) {
        snprintf(token, sizeof(token), "%s", env);
        return token;
    }

    home = getenv("HOME");
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/.env", home);

    f = fopen(path, "r");
    if (!f) return NULL;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ABUSEIPDB_TOKEN=", 16) == 0) {
            char *val = line + 16;
            char *nl = strchr(val, '\n');
            if (nl) *nl = '\0';
            if (strlen(val) >= 2 && val[0] == '"' && val[strlen(val)-1] == '"') {
                val[strlen(val)-1] = '\0';
                val++;
            }
            snprintf(token, sizeof(token), "%s", val);
            fclose(f);
            return token;
        }
    }
    fclose(f);
    return NULL;
}

/* Check an IP against AbuseIPDB. Returns abuse confidence score (0-100),
 * or -1 if the check is unavailable (no token, network error). */
static int abuseipdb_check(const char *ip)
{
    const char *api_token = get_abuseipdb_token();
    CURL *curl;
    CURLcode cres;
    char url[512];
    char auth_header[300];
    struct curl_slist *headers = NULL;
    struct abuse_buf buf = {NULL, 0};
    int score = -1;

    if (!api_token || !ip || !*ip)
        return -1;  /* no token = skip check */

    curl = curl_easy_init();
    if (!curl) return -1;

    snprintf(url, sizeof(url),
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
        ip);
    snprintf(auth_header, sizeof(auth_header), "Key: %s", api_token);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, abuse_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    cres = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (cres != CURLE_OK || !buf.data) {
        free(buf.data);
        return -1;
    }

    /* Parse: {"data":{"abuseConfidenceScore":N}} */
    {
        struct json_object *obj = json_tokener_parse(buf.data);
        struct json_object *data_obj, *score_obj;
        if (obj &&
            json_object_object_get_ex(obj, "data", &data_obj) &&
            json_object_object_get_ex(data_obj, "abuseConfidenceScore", &score_obj)) {
            score = json_object_get_int(score_obj);
        }
        if (obj) json_object_put(obj);
    }

    free(buf.data);
    return score;
}

/* Check IP and reject if abuse score >= threshold. Returns 0 = OK, -1 = reject. */
static int mqc_abuse_check(const char *ip)
{
    int score = abuseipdb_check(ip);
    if (score < 0) return 0;  /* no token or error = allow (fail-open) */
    if (score >= MQC_ABUSE_THRESHOLD) {
        MQC_SECURITY("ABUSEIPDB_REJECTED: %s score=%d (threshold=%d)",
                     ip, score, MQC_ABUSE_THRESHOLD);
        return -1;
    }
    MQC_LOG("AbuseIPDB: %s score=%d (OK)", ip, score);
    return 0;
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
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d\n",
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
                MQC_SECURITY("SIG_VERIFY_FAILED: server signature invalid");
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

    {
        char ip[64] = "unknown";
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
        MQC_LOG("accepted connection from %s:%d", ip, ntohs(cli_addr.sin_port));

        /* AbuseIPDB check */
        if (mqc_abuse_check(ip) != 0) {
            close(fd);
            return NULL;
        }
    }

    /* Handshake timeout — drop slowloris connections */
    set_socket_timeout(fd, MQC_HANDSHAKE_TIMEOUT);

    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    rng_ok = 1;

    /* Receive client's handshake */
    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) {
        MQC_SECURITY("handshake read failed (empty or malformed, fd=%d)", fd);
        goto fail;
    }
    if (ret > MQC_MAX_HANDSHAKE) {
        MQC_SECURITY("handshake too large: %d bytes (max %d)", ret, MQC_MAX_HANDSHAKE);
        goto fail;
    }

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
            MQC_SECURITY("PEER_VERIFY_FAILED: peer for index %d\n",
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
                MQC_SECURITY("SIG_VERIFY_FAILED: client signature invalid");
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
        clear_socket_timeout(fd);

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

/* --- Encrypted-identity handshake helpers --- */

static int enc_send(int fd, const uint8_t *aes_key, uint64_t *seq,
                    const void *data, int data_sz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t *ct;
    uint32_t net_len;
    int ret;

    ct = malloc((size_t)data_sz);
    if (!ct) return -1;
    make_nonce((*seq)++, nonce);
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }
    ret = wc_AesGcmSetKey(&aes, aes_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }
    ret = wc_AesGcmEncrypt(&aes, ct, (const byte *)data, (word32)data_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) { free(ct); return -1; }

    net_len = htonl((uint32_t)(data_sz + MQC_GCM_TAG_SZ));
    if (write_all(fd, (unsigned char *)&net_len, 4) != 0 ||
        write_all(fd, ct, (unsigned int)data_sz) != 0 ||
        write_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    free(ct);
    return 0;
}

static int enc_recv(int fd, const uint8_t *aes_key, uint64_t *seq,
                    void *buf, int bufsz)
{
    Aes aes;
    uint8_t nonce[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint32_t net_len, total_len;
    int ct_sz;
    uint8_t *ct;
    int ret;

    if (read_all(fd, (unsigned char *)&net_len, 4) != 0) return -1;
    total_len = ntohl(net_len);
    if (total_len < MQC_GCM_TAG_SZ || total_len > MQC_MAX_MSG) return -1;
    ct_sz = (int)(total_len - MQC_GCM_TAG_SZ);
    if (ct_sz > bufsz) return -1;

    ct = malloc((size_t)ct_sz);
    if (!ct) return -1;
    if (read_all(fd, ct, (unsigned int)ct_sz) != 0 ||
        read_all(fd, tag, MQC_GCM_TAG_SZ) != 0) {
        free(ct); return -1;
    }
    make_nonce((*seq)++, nonce);
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) { free(ct); return -1; }
    ret = wc_AesGcmSetKey(&aes, aes_key, MQC_AES_KEY_SZ);
    if (ret != 0) { wc_AesFree(&aes); free(ct); return -1; }
    ret = wc_AesGcmDecrypt(&aes, (byte *)buf, ct, (word32)ct_sz,
        nonce, MQC_GCM_IV_SZ, tag, MQC_GCM_TAG_SZ, NULL, 0);
    wc_AesFree(&aes);
    free(ct);
    if (ret != 0) {
        MQC_SECURITY("GCM_AUTH_FAILED: decryption failed (tampered data or wrong key, seq=%lu)",
                     (unsigned long)(*seq - 1));
        return -1;
    }
    return ct_sz;
}

/* --- Encrypted-identity connect (two-phase handshake) --- */

mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port)
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
        if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;
        for (rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) return NULL;
    }
    fprintf(stderr, "[mqc-enc] connected to %s:%d\n", host, port);

    if (wc_InitRng(&rng) != 0) goto fail;
    rng_ok = 1;

    /* Phase 1: ML-KEM key exchange (plaintext) */
    ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) goto fail;
    mlkem_ok = 1;
    ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    if (ret != 0) goto fail;
    wc_MlKemKey_PublicKeySize(&mlkem, &encaps_key_sz);
    if (encaps_key_sz > sizeof(encaps_key)) goto fail;
    ret = wc_MlKemKey_EncodePublicKey(&mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) goto fail;

    /* Send ML-KEM encaps key only (no identity) */
    {
        char *ek_hex = malloc(encaps_key_sz * 2 + 1);
        int json_len;
        to_hex(encaps_key, (int)encaps_key_sz, ek_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"mlkem_encaps_key\":\"%s\"}", ek_hex);
        free(ek_hex);
        if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0)
            goto fail;
    }
    fprintf(stderr, "[mqc-enc] phase 1: sent ML-KEM key (plaintext)\n");

    /* Receive server's ML-KEM ciphertext (plaintext) */
    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;
    {
        struct json_object *r1 = json_tokener_parse(json_buf);
        struct json_object *v1;
        const char *ct_hex;
        uint8_t ct[4096];
        int ct_sz;

        if (!r1 || !json_object_object_get_ex(r1, "mlkem_ciphertext", &v1)) {
            if (r1) json_object_put(r1);
            goto fail;
        }
        ct_hex = json_object_get_string(v1);
        ct_sz = hex_to_bytes(ct_hex, ct, sizeof(ct));
        json_object_put(r1);
        if (ct_sz <= 0) goto fail;

        ret = wc_MlKemKey_Decapsulate(&mlkem, shared_secret, ct, (word32)ct_sz);
        if (ret != 0) goto fail;
    }

    /* Derive session key */
    ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ,
        NULL, 0, (const byte *)MQC_HKDF_INFO,
        (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
    if (ret != 0) goto fail;
    fprintf(stderr, "[mqc-enc] phase 1: ML-KEM shared secret derived\n");

    /* Phase 2: encrypted identity exchange */
    /* Sign the encaps key we sent (proves we generated it) */
    wc_dilithium_init(&dil);
    dil_ok = 1;
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    {
        word32 dil_idx = 0;
        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &dil_idx,
            &dil, (word32)ctx->privkey_der_sz);
    }
    if (ret != 0) goto fail;
    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
        encaps_key, encaps_key_sz, sig, &sig_sz, &dil, &rng);
    if (ret != 0) goto fail;

    /* Send encrypted: {cert_index, signature} */
    {
        char *sig_hex = malloc(sig_sz * 2 + 1);
        int id_len;
        uint64_t hs_seq = 0;
        to_hex(sig, (int)sig_sz, sig_hex);
        id_len = snprintf(json_buf, sizeof(json_buf),
            "{\"cert_index\":%d,\"signature\":\"%s\"}",
            ctx->our_cert_index, sig_hex);
        free(sig_hex);
        if (enc_send(fd, aes_key, &hs_seq, json_buf, id_len) != 0)
            goto fail;
    }
    fprintf(stderr, "[mqc-enc] phase 2: sent identity (encrypted, cert_index=%d)\n",
            ctx->our_cert_index);

    /* Receive encrypted server identity */
    {
        uint64_t hs_seq = 0;
        ret = enc_recv(fd, aes_key, &hs_seq, json_buf, sizeof(json_buf) - 1);
        if (ret <= 0) goto fail;
        json_buf[ret] = '\0';
    }

    /* Parse server identity, verify peer + signature */
    {
        struct json_object *r2 = json_tokener_parse(json_buf);
        struct json_object *v2;
        const char *resp_sig_hex;
        uint8_t resp_sig[8192];
        int resp_sig_sz;
        int peer_index;
        unsigned char *peer_pubkey = NULL;
        int peer_pubkey_sz = 0;

        if (!r2) goto fail;
        if (!json_object_object_get_ex(r2, "cert_index", &v2)) {
            json_object_put(r2); goto fail;
        }
        peer_index = json_object_get_int(v2);
        if (!json_object_object_get_ex(r2, "signature", &v2)) {
            json_object_put(r2); goto fail;
        }
        resp_sig_hex = json_object_get_string(v2);
        resp_sig_sz = hex_to_bytes(resp_sig_hex, resp_sig, sizeof(resp_sig));
        json_object_put(r2);
        if (resp_sig_sz <= 0) goto fail;

        /* Verify peer via Merkle */
        ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                              peer_index, &peer_pubkey, &peer_pubkey_sz);
        if (ret != 0) goto fail;

        /* The server signed its ML-KEM ciphertext — but we already consumed it.
         * Instead, the server signs a known challenge: the shared secret hash.
         * For simplicity: server signs its own cert_index as a string. */
        {
            dilithium_key peer_dil;
            int verified = 0;
            char peer_challenge[32];
            int pc_len = snprintf(peer_challenge, sizeof(peer_challenge),
                                  "mqc-id:%d", peer_index);
            wc_dilithium_init(&peer_dil);
            wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
            {
                word32 pi = 0;
                ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi,
                    &peer_dil, (word32)peer_pubkey_sz);
            }
            if (ret == 0)
                ret = wc_dilithium_verify_ctx_msg(resp_sig, (word32)resp_sig_sz,
                    NULL, 0, (const byte *)peer_challenge, (word32)pc_len,
                    &verified, &peer_dil);
            wc_dilithium_free(&peer_dil);
            free(peer_pubkey);
            if (ret != 0 || !verified) {
                MQC_SECURITY("SIG_VERIFY_FAILED: encrypted mode server signature invalid");
                goto fail;
            }
        }
        fprintf(stderr, "[mqc-enc] peer %d verified + signature OK\n", peer_index);

        conn = calloc(1, sizeof(*conn));
        if (!conn) goto fail;
        conn->fd = fd;
        memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
        conn->peer_index = peer_index;
        conn->send_seq = 1;  /* 0 was used for handshake */
        conn->recv_seq = 1;
    }

    fprintf(stderr, "[mqc-enc] session established\n");
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

/* --- Encrypted-identity accept (two-phase handshake) --- */

mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd)
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
    uint8_t aes_key[MQC_AES_KEY_SZ];
    char json_buf[64000];
    int ret;
    mqc_conn_t *conn = NULL;
    int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;
    {
        char ip[64] = "unknown";
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
        MQC_LOG("accepted encrypted connection from %s:%d", ip, ntohs(cli_addr.sin_port));
        if (mqc_abuse_check(ip) != 0) { close(fd); return NULL; }
    }
    set_socket_timeout(fd, MQC_HANDSHAKE_TIMEOUT);

    if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
    rng_ok = 1;

    /* Phase 1: receive ML-KEM encaps key (plaintext) */
    ret = read_json_block(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) goto fail;
    {
        struct json_object *r1 = json_tokener_parse(json_buf);
        struct json_object *v1;
        const char *ek_hex;
        uint8_t encaps_key[4096];
        int ek_sz;

        if (!r1 || !json_object_object_get_ex(r1, "mlkem_encaps_key", &v1)) {
            if (r1) json_object_put(r1);
            goto fail;
        }
        ek_hex = json_object_get_string(v1);
        ek_sz = hex_to_bytes(ek_hex, encaps_key, sizeof(encaps_key));
        json_object_put(r1);
        if (ek_sz <= 0) goto fail;

        /* Encapsulate */
        ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
        if (ret != 0) goto fail;
        mlkem_ok = 1;
        ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key, (word32)ek_sz);
        if (ret != 0) goto fail;
        ct_sz = sizeof(ciphertext);
        wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
        ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
        if (ret != 0) goto fail;

        /* Send ML-KEM ciphertext (plaintext) */
        {
            char *ct_hex = malloc(ct_sz * 2 + 1);
            int jl;
            to_hex(ciphertext, (int)ct_sz, ct_hex);
            jl = snprintf(json_buf, sizeof(json_buf),
                "{\"mlkem_ciphertext\":\"%s\"}", ct_hex);
            free(ct_hex);
            if (write_all(fd, (unsigned char *)json_buf, (unsigned int)jl) != 0)
                goto fail;
        }

        /* Save encaps_key for later signature verification */
        /* (client signed the encaps_key it sent) */
        {
            /* Store on stack — we need it for phase 2 verification */
            /* ek_sz and encaps_key are still valid here */

            /* Derive session key */
            ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ,
                NULL, 0, (const byte *)MQC_HKDF_INFO,
                (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
            if (ret != 0) goto fail;
            fprintf(stderr, "[mqc-enc] phase 1: ML-KEM done, channel encrypted\n");

            /* Phase 2: receive encrypted client identity */
            {
                uint64_t hs_seq = 0;
                ret = enc_recv(fd, aes_key, &hs_seq,
                               json_buf, sizeof(json_buf) - 1);
                if (ret <= 0) goto fail;
                json_buf[ret] = '\0';
            }

            /* Parse client identity */
            {
                struct json_object *r2 = json_tokener_parse(json_buf);
                struct json_object *v2;
                const char *cli_sig_hex;
                uint8_t cli_sig[8192];
                int cli_sig_sz;
                int peer_index;
                unsigned char *peer_pubkey = NULL;
                int peer_pubkey_sz = 0;

                if (!r2) goto fail;
                if (!json_object_object_get_ex(r2, "cert_index", &v2)) {
                    json_object_put(r2); goto fail;
                }
                peer_index = json_object_get_int(v2);
                if (!json_object_object_get_ex(r2, "signature", &v2)) {
                    json_object_put(r2); goto fail;
                }
                cli_sig_hex = json_object_get_string(v2);
                cli_sig_sz = hex_to_bytes(cli_sig_hex, cli_sig, sizeof(cli_sig));
                json_object_put(r2);
                if (cli_sig_sz <= 0) goto fail;

                /* Verify peer */
                ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey,
                    ctx->ca_pubkey_sz, peer_index, &peer_pubkey, &peer_pubkey_sz);
                if (ret != 0) goto fail;

                /* Verify client signed the encaps_key it sent */
                {
                    dilithium_key peer_dil;
                    int verified = 0;
                    wc_dilithium_init(&peer_dil);
                    wc_dilithium_set_level(&peer_dil, WC_ML_DSA_87);
                    {
                        word32 pi = 0;
                        ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi,
                            &peer_dil, (word32)peer_pubkey_sz);
                    }
                    if (ret == 0)
                        ret = wc_dilithium_verify_ctx_msg(
                            cli_sig, (word32)cli_sig_sz, NULL, 0,
                            encaps_key, (word32)ek_sz, &verified, &peer_dil);
                    wc_dilithium_free(&peer_dil);
                    free(peer_pubkey);
                    if (ret != 0 || !verified) {
                        fprintf(stderr, "[mqc-enc] client signature failed\n");
                        goto fail;
                    }
                }
                fprintf(stderr, "[mqc-enc] peer %d verified + signature OK\n",
                        peer_index);

                /* Send our encrypted identity */
                {
                    uint8_t our_sig[8192];
                    word32 our_sig_sz = sizeof(our_sig);
                    char peer_challenge[32];
                    int pc_len = snprintf(peer_challenge, sizeof(peer_challenge),
                                          "mqc-id:%d", ctx->our_cert_index);

                    wc_dilithium_init(&dil);
                    dil_ok = 1;
                    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
                    {
                        word32 di = 0;
                        ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der,
                            &di, &dil, (word32)ctx->privkey_der_sz);
                    }
                    if (ret != 0) goto fail;
                    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                        (const byte *)peer_challenge, (word32)pc_len,
                        our_sig, &our_sig_sz, &dil, &rng);
                    if (ret != 0) goto fail;

                    {
                        char *sh = malloc(our_sig_sz * 2 + 1);
                        int il;
                        uint64_t hs_seq = 0;
                        to_hex(our_sig, (int)our_sig_sz, sh);
                        il = snprintf(json_buf, sizeof(json_buf),
                            "{\"cert_index\":%d,\"signature\":\"%s\"}",
                            ctx->our_cert_index, sh);
                        free(sh);
                        if (enc_send(fd, aes_key, &hs_seq, json_buf, il) != 0)
                            goto fail;
                    }
                }

                conn = calloc(1, sizeof(*conn));
                if (!conn) goto fail;
                conn->fd = fd;
                memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
                conn->peer_index = peer_index;
                conn->send_seq = 1;
                conn->recv_seq = 1;
                clear_socket_timeout(fd);
            }
        }
    }

    fprintf(stderr, "[mqc-enc] session established\n");
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

/* --- Auto-detecting accept --- */

/* Internal: accept TCP, read first JSON, detect mode.
 * Returns fd and fills json_buf. Sets *is_encrypted = 1 if no cert_index
 * in the first JSON (encrypted identity mode), 0 otherwise.
 * Returns -1 on failure. */
static int auto_accept_detect(int listen_fd, char *json_buf, int json_bufsz,
                              int *is_encrypted)
{
    int fd;
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int ret;
    struct json_object *obj, *val;

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return -1;
    {
        char ip[64] = "unknown";
        inet_ntop(AF_INET, &cli_addr.sin_addr, ip, sizeof(ip));
        MQC_LOG("auto-accept from %s:%d", ip, ntohs(cli_addr.sin_port));
        if (mqc_abuse_check(ip) != 0) { close(fd); return -1; }
    }
    set_socket_timeout(fd, MQC_HANDSHAKE_TIMEOUT);

    ret = read_json_block(fd, json_buf, json_bufsz);
    if (ret <= 0) { close(fd); return -1; }

    obj = json_tokener_parse(json_buf);
    if (!obj) { close(fd); return -1; }

    /* If "cert_index" is present, it's clear mode (single round trip).
     * If absent, it's encrypted mode (ML-KEM first, identity later). */
    *is_encrypted = json_object_object_get_ex(obj, "cert_index", &val) ? 0 : 1;
    json_object_put(obj);

    fprintf(stderr, "[mqc-auto] detected %s mode\n",
            *is_encrypted ? "encrypted" : "clear");
    return fd;
}

mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)
{
    char json_buf[64000];
    int is_encrypted = 0;
    int fd;

    fd = auto_accept_detect(listen_fd, json_buf, sizeof(json_buf), &is_encrypted);
    if (fd < 0) return NULL;

    if (!is_encrypted) {
        /* Clear mode: json_buf has the full handshake JSON.
         * Process it inline (same logic as mqc_accept but with
         * already-accepted fd and already-read JSON). */
        MlKemKey mlkem;
        dilithium_key dil;
        WC_RNG rng;
        uint8_t shared_secret[WC_ML_KEM_SS_SZ];
        uint8_t ciphertext[4096];
        word32 ct_sz;
        uint8_t sig[8192];
        word32 sig_sz = sizeof(sig);
        uint8_t aes_key[MQC_AES_KEY_SZ];
        int ret;
        mqc_conn_t *conn = NULL;
        int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

        if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
        rng_ok = 1;

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
            if (!req) goto clear_fail;
            if (!json_object_object_get_ex(req, "cert_index", &val)) { json_object_put(req); goto clear_fail; }
            peer_index = json_object_get_int(val);
            if (!json_object_object_get_ex(req, "mlkem_encaps_key", &val)) { json_object_put(req); goto clear_fail; }
            ek_hex = json_object_get_string(val);
            ek_sz = hex_to_bytes(ek_hex, encaps_key, sizeof(encaps_key));
            if (!json_object_object_get_ex(req, "signature", &val)) { json_object_put(req); goto clear_fail; }
            req_sig_hex = json_object_get_string(val);
            req_sig_sz = hex_to_bytes(req_sig_hex, req_sig, sizeof(req_sig));
            json_object_put(req);
            if (ek_sz <= 0 || req_sig_sz <= 0) goto clear_fail;

            ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                                  peer_index, &peer_pubkey, &peer_pubkey_sz);
            if (ret != 0) goto clear_fail;

            { dilithium_key pd; int v = 0; wc_dilithium_init(&pd); wc_dilithium_set_level(&pd, WC_ML_DSA_87);
              { word32 pi = 0; ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi, &pd, (word32)peer_pubkey_sz); }
              if (ret == 0) ret = wc_dilithium_verify_ctx_msg(req_sig, (word32)req_sig_sz, NULL, 0, encaps_key, (word32)ek_sz, &v, &pd);
              wc_dilithium_free(&pd); free(peer_pubkey);
              if (ret != 0 || !v) goto clear_fail; }

            ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
            if (ret != 0) goto clear_fail; mlkem_ok = 1;
            ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key, (word32)ek_sz);
            if (ret != 0) goto clear_fail;
            ct_sz = sizeof(ciphertext); wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
            ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
            if (ret != 0) goto clear_fail;

            wc_dilithium_init(&dil); dil_ok = 1; wc_dilithium_set_level(&dil, WC_ML_DSA_87);
            { word32 di = 0; ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &di, &dil, (word32)ctx->privkey_der_sz); }
            if (ret != 0) goto clear_fail;
            ret = wc_dilithium_sign_ctx_msg(NULL, 0, ciphertext, ct_sz, sig, &sig_sz, &dil, &rng);
            if (ret != 0) goto clear_fail;

            { char *ch = malloc(ct_sz*2+1); char *sh = malloc(sig_sz*2+1); int jl;
              to_hex(ciphertext,(int)ct_sz,ch); to_hex(sig,(int)sig_sz,sh);
              jl = snprintf(json_buf,sizeof(json_buf),"{\"cert_index\":%d,\"mlkem_ciphertext\":\"%s\",\"signature\":\"%s\"}",ctx->our_cert_index,ch,sh);
              free(ch); free(sh);
              if (write_all(fd,(unsigned char*)json_buf,(unsigned int)jl)!=0) goto clear_fail; }

            ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ, NULL, 0,
                (const byte*)MQC_HKDF_INFO, (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
            if (ret != 0) goto clear_fail;

            conn = calloc(1, sizeof(*conn));
            if (!conn) goto clear_fail;
            conn->fd = fd; memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
            conn->peer_index = peer_index;
            clear_socket_timeout(fd);
            fprintf(stderr, "[mqc-auto] clear session with peer %d\n", peer_index);
        }
        secure_zero(shared_secret, sizeof(shared_secret));
        secure_zero(aes_key, sizeof(aes_key));
        if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
        if (dil_ok) wc_dilithium_free(&dil);
        wc_FreeRng(&rng);
        return conn;

    clear_fail:
        secure_zero(shared_secret, sizeof(shared_secret));
        secure_zero(aes_key, sizeof(aes_key));
        if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
        if (dil_ok) wc_dilithium_free(&dil);
        if (rng_ok) wc_FreeRng(&rng);
        close(fd);
        return NULL;
    } else {
        /* Encrypted mode: json_buf has {"mlkem_encaps_key":"..."} only.
         * Do ML-KEM encapsulate, derive key, then receive encrypted identity. */
        MlKemKey mlkem;
        dilithium_key dil;
        WC_RNG rng;
        uint8_t shared_secret[WC_ML_KEM_SS_SZ];
        uint8_t ciphertext[4096];
        word32 ct_sz;
        uint8_t aes_key[MQC_AES_KEY_SZ];
        int ret;
        mqc_conn_t *conn = NULL;
        int mlkem_ok = 0, dil_ok = 0, rng_ok = 0;

        if (wc_InitRng(&rng) != 0) { close(fd); return NULL; }
        rng_ok = 1;

        /* Parse ML-KEM encaps key from json_buf */
        {
            struct json_object *r1, *v1;
            const char *ek_hex;
            uint8_t encaps_key[4096];
            int ek_sz;

            r1 = json_tokener_parse(json_buf);
            if (!r1 || !json_object_object_get_ex(r1, "mlkem_encaps_key", &v1)) {
                if (r1) json_object_put(r1); goto enc_fail;
            }
            ek_hex = json_object_get_string(v1);
            ek_sz = hex_to_bytes(ek_hex, encaps_key, sizeof(encaps_key));
            json_object_put(r1);
            if (ek_sz <= 0) goto enc_fail;

            /* Encapsulate */
            ret = wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
            if (ret != 0) goto enc_fail; mlkem_ok = 1;
            ret = wc_MlKemKey_DecodePublicKey(&mlkem, encaps_key, (word32)ek_sz);
            if (ret != 0) goto enc_fail;
            ct_sz = sizeof(ciphertext); wc_MlKemKey_CipherTextSize(&mlkem, &ct_sz);
            ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext, shared_secret, &rng);
            if (ret != 0) goto enc_fail;

            /* Send ML-KEM ciphertext (plaintext) */
            { char *ch = malloc(ct_sz*2+1); int jl;
              to_hex(ciphertext,(int)ct_sz,ch);
              jl = snprintf(json_buf,sizeof(json_buf),"{\"mlkem_ciphertext\":\"%s\"}",ch);
              free(ch);
              if (write_all(fd,(unsigned char*)json_buf,(unsigned int)jl)!=0) goto enc_fail; }

            /* Derive session key */
            ret = wc_HKDF(WC_SHA256, shared_secret, WC_ML_KEM_SS_SZ, NULL, 0,
                (const byte*)MQC_HKDF_INFO, (word32)strlen(MQC_HKDF_INFO), aes_key, MQC_AES_KEY_SZ);
            if (ret != 0) goto enc_fail;

            fprintf(stderr, "[mqc-auto] encrypted: ML-KEM done, receiving identity\n");

            /* Receive encrypted client identity */
            { uint64_t hs_seq = 0;
              ret = enc_recv(fd, aes_key, &hs_seq, json_buf, sizeof(json_buf)-1);
              if (ret <= 0) goto enc_fail;
              json_buf[ret] = '\0'; }

            /* Parse client identity, verify */
            {
                struct json_object *r2, *v2;
                const char *cli_sig_hex;
                uint8_t cli_sig[8192];
                int cli_sig_sz, peer_index;
                unsigned char *peer_pubkey = NULL;
                int peer_pubkey_sz = 0;

                r2 = json_tokener_parse(json_buf);
                if (!r2) goto enc_fail;
                if (!json_object_object_get_ex(r2, "cert_index", &v2)) { json_object_put(r2); goto enc_fail; }
                peer_index = json_object_get_int(v2);
                if (!json_object_object_get_ex(r2, "signature", &v2)) { json_object_put(r2); goto enc_fail; }
                cli_sig_hex = json_object_get_string(v2);
                cli_sig_sz = hex_to_bytes(cli_sig_hex, cli_sig, sizeof(cli_sig));
                json_object_put(r2);
                if (cli_sig_sz <= 0) goto enc_fail;

                ret = mqc_peer_verify(ctx->mtc_server, ctx->ca_pubkey, ctx->ca_pubkey_sz,
                                      peer_index, &peer_pubkey, &peer_pubkey_sz);
                if (ret != 0) goto enc_fail;

                /* Client signed the encaps_key it sent */
                { dilithium_key pd; int v = 0; wc_dilithium_init(&pd); wc_dilithium_set_level(&pd, WC_ML_DSA_87);
                  { word32 pi = 0; ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi, &pd, (word32)peer_pubkey_sz); }
                  if (ret == 0) ret = wc_dilithium_verify_ctx_msg(cli_sig, (word32)cli_sig_sz, NULL, 0, encaps_key, (word32)ek_sz, &v, &pd);
                  wc_dilithium_free(&pd); free(peer_pubkey);
                  if (ret != 0 || !v) { fprintf(stderr, "[mqc-auto] encrypted: client sig failed\n"); goto enc_fail; } }

                fprintf(stderr, "[mqc-auto] encrypted: peer %d verified\n", peer_index);

                /* Send our encrypted identity */
                { uint8_t our_sig[8192]; word32 our_sig_sz = sizeof(our_sig);
                  char challenge[32]; int cl = snprintf(challenge,sizeof(challenge),"mqc-id:%d",ctx->our_cert_index);
                  wc_dilithium_init(&dil); dil_ok = 1; wc_dilithium_set_level(&dil, WC_ML_DSA_87);
                  { word32 di = 0; ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &di, &dil, (word32)ctx->privkey_der_sz); }
                  if (ret != 0) goto enc_fail;
                  ret = wc_dilithium_sign_ctx_msg(NULL, 0, (const byte*)challenge, (word32)cl, our_sig, &our_sig_sz, &dil, &rng);
                  if (ret != 0) goto enc_fail;
                  { char *sh = malloc(our_sig_sz*2+1); int il; uint64_t hs_seq = 0;
                    to_hex(our_sig,(int)our_sig_sz,sh);
                    il = snprintf(json_buf,sizeof(json_buf),"{\"cert_index\":%d,\"signature\":\"%s\"}",ctx->our_cert_index,sh);
                    free(sh);
                    if (enc_send(fd, aes_key, &hs_seq, json_buf, il) != 0) goto enc_fail; } }

                conn = calloc(1, sizeof(*conn));
                if (!conn) goto enc_fail;
                conn->fd = fd; memcpy(conn->aes_key, aes_key, MQC_AES_KEY_SZ);
                conn->peer_index = peer_index;
                conn->send_seq = 1; conn->recv_seq = 1;
                clear_socket_timeout(fd);
                fprintf(stderr, "[mqc-auto] encrypted session with peer %d\n", peer_index);
            }
        }

        secure_zero(shared_secret, sizeof(shared_secret));
        secure_zero(aes_key, sizeof(aes_key));
        if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
        if (dil_ok) wc_dilithium_free(&dil);
        wc_FreeRng(&rng);
        return conn;

    enc_fail:
        secure_zero(shared_secret, sizeof(shared_secret));
        secure_zero(aes_key, sizeof(aes_key));
        if (mlkem_ok) wc_MlKemKey_Free(&mlkem);
        if (dil_ok) wc_dilithium_free(&dil);
        if (rng_ok) wc_FreeRng(&rng);
        close(fd);
        return NULL;
    }
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

    if (ret != 0) {
        MQC_SECURITY("GCM_AUTH_FAILED: data decryption failed "
                     "(tampered data or wrong key, peer=%d seq=%lu)",
                     conn->peer_index, (unsigned long)(conn->recv_seq - 1));
        return -1;
    }

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
