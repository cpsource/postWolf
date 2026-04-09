/* src/ssl_mtc.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * MTC Public API — wolfSSL port.
 *
 * Talks to the CA/Log server over HTTP (libcurl) and manages local
 * key/cert storage in a configurable path (default ~/.TPM).
 *
 * Dependencies: libcurl, json-c (external); wolfcrypt (for key generation)
 *
 * This file is #included from ssl.c when HAVE_MTC is defined.
 */

#ifdef HAVE_MTC

#ifndef WOLFSSL_SSL_MTC_INCLUDED
#error "ssl_mtc.c should be included from ssl.c"
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_MTC_API

/* Include the MTC public C API types from the wolfssl header tree.
 * This header defines mtc_conn_t, mtc_cert_t, mtc_verify_t, etc. */
#include <wolfssl/wolfcrypt/mtc_api.h>

/* Suppress warnings from third-party headers that use C99 pragmas */
#ifdef __GNUC__
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpragmas\"")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#ifdef __GNUC__
    _Pragma("GCC diagnostic pop")
#endif

#ifndef MTC_DEFAULT_STORE_PATH
#define MTC_DEFAULT_STORE_PATH "/.TPM"
#endif

/* ----------------------------------------------------------------------- */
/* Internal state                                                          */
/* ----------------------------------------------------------------------- */

struct mtc_conn {
    char *server_url;
    char *ca_name;
    char *log_id;
    int   tree_size;
    CURL *curl;
    char *store_path;   /* Configurable store path */
    /* Cached CA public key (fetched once from /ca/public-key).
     * Sized for ML-DSA-87 (2592 bytes) in case the CA cosigning
     * key migrates from Ed25519 to post-quantum in the future. */
    uint8_t ca_pub_key[4096];
    int     ca_pub_key_sz;  /* 0 = not yet fetched */
};

static char _mtc_last_error[512] = {0};

static void mtc_set_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    XVSNPRINTF(_mtc_last_error, sizeof(_mtc_last_error), fmt, ap);
    va_end(ap);
}

const char *MTC_Last_Error(void) {
    return _mtc_last_error[0] ? _mtc_last_error : NULL;
}

/* ----------------------------------------------------------------------- */
/* HTTP helpers                                                            */
/* ----------------------------------------------------------------------- */

struct mtc_http_buf {
    char  *data;
    size_t len;
};

static size_t mtc_write_cb(void *ptr, size_t size, size_t nmemb, void *userp) {
    struct mtc_http_buf *buf = (struct mtc_http_buf*)userp;
    size_t total = size * nmemb;
    char *tmp = (char*)realloc(buf->data, buf->len + total + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    XMEMCPY(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static struct json_object *mtc_http_get(mtc_conn_t *conn, const char *path) {
    char url[1024];
    struct mtc_http_buf buf;
    CURLcode res;
    struct json_object *obj;

    XSNPRINTF(url, sizeof(url), "%s%s", conn->server_url, path);

    buf.data = NULL;
    buf.len = 0;
    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, mtc_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);

    res = curl_easy_perform(conn->curl);
    if (res != CURLE_OK) {
        mtc_set_error("HTTP GET %s failed: %s", path, curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    obj = json_tokener_parse(buf.data);
    free(buf.data);
    return obj;
}

static struct json_object *mtc_http_post(mtc_conn_t *conn, const char *path,
                                         const char *json_body) {
    char url[1024];
    struct mtc_http_buf buf;
    struct curl_slist *headers = NULL;
    CURLcode res;
    struct json_object *obj;

    XSNPRINTF(url, sizeof(url), "%s%s", conn->server_url, path);

    buf.data = NULL;
    buf.len = 0;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, mtc_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, json_body);

    res = curl_easy_perform(conn->curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        mtc_set_error("HTTP POST %s failed: %s", path, curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    obj = json_tokener_parse(buf.data);
    free(buf.data);
    return obj;
}

/* ----------------------------------------------------------------------- */
/* Path helpers                                                            */
/* ----------------------------------------------------------------------- */

static const char *mtc_get_home(void) {
    const char *h = getenv("HOME");
    if (h) return h;
    return "/tmp";
}

/* Build path: {store_path}/{sanitized_subject}/{file} */
static void mtc_store_file_path(char *out, size_t len,
    const char *store_path, const char *subject, const char *file) {
    char safe[256];
    char *p;
    size_t slen = XSTRLEN(subject);

    if (slen >= sizeof(safe))
        slen = sizeof(safe) - 1;
    XMEMCPY(safe, subject, slen);
    safe[slen] = '\0';

    for (p = safe; *p; p++) {
        if (*p == '/' || *p == ':') *p = '_';
    }
    XSNPRINTF(out, len, "%s/%s/%s", store_path, safe, file);
}

static void mtc_store_dir_path(char *out, size_t len,
    const char *store_path, const char *subject) {
    char safe[256];
    char *p;
    size_t slen = XSTRLEN(subject);

    if (slen >= sizeof(safe))
        slen = sizeof(safe) - 1;
    XMEMCPY(safe, subject, slen);
    safe[slen] = '\0';

    for (p = safe; *p; p++) {
        if (*p == '/' || *p == ':') *p = '_';
    }
    XSNPRINTF(out, len, "%s/%s", store_path, safe);
}

static void mtc_mkdirp(const char *path) {
    char tmp[512];
    char *p;
    XSNPRINTF(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}

/* ----------------------------------------------------------------------- */
/* MTC_Connect                                                             */
/* ----------------------------------------------------------------------- */

mtc_conn_t *MTC_Connect(const char *server_url) {
    mtc_conn_t *conn;
    struct json_object *info;
    struct json_object *val;

    conn = (mtc_conn_t*)calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->server_url = strdup(server_url);
    conn->curl = curl_easy_init();
    if (!conn->curl) {
        mtc_set_error("failed to init curl");
        free(conn->server_url);
        free(conn);
        return NULL;
    }

    /* Build default store path */
    {
        char default_path[512];
        XSNPRINTF(default_path, sizeof(default_path), "%s%s",
            mtc_get_home(), MTC_DEFAULT_STORE_PATH);
        conn->store_path = strdup(default_path);
    }

    /* Fetch server info */
    info = mtc_http_get(conn, "/");
    if (!info) {
        MTC_Disconnect(conn);
        return NULL;
    }

    if (json_object_object_get_ex(info, "ca_name", &val))
        conn->ca_name = strdup(json_object_get_string(val));
    if (json_object_object_get_ex(info, "log_id", &val))
        conn->log_id = strdup(json_object_get_string(val));
    if (json_object_object_get_ex(info, "tree_size", &val))
        conn->tree_size = json_object_get_int(val);

    json_object_put(info);
    return conn;
}

void MTC_Disconnect(mtc_conn_t *conn) {
    if (!conn) return;
    if (conn->curl) curl_easy_cleanup(conn->curl);
    free(conn->server_url);
    free(conn->ca_name);
    free(conn->log_id);
    free(conn->store_path);
    free(conn);
}

const char *MTC_Conn_CA_Name(const mtc_conn_t *conn) { return conn->ca_name; }
const char *MTC_Conn_Log_ID(const mtc_conn_t *conn) { return conn->log_id; }
int MTC_Conn_Tree_Size(const mtc_conn_t *conn) { return conn->tree_size; }

void MTC_Conn_SetStorePath(mtc_conn_t *conn, const char *path) {
    if (!conn || !path) return;
    free(conn->store_path);
    conn->store_path = strdup(path);
}

/* ----------------------------------------------------------------------- */
/* MTC_Enroll (wolfSSL key generation)                                     */
/* ----------------------------------------------------------------------- */

mtc_cert_t *MTC_Enroll(mtc_conn_t *conn, const char *subject,
                        const char *algorithm, int validity_days,
                        const mtc_extensions_t *extensions) {
    ecc_key key;
    byte derBuf[512];
    byte pemBuf[1024];
    int derSz, pemSz;
    char dir[512], path[512];
    FILE *fp;
    struct json_object *req, *ext, *resp, *val, *sc, *tbs;
    const char *body;
    mtc_cert_t *cert;
    WC_RNG rng;
    int ret;
    const char *store = conn->store_path;

    if (!algorithm) algorithm = "EC-P256";
    if (validity_days <= 0) validity_days = 90;

    /* Generate EC-P256 key using wolfcrypt */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        mtc_set_error("RNG init failed: %d", ret);
        return NULL;
    }

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        mtc_set_error("ecc init failed: %d", ret);
        return NULL;
    }

    ret = wc_ecc_make_key(&rng, 32, &key); /* P-256 = 32 bytes */
    wc_FreeRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&key);
        mtc_set_error("key generation failed: %d", ret);
        return NULL;
    }

    /* Create store directory */
    mtc_store_dir_path(dir, sizeof(dir), store, subject);
    mtc_mkdirp(dir);

    /* Write private key PEM */
    derSz = wc_EccKeyToDer(&key, derBuf, sizeof(derBuf));
    if (derSz > 0) {
        pemSz = wc_DerToPem(derBuf, (word32)derSz, pemBuf, sizeof(pemBuf),
            ECC_PRIVATEKEY_TYPE);
        if (pemSz > 0) {
            mtc_store_file_path(path, sizeof(path), store, subject,
                "private_key.pem");
            fp = fopen(path, "w");
            if (fp) {
                fwrite(pemBuf, 1, (size_t)pemSz, fp);
                fclose(fp);
                chmod(path, 0600);
            }
        }
    }

    /* Write public key PEM */
    derSz = wc_EccPublicKeyToDer(&key, derBuf, sizeof(derBuf), 1);
    if (derSz > 0) {
        pemSz = wc_DerToPem(derBuf, (word32)derSz, pemBuf, sizeof(pemBuf),
            ECC_PUBLICKEY_TYPE);
        if (pemSz > 0) {
            mtc_store_file_path(path, sizeof(path), store, subject,
                "public_key.pem");
            fp = fopen(path, "w");
            if (fp) {
                fwrite(pemBuf, 1, (size_t)pemSz, fp);
                fclose(fp);
            }
        }
    }

    wc_ecc_free(&key);

    /* Build JSON request */
    req = json_object_new_object();
    json_object_object_add(req, "subject", json_object_new_string(subject));
    json_object_object_add(req, "public_key_pem",
        json_object_new_string((char*)pemBuf));
    json_object_object_add(req, "key_algorithm",
        json_object_new_string(algorithm));
    json_object_object_add(req, "validity_days",
        json_object_new_int(validity_days));

    ext = json_object_new_object();
    json_object_object_add(ext, "key_usage",
        json_object_new_string("digitalSignature"));
    if (extensions) {
        int i;
        for (i = 0; i < extensions->count; i++)
            json_object_object_add(ext, extensions->keys[i],
                json_object_new_string(extensions->values[i]));
    }
    json_object_object_add(req, "extensions", ext);

    body = json_object_to_json_string(req);
    resp = mtc_http_post(conn, "/certificate/request", body);
    json_object_put(req);

    if (!resp) return NULL;

    printf("[MTC_Enroll] response keys:");
    json_object_object_foreach(resp, rkey, rval) {
        printf(" %s", rkey);
        (void)rval;
    }
    printf("\n");

    /* Save certificate JSON */
    mtc_store_file_path(path, sizeof(path), store, subject, "certificate.json");
    fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%s\n",
            json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PRETTY));
        fclose(fp);
    }

    /* Parse result */
    cert = (mtc_cert_t*)calloc(1, sizeof(*cert));

    if (json_object_object_get_ex(resp, "index", &val))
        cert->index = json_object_get_int(val);

    /* Save index file */
    mtc_store_file_path(path, sizeof(path), store, subject, "index");
    fp = fopen(path, "w");
    if (fp) { fprintf(fp, "%d", cert->index); fclose(fp); }

    if (json_object_object_get_ex(resp, "standalone_certificate", &sc)) {
        if (json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
            if (json_object_object_get_ex(tbs, "subject", &val))
                cert->subject = strdup(json_object_get_string(val));
            if (json_object_object_get_ex(tbs, "not_before", &val))
                cert->not_before = json_object_get_double(val);
            if (json_object_object_get_ex(tbs, "not_after", &val))
                cert->not_after = json_object_get_double(val);
            {
                struct json_object *ext_obj;
                if (json_object_object_get_ex(tbs, "extensions", &ext_obj))
                    cert->extensions_json =
                        strdup(json_object_to_json_string(ext_obj));
            }
        }
        if (json_object_object_get_ex(sc, "trust_anchor_id", &val))
            cert->trust_anchor_id = strdup(json_object_get_string(val));
    }

    cert->has_landmark =
        json_object_object_get_ex(resp, "landmark_certificate", &val);
    mtc_store_dir_path(path, sizeof(path), store, subject);
    cert->local_path = strdup(path);

    json_object_put(resp);
    return cert;
}

/* ----------------------------------------------------------------------- */
/* MTC_Verify — independent client-side verification                       */
/* ----------------------------------------------------------------------- */

/* RFC 9162 Section 2.1: HASH(0x00 || data) */
static void mtc_hash_leaf(const uint8_t *data, int dataSz, uint8_t out[32])
{
    wc_Sha256 sha;
    uint8_t prefix = 0x00;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, data, (word32)dataSz);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

/* RFC 9162 Section 2.1: HASH(0x01 || left || right) */
static void mtc_hash_node(const uint8_t left[32], const uint8_t right[32],
                          uint8_t out[32])
{
    wc_Sha256 sha;
    uint8_t prefix = 0x01;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &prefix, 1);
    wc_Sha256Update(&sha, left, 32);
    wc_Sha256Update(&sha, right, 32);
    wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
}

/* Verify inclusion proof: hash chain from leaf to subtree root.
 * Returns 1 if valid, 0 if not. */
static int mtc_verify_inclusion(const uint8_t entry_hash[32], int index,
                                int start, int end,
                                struct json_object *proof_arr,
                                const uint8_t expected_root[32])
{
    int fn, sn, i, proof_len;
    uint8_t r[32], p[32];

    proof_len = (int)json_object_array_length(proof_arr);
    XMEMCPY(r, entry_hash, 32);

    fn = index - start;
    sn = end - start - 1;

    for (i = 0; i < proof_len; i++) {
        const char *hex = json_object_get_string(
            json_object_array_get_idx(proof_arr, i));
        int j;
        if (!hex || (int)strlen(hex) < 64) return 0;
        for (j = 0; j < 32; j++) {
            unsigned int b;
            sscanf(hex + j * 2, "%2x", &b);
            p[j] = (uint8_t)b;
        }

        if (sn == 0) return 0;
        if ((fn & 1) || fn == sn) {
            mtc_hash_node(p, r, r);
            while (fn > 0 && !(fn & 1)) {
                fn >>= 1;
                sn >>= 1;
            }
        }
        else {
            mtc_hash_node(r, p, r);
        }
        fn >>= 1;
        sn >>= 1;
    }

    return (sn == 0 && XMEMCMP(r, expected_root, 32) == 0);
}

/* Verify Ed25519 cosignature over a subtree.
 * Returns 1 if valid, 0 if not. */
static int mtc_verify_cosig(const uint8_t *ca_pub_key, int ca_pub_key_sz,
                            const char *cosigner_id, const char *log_id,
                            int start, int end,
                            const uint8_t subtree_hash[32],
                            const uint8_t *sig, int sig_sz)
{
    ed25519_key key;
    int ret, verified = 0;
    /* Build MTCSubtreeSignatureInput */
    uint8_t sig_input[512];
    int si_len = 0;
    uint8_t be8[8];

    XMEMCPY(sig_input + si_len, "mtc-subtree/v1\n\x00", 16);
    si_len += 16;
    XMEMCPY(sig_input + si_len, cosigner_id, strlen(cosigner_id));
    si_len += (int)strlen(cosigner_id);
    XMEMCPY(sig_input + si_len, log_id, strlen(log_id));
    si_len += (int)strlen(log_id);

    /* start as 8-byte big-endian */
    XMEMSET(be8, 0, 8);
    be8[4] = (uint8_t)((start >> 24) & 0xFF);
    be8[5] = (uint8_t)((start >> 16) & 0xFF);
    be8[6] = (uint8_t)((start >> 8) & 0xFF);
    be8[7] = (uint8_t)(start & 0xFF);
    XMEMCPY(sig_input + si_len, be8, 8);
    si_len += 8;

    /* end as 8-byte big-endian */
    XMEMSET(be8, 0, 8);
    be8[4] = (uint8_t)((end >> 24) & 0xFF);
    be8[5] = (uint8_t)((end >> 16) & 0xFF);
    be8[6] = (uint8_t)((end >> 8) & 0xFF);
    be8[7] = (uint8_t)(end & 0xFF);
    XMEMCPY(sig_input + si_len, be8, 8);
    si_len += 8;

    XMEMCPY(sig_input + si_len, subtree_hash, 32);
    si_len += 32;

    ret = wc_ed25519_init(&key);
    if (ret != 0) return 0;

    ret = wc_ed25519_import_public(ca_pub_key, (word32)ca_pub_key_sz, &key);
    if (ret != 0) {
        wc_ed25519_free(&key);
        return 0;
    }

    ret = wc_ed25519_verify_msg(sig, (word32)sig_sz, sig_input, (word32)si_len,
                                &verified, &key);
    wc_ed25519_free(&key);

    return (ret == 0 && verified);
}

/* Parse a hex string into bytes. Returns byte count, or -1 on error. */
static int mtc_hex_to_bytes(const char *hex, uint8_t *out, int max_out)
{
    int i, len;
    if (hex == NULL) return -1;
    len = (int)strlen(hex);
    if (len % 2 != 0) return -1;  /* odd length */
    len /= 2;
    if (len > max_out) return -1;  /* too large */
    for (i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
            return -1;  /* non-hex character */
        out[i] = (uint8_t)b;
    }
    return len;
}

/* Fetch and cache the CA Ed25519 public key. Returns key size or 0 on failure. */
static int mtc_ensure_ca_pubkey(mtc_conn_t *conn)
{
    struct json_object *ca_info, *pk_val;

    if (conn->ca_pub_key_sz > 0)
        return conn->ca_pub_key_sz; /* already cached */

    ca_info = mtc_http_get(conn, "/ca/public-key");
    if (!ca_info) return 0;

    if (json_object_object_get_ex(ca_info, "public_key_raw_hex", &pk_val)) {
        const char *hex = json_object_get_string(pk_val);
        int key_bytes = (int)strlen(hex) / 2;
        if (key_bytes > (int)sizeof(conn->ca_pub_key)) {
            mtc_set_error("CA public key too large (%d bytes, max %d)",
                          key_bytes, (int)sizeof(conn->ca_pub_key));
            json_object_put(ca_info);
            return 0;
        }
        conn->ca_pub_key_sz = mtc_hex_to_bytes(hex, conn->ca_pub_key,
            (int)sizeof(conn->ca_pub_key));
    }
    json_object_put(ca_info);
    return conn->ca_pub_key_sz;
}

mtc_verify_t *MTC_Verify(mtc_conn_t *conn, int index) {
    char path[256];
    struct json_object *cert_json, *val, *sc, *tbs;
    mtc_verify_t *result;

    result = (mtc_verify_t*)calloc(1, sizeof(*result));
    result->index = index;
    result->landmark_valid = -1;

    /* Fetch the full certificate (includes proof + cosignatures) */
    XSNPRINTF(path, sizeof(path), "/certificate/%d", index);
    cert_json = mtc_http_get(conn, path);
    if (!cert_json) {
        result->error = strdup("failed to fetch certificate");
        return result;
    }

    if (!json_object_object_get_ex(cert_json, "standalone_certificate", &sc)) {
        result->error = strdup("no standalone_certificate in response");
        json_object_put(cert_json);
        return result;
    }

    if (!json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        result->error = strdup("no tbs_entry in standalone_certificate");
        json_object_put(cert_json);
        return result;
    }

    /* Extract subject */
    if (json_object_object_get_ex(tbs, "subject", &val))
        result->subject = strdup(json_object_get_string(val));

    /* 1. Reconstruct entry hash from TBS data */
    {
        struct json_object *ext_obj = NULL;
        const char *tbs_str;
        struct json_object *tbs_rebuild = json_object_new_object();
        uint8_t entry_hash[32];

        json_object_object_add(tbs_rebuild, "extensions",
            json_object_object_get_ex(tbs, "extensions", &ext_obj) ?
                json_object_get(ext_obj) : json_object_new_object());
        if (json_object_object_get_ex(tbs, "not_after", &val))
            json_object_object_add(tbs_rebuild, "not_after",
                json_object_get(val));
        if (json_object_object_get_ex(tbs, "not_before", &val))
            json_object_object_add(tbs_rebuild, "not_before",
                json_object_get(val));
        if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
            json_object_object_add(tbs_rebuild, "spk_algorithm",
                json_object_get(val));
        if (json_object_object_get_ex(tbs, "subject_public_key_hash", &val))
            json_object_object_add(tbs_rebuild, "spk_hash",
                json_object_get(val));
        if (json_object_object_get_ex(tbs, "subject", &val))
            json_object_object_add(tbs_rebuild, "subject",
                json_object_get(val));

        tbs_str = json_object_to_json_string_ext(tbs_rebuild,
            JSON_C_TO_STRING_PLAIN);

        /* entry_data = 0x01 || tbs_serialized */
        {
            int tbs_len = (int)strlen(tbs_str);
            uint8_t *entry_data = (uint8_t*)malloc((size_t)(1 + tbs_len));
            entry_data[0] = 0x01;
            XMEMCPY(entry_data + 1, tbs_str, (size_t)tbs_len);
            mtc_hash_leaf(entry_data, 1 + tbs_len, entry_hash);
            free(entry_data);
        }
        json_object_put(tbs_rebuild);

        /* 2. Verify inclusion proof */
        {
            struct json_object *proof_arr, *root_val;
            int sub_start = 0, sub_end = 0;
            uint8_t expected_root[32];

            if (json_object_object_get_ex(sc, "inclusion_proof", &proof_arr) &&
                json_object_object_get_ex(sc, "subtree_hash", &root_val) &&
                json_object_object_get_ex(sc, "subtree_start", &val)) {
                sub_start = json_object_get_int(val);
                if (json_object_object_get_ex(sc, "subtree_end", &val))
                    sub_end = json_object_get_int(val);

                mtc_hex_to_bytes(json_object_get_string(root_val),
                             expected_root, 32);

                result->inclusion_proof = mtc_verify_inclusion(
                    entry_hash, index, sub_start, sub_end,
                    proof_arr, expected_root);
            }
        }

        /* 3. Verify cosignature(s) using cached CA public key */
        {
            struct json_object *cosigs;
            if (json_object_object_get_ex(sc, "cosignatures", &cosigs) &&
                json_object_array_length(cosigs) > 0 &&
                mtc_ensure_ca_pubkey(conn) > 0) {

                int all_valid = 1;
                int ci;
                for (ci = 0; ci < (int)json_object_array_length(cosigs);
                     ci++) {
                    struct json_object *cosig =
                        json_object_array_get_idx(cosigs, ci);
                    struct json_object *cv;
                    const char *cid = "", *lid = "";
                    int cs = 0, ce = 0;
                    uint8_t sub_hash[32], sig_bytes[64];
                    int sig_len;

                    if (json_object_object_get_ex(cosig,
                            "cosigner_id", &cv))
                        cid = json_object_get_string(cv);
                    if (json_object_object_get_ex(cosig, "log_id", &cv))
                        lid = json_object_get_string(cv);
                    if (json_object_object_get_ex(cosig, "start", &cv))
                        cs = json_object_get_int(cv);
                    if (json_object_object_get_ex(cosig, "end", &cv))
                        ce = json_object_get_int(cv);
                    if (json_object_object_get_ex(cosig,
                            "subtree_hash", &cv))
                        mtc_hex_to_bytes(json_object_get_string(cv),
                                         sub_hash, 32);
                    if (json_object_object_get_ex(cosig,
                            "signature", &cv))
                        sig_len = mtc_hex_to_bytes(
                            json_object_get_string(cv), sig_bytes, 64);
                    else
                        sig_len = 0;

                    if (!mtc_verify_cosig(conn->ca_pub_key,
                            conn->ca_pub_key_sz, cid, lid,
                            cs, ce, sub_hash, sig_bytes, sig_len))
                        all_valid = 0;
                }
                result->cosignature_valid = all_valid;
            }
        }
    }

    /* 4. Check expiry */
    {
        double now, nb = 0, na = 0;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
        if (json_object_object_get_ex(tbs, "not_before", &val))
            nb = json_object_get_double(val);
        if (json_object_object_get_ex(tbs, "not_after", &val))
            na = json_object_get_double(val);
        result->not_expired = ((nb - 1.0) <= now && now <= (na + 1.0));
    }

    result->valid = result->inclusion_proof && result->cosignature_valid &&
                    result->not_expired;

    json_object_put(cert_json);
    return result;
}

/* ----------------------------------------------------------------------- */
/* MTC_Find                                                                */
/* ----------------------------------------------------------------------- */

mtc_find_results_t *MTC_Find(mtc_conn_t *conn, const char *query) {
    char path[512];
    struct json_object *resp, *arr;
    mtc_find_results_t *out;

    XSNPRINTF(path, sizeof(path), "/certificate/search?q=%s", query);
    resp = mtc_http_get(conn, path);
    if (!resp) return NULL;

    out = (mtc_find_results_t*)calloc(1, sizeof(*out));
    if (json_object_object_get_ex(resp, "results", &arr)) {
        int i;
        out->count = (int)json_object_array_length(arr);
        out->results = (mtc_find_result_t*)calloc((size_t)out->count,
            sizeof(*out->results));
        for (i = 0; i < out->count; i++) {
            struct json_object *item = json_object_array_get_idx(arr, i);
            struct json_object *val;
            if (json_object_object_get_ex(item, "index", &val))
                out->results[i].index = json_object_get_int(val);
            if (json_object_object_get_ex(item, "subject", &val))
                out->results[i].subject = strdup(json_object_get_string(val));
        }
    }
    json_object_put(resp);
    return out;
}

/* ----------------------------------------------------------------------- */
/* MTC_Status                                                              */
/* ----------------------------------------------------------------------- */

mtc_status_t *MTC_Status(mtc_conn_t *conn) {
    struct json_object *log, *val, *lm;
    mtc_status_t *s;

    log = mtc_http_get(conn, "/log");
    if (!log) return NULL;

    s = (mtc_status_t*)calloc(1, sizeof(*s));
    s->server_url = strdup(conn->server_url);
    s->ca_name = conn->ca_name ? strdup(conn->ca_name) : NULL;
    s->log_id = conn->log_id ? strdup(conn->log_id) : NULL;

    if (json_object_object_get_ex(log, "tree_size", &val))
        s->tree_size = json_object_get_int(val);
    if (json_object_object_get_ex(log, "root_hash", &val))
        s->root_hash = strdup(json_object_get_string(val));
    if (json_object_object_get_ex(log, "landmarks", &lm))
        s->landmark_count = (int)json_object_array_length(lm);

    json_object_put(log);
    return s;
}

/* ----------------------------------------------------------------------- */
/* MTC_Revoke (placeholder)                                                */
/* ----------------------------------------------------------------------- */

int MTC_Revoke(mtc_conn_t *conn, int index) {
    (void)conn;
    (void)index;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Memory management                                                       */
/* ----------------------------------------------------------------------- */

void MTC_Free_Cert(mtc_cert_t *cert) {
    if (!cert) return;
    free(cert->subject);
    free(cert->trust_anchor_id);
    free(cert->extensions_json);
    free(cert->local_path);
    free(cert);
}

void MTC_Free_Verify(mtc_verify_t *result) {
    if (!result) return;
    free(result->subject);
    free(result->error);
    free(result);
}

void MTC_Free_Find(mtc_find_results_t *results) {
    if (!results) return;
    {
        int i;
        for (i = 0; i < results->count; i++)
            free(results->results[i].subject);
    }
    free(results->results);
    free(results);
}

void MTC_Free_Status(mtc_status_t *status) {
    if (!status) return;
    free(status->server_url);
    free(status->ca_name);
    free(status->log_id);
    free(status->root_hash);
    free(status);
}

/* ----------------------------------------------------------------------- */
/* Extensions builder                                                      */
/* ----------------------------------------------------------------------- */

mtc_extensions_t *MTC_Extensions_New(void) {
    return (mtc_extensions_t*)calloc(1, sizeof(mtc_extensions_t));
}

int MTC_Extensions_Add(mtc_extensions_t *ext, const char *key,
                        const char *value) {
    int n = ext->count + 1;
    ext->keys = (char**)realloc(ext->keys, (size_t)n * sizeof(char*));
    ext->values = (char**)realloc(ext->values, (size_t)n * sizeof(char*));
    ext->keys[ext->count] = strdup(key);
    ext->values[ext->count] = strdup(value);
    ext->count = n;
    return 0;
}

void MTC_Free_Extensions(mtc_extensions_t *ext) {
    if (!ext) return;
    {
        int i;
        for (i = 0; i < ext->count; i++) {
            free(ext->keys[i]);
            free(ext->values[i]);
        }
    }
    free(ext->keys);
    free(ext->values);
    free(ext);
}

/* ----------------------------------------------------------------------- */
/* MTC_Renew                                                               */
/* ----------------------------------------------------------------------- */

mtc_cert_t *MTC_Renew(mtc_conn_t *conn, int index, int validity_days) {
    char path[256];
    struct json_object *cert_json, *sc, *tbs, *val;
    const char *subject = NULL;
    const char *algorithm = "EC-P256";
    mtc_extensions_t *ext = NULL;
    char *subject_copy;
    mtc_cert_t *new_cert;
    const char *store = conn->store_path;

    XSNPRINTF(path, sizeof(path), "/certificate/%d", index);
    cert_json = mtc_http_get(conn, path);
    if (!cert_json) {
        mtc_set_error("certificate %d not found", index);
        return NULL;
    }

    if (json_object_object_get_ex(cert_json, "standalone_certificate", &sc) &&
        json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        if (json_object_object_get_ex(tbs, "subject", &val))
            subject = json_object_get_string(val);
        if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
            algorithm = json_object_get_string(val);

        {
            struct json_object *ext_obj;
            if (json_object_object_get_ex(tbs, "extensions", &ext_obj)) {
                ext = MTC_Extensions_New();
                json_object_object_foreach(ext_obj, key, ext_val) {
                    MTC_Extensions_Add(ext, key,
                        json_object_get_string(ext_val));
                }
            }
        }
    }

    if (!subject) {
        mtc_set_error("could not read subject from certificate %d", index);
        json_object_put(cert_json);
        return NULL;
    }

    /* Archive old files */
    {
        char old_path[512], new_path[512];
        mtc_store_file_path(old_path, sizeof(old_path), store, subject,
            "certificate.json");
        mtc_store_file_path(new_path, sizeof(new_path), store, subject,
            "certificate.json.old");
        rename(old_path, new_path);
        mtc_store_file_path(old_path, sizeof(old_path), store, subject,
            "private_key.pem");
        mtc_store_file_path(new_path, sizeof(new_path), store, subject,
            "private_key.pem.old");
        rename(old_path, new_path);
    }

    subject_copy = strdup(subject);
    json_object_put(cert_json);

    new_cert = MTC_Enroll(conn, subject_copy, algorithm, validity_days, ext);
    free(subject_copy);
    if (ext) MTC_Free_Extensions(ext);
    return new_cert;
}

/* ----------------------------------------------------------------------- */
/* MTC_List (stub)                                                         */
/* ----------------------------------------------------------------------- */

mtc_cert_t **MTC_List(int *count) {
    *count = 0;
    return NULL;
}

/* ----------------------------------------------------------------------- */
/* wolfSSL_CTX_use_MTC_certificate                                         */
/*                                                                         */
/* Load MTC certificate from a ~/.TPM store directory. Reads               */
/* certificate.json, builds X.509 DER with id-alg-mtcProof, and loads     */
/* the cert + key into the WOLFSSL_CTX.                                    */
/* ----------------------------------------------------------------------- */

/* DER encoding helpers */
static int mtc_der_length(int len, byte *out)
{
    if (len < 0x80) {
        out[0] = (byte)len;
        return 1;
    }
    else if (len < 0x100) {
        out[0] = 0x81;
        out[1] = (byte)len;
        return 2;
    }
    else {
        out[0] = 0x82;
        out[1] = (byte)(len >> 8);
        out[2] = (byte)(len & 0xff);
        return 3;
    }
}

/* MTC proof OID: 1.3.6.1.4.1.44363.47.0
 * Encoded: 2b 06 01 04 01 82 da 4b 2f 00 */
static const byte mtcProofOidDer[] = {
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x00
};

/* EC P-256 OID for SubjectPublicKeyInfo */
static const byte ecPubKeyAlgDer[] = {
    0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  /* id-ecPublicKey */
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07  /* P-256 */
};

/* Read an entire file into a malloc'd buffer. Caller frees. */
static byte *mtc_read_file(const char *path, long *outSz)
{
    FILE *f;
    byte *buf;
    long sz;

    f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    buf = (byte *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if ((long)fread(buf, 1, (size_t)sz, f) != sz) {
        fclose(f); free(buf); return NULL;
    }
    buf[sz] = 0;
    fclose(f);
    *outSz = sz;
    return buf;
}

/* Serialize MTC proof from JSON into wire format:
 *   start(8) + end(8) + pathCount(2) + path(N*32) + subtreeHash(32) */
static int mtc_serialize_proof(struct json_object *sc, byte *out, int maxSz)
{
    struct json_object *val, *proof_arr;
    int64_t start_val, end_val;
    int path_count, i, idx = 0;
    const char *hash_hex;

    if (!json_object_object_get_ex(sc, "subtree_start", &val)) return -1;
    start_val = json_object_get_int64(val);

    if (!json_object_object_get_ex(sc, "subtree_end", &val)) return -1;
    end_val = json_object_get_int64(val);

    if (!json_object_object_get_ex(sc, "inclusion_proof", &proof_arr)) return -1;
    path_count = (int)json_object_array_length(proof_arr);

    if (!json_object_object_get_ex(sc, "subtree_hash", &val)) return -1;
    hash_hex = json_object_get_string(val);

    /* Check buffer size: 8 + 8 + 2 + path_count*32 + 32 */
    if (18 + path_count * 32 + 32 > maxSz) return -1;

    /* start (big-endian 64) */
    for (i = 7; i >= 0; i--)
        out[idx++] = (byte)(start_val >> (i * 8));

    /* end (big-endian 64) */
    for (i = 7; i >= 0; i--)
        out[idx++] = (byte)(end_val >> (i * 8));

    /* pathCount (big-endian 16) */
    out[idx++] = (byte)(path_count >> 8);
    out[idx++] = (byte)(path_count & 0xff);

    /* inclusion path hashes */
    for (i = 0; i < path_count; i++) {
        struct json_object *h = json_object_array_get_idx(proof_arr, (size_t)i);
        const char *hex = json_object_get_string(h);
        int j;
        for (j = 0; j < 32 && hex[j*2] && hex[j*2+1]; j++) {
            unsigned int byte_val;
            sscanf(hex + j * 2, "%02x", &byte_val);
            out[idx++] = (byte)byte_val;
        }
    }

    /* subtree hash */
    {
        int j;
        for (j = 0; j < 32 && hash_hex[j*2] && hash_hex[j*2+1]; j++) {
            unsigned int byte_val;
            sscanf(hash_hex + j * 2, "%02x", &byte_val);
            out[idx++] = (byte)byte_val;
        }
    }

    return idx;
}

/* Build a minimal X.509 DER certificate with:
 *   - subject CN from JSON
 *   - EC P-256 public key from the generated key
 *   - signatureAlgorithm = id-alg-mtcProof
 *   - signatureValue = serialized MTC proof
 *
 * Returns malloc'd DER buffer, caller frees. Sets *outSz. */
static byte *mtc_build_cert_der(struct json_object *cert_json,
    const byte *pubKeyDer, int pubKeyDerSz,
    int *outSz)
{
    struct json_object *sc, *tbs, *val;
    const char *subject;
    byte proof[2048];
    int proofSz;
    byte subjectDer[256], spkiDer[256], validityDer[64];
    int subjectDerSz, spkiDerSz, validityDerSz;
    byte tbsDer[4096], certDer[4096];
    int tbsSz, certSz;
    int idx;
    byte lenBuf[4];
    int lenSz;

    *outSz = 0;

    if (!json_object_object_get_ex(cert_json, "standalone_certificate", &sc))
        return NULL;
    if (!json_object_object_get_ex(sc, "tbs_entry", &tbs))
        return NULL;
    if (!json_object_object_get_ex(tbs, "subject", &val))
        return NULL;
    subject = json_object_get_string(val);

    /* Serialize MTC proof */
    proofSz = mtc_serialize_proof(sc, proof, (int)sizeof(proof));
    if (proofSz < 0) return NULL;

    /* Build Subject: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8(subject) } } } */
    {
        int cnLen = (int)strlen(subject);
        byte oid_cn[] = {0x06, 0x03, 0x55, 0x04, 0x03};  /* OID 2.5.4.3 */
        byte utf8Tag = 0x0c;
        int seqInner, setInner;

        idx = 0;
        /* inner SEQUENCE: OID + UTF8STRING */
        seqInner = (int)sizeof(oid_cn) + 1 + 1 + cnLen; /* oid + tag + len + str */
        if (cnLen >= 0x80) return NULL; /* keep it simple */

        /* SET */
        setInner = 1 + 1 + seqInner; /* seq tag + len + content */

        /* outer SEQUENCE (Subject) */
        subjectDer[idx++] = 0x30;
        lenSz = mtc_der_length(1 + 1 + setInner, lenBuf);
        memcpy(subjectDer + idx, lenBuf, lenSz); idx += lenSz;

        /* SET */
        subjectDer[idx++] = 0x31;
        lenSz = mtc_der_length(1 + 1 + seqInner, lenBuf);
        memcpy(subjectDer + idx, lenBuf, lenSz); idx += lenSz;

        /* inner SEQUENCE */
        subjectDer[idx++] = 0x30;
        lenSz = mtc_der_length(seqInner, lenBuf);
        memcpy(subjectDer + idx, lenBuf, lenSz); idx += lenSz;

        /* OID */
        memcpy(subjectDer + idx, oid_cn, sizeof(oid_cn)); idx += sizeof(oid_cn);

        /* UTF8STRING */
        subjectDer[idx++] = utf8Tag;
        subjectDer[idx++] = (byte)cnLen;
        memcpy(subjectDer + idx, subject, cnLen); idx += cnLen;

        subjectDerSz = idx;
    }

    /* Build SubjectPublicKeyInfo */
    {
        /* SEQUENCE { algId, BIT STRING { 0x00, pubkey } } */
        int bitStrInner = 1 + pubKeyDerSz;  /* 0x00 + key bytes */

        idx = 0;
        spkiDer[idx++] = 0x30;
        lenSz = mtc_der_length((int)sizeof(ecPubKeyAlgDer) + 1 + 1 + bitStrInner +
            (bitStrInner >= 0x80 ? 2 : 0), lenBuf);
        /* Recalculate properly */
        {
            int algSz = (int)sizeof(ecPubKeyAlgDer);
            byte bsLenBuf[4];
            int bsLenSz = mtc_der_length(bitStrInner, bsLenBuf);
            int totalInner = algSz + 1 + bsLenSz + bitStrInner;

            idx = 0;
            spkiDer[idx++] = 0x30;
            lenSz = mtc_der_length(totalInner, lenBuf);
            memcpy(spkiDer + idx, lenBuf, lenSz); idx += lenSz;

            memcpy(spkiDer + idx, ecPubKeyAlgDer, algSz); idx += algSz;

            spkiDer[idx++] = 0x03; /* BIT STRING */
            memcpy(spkiDer + idx, bsLenBuf, bsLenSz); idx += bsLenSz;
            spkiDer[idx++] = 0x00; /* 0 unused bits */
            memcpy(spkiDer + idx, pubKeyDer, pubKeyDerSz); idx += pubKeyDerSz;
        }
        spkiDerSz = idx;
    }

    /* Build Validity: SEQUENCE { UTCTime, UTCTime } */
    {
        double nb = 0, na = 0;
        time_t nb_t, na_t;
        struct tm nb_tm, na_tm;
        char nbStr[16], naStr[16];

        if (json_object_object_get_ex(tbs, "not_before", &val))
            nb = json_object_get_double(val);
        if (json_object_object_get_ex(tbs, "not_after", &val))
            na = json_object_get_double(val);

        nb_t = (time_t)nb;
        na_t = (time_t)na;
        gmtime_r(&nb_t, &nb_tm);
        gmtime_r(&na_t, &na_tm);

        snprintf(nbStr, sizeof(nbStr), "%02d%02d%02d%02d%02d%02dZ",
            nb_tm.tm_year % 100, nb_tm.tm_mon + 1, nb_tm.tm_mday,
            nb_tm.tm_hour, nb_tm.tm_min, nb_tm.tm_sec);
        snprintf(naStr, sizeof(naStr), "%02d%02d%02d%02d%02d%02dZ",
            na_tm.tm_year % 100, na_tm.tm_mon + 1, na_tm.tm_mday,
            na_tm.tm_hour, na_tm.tm_min, na_tm.tm_sec);

        idx = 0;
        validityDer[idx++] = 0x30;
        validityDer[idx++] = 2 + 13 + 2 + 13; /* two UTCTime fields */
        validityDer[idx++] = 0x17; validityDer[idx++] = 13;
        memcpy(validityDer + idx, nbStr, 13); idx += 13;
        validityDer[idx++] = 0x17; validityDer[idx++] = 13;
        memcpy(validityDer + idx, naStr, 13); idx += 13;
        validityDerSz = idx;
    }

    /* Build TBSCertificate */
    {
        /* version [0] EXPLICIT INTEGER 2 (v3) */
        byte version[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
        /* serialNumber INTEGER (small random) */
        byte serial[6];
        /* signatureAlgorithm (MTC proof OID) */
        byte sigAlgSeq[2 + sizeof(mtcProofOidDer)];

        serial[0] = 0x02; serial[1] = 0x04;
        {
            WC_RNG rng;
            wc_InitRng(&rng);
            wc_RNG_GenerateBlock(&rng, serial + 2, 4);
            wc_FreeRng(&rng);
            serial[2] &= 0x7f; /* ensure positive */
        }

        /* sigAlg SEQUENCE { OID } */
        sigAlgSeq[0] = 0x30;
        sigAlgSeq[1] = sizeof(mtcProofOidDer);
        memcpy(sigAlgSeq + 2, mtcProofOidDer, sizeof(mtcProofOidDer));

        /* Issuer = same as subject (self-referencing for MTC) */

        /* Assemble TBS */
        {
            int innerSz = (int)sizeof(version) + (int)sizeof(serial) +
                (int)sizeof(sigAlgSeq) + subjectDerSz /* issuer */ +
                validityDerSz + subjectDerSz /* subject */ + spkiDerSz;

            idx = 0;
            tbsDer[idx++] = 0x30;
            lenSz = mtc_der_length(innerSz, lenBuf);
            memcpy(tbsDer + idx, lenBuf, lenSz); idx += lenSz;

            memcpy(tbsDer + idx, version, sizeof(version));
            idx += sizeof(version);
            memcpy(tbsDer + idx, serial, sizeof(serial));
            idx += sizeof(serial);
            memcpy(tbsDer + idx, sigAlgSeq, sizeof(sigAlgSeq));
            idx += sizeof(sigAlgSeq);
            /* Issuer */
            memcpy(tbsDer + idx, subjectDer, subjectDerSz);
            idx += subjectDerSz;
            /* Validity */
            memcpy(tbsDer + idx, validityDer, validityDerSz);
            idx += validityDerSz;
            /* Subject */
            memcpy(tbsDer + idx, subjectDer, subjectDerSz);
            idx += subjectDerSz;
            /* SPKI */
            memcpy(tbsDer + idx, spkiDer, spkiDerSz);
            idx += spkiDerSz;

            tbsSz = idx;
        }
    }

    /* Build Certificate: SEQUENCE { TBS, sigAlg, sigVal } */
    {
        byte sigAlgOuter[2 + sizeof(mtcProofOidDer)];
        byte sigValHdr[4];
        int sigValInner = 1 + proofSz; /* 0x00 unused bits + proof */
        int sigValHdrSz;
        int outerInner;

        sigAlgOuter[0] = 0x30;
        sigAlgOuter[1] = sizeof(mtcProofOidDer);
        memcpy(sigAlgOuter + 2, mtcProofOidDer, sizeof(mtcProofOidDer));

        sigValHdr[0] = 0x03; /* BIT STRING */
        sigValHdrSz = 1 + mtc_der_length(sigValInner, sigValHdr + 1);

        outerInner = tbsSz + (int)sizeof(sigAlgOuter) +
            sigValHdrSz + sigValInner;

        idx = 0;
        certDer[idx++] = 0x30;
        lenSz = mtc_der_length(outerInner, lenBuf);
        memcpy(certDer + idx, lenBuf, lenSz); idx += lenSz;

        memcpy(certDer + idx, tbsDer, tbsSz); idx += tbsSz;
        memcpy(certDer + idx, sigAlgOuter, sizeof(sigAlgOuter));
        idx += sizeof(sigAlgOuter);

        /* signatureValue BIT STRING */
        certDer[idx++] = 0x03;
        {
            int sl = mtc_der_length(sigValInner, lenBuf);
            memcpy(certDer + idx, lenBuf, sl); idx += sl;
        }
        certDer[idx++] = 0x00; /* 0 unused bits */
        memcpy(certDer + idx, proof, proofSz); idx += proofSz;

        certSz = idx;
    }

    {
        byte *result = (byte *)malloc(certSz);
        if (!result) return NULL;
        memcpy(result, certDer, certSz);
        *outSz = certSz;
        return result;
    }
}

int wolfSSL_CTX_use_MTC_certificate(WOLFSSL_CTX* ctx, const char* storePath)
{
    char path[512];
    byte *jsonBuf = NULL, *certDer = NULL;
    long jsonSz = 0;
    int certDerSz = 0;
    struct json_object *cert_json = NULL;
    ecc_key eccKey;
    byte pubDer[256];
    int pubDerSz;
    int ret;

    if (ctx == NULL || storePath == NULL)
        return BAD_FUNC_ARG;

    WOLFSSL_ENTER("wolfSSL_CTX_use_MTC_certificate");

    /* Load private key */
    XSNPRINTF(path, sizeof(path), "%s/private_key.pem", storePath);
    printf("[MTC] loading key: %s\n", path);
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, path, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        printf("[MTC] failed to load private key: %d\n", ret);
        return ret;
    }

    /* Read certificate.json */
    XSNPRINTF(path, sizeof(path), "%s/certificate.json", storePath);
    printf("[MTC] loading cert: %s\n", path);
    jsonBuf = mtc_read_file(path, &jsonSz);
    if (jsonBuf == NULL) {
        printf("[MTC] failed to read certificate.json\n");
        return WOLFSSL_FAILURE;
    }

    cert_json = json_tokener_parse((char*)jsonBuf);
    free(jsonBuf);
    if (cert_json == NULL) {
        printf("[MTC] failed to parse certificate.json\n");
        return WOLFSSL_FAILURE;
    }

    /* Get the EC public key from the loaded private key context.
     * We need to export it for the X.509 cert's SPKI field. */
    {
        WC_RNG rng;
        wc_InitRng(&rng);
        wc_ecc_init(&eccKey);
        /* Generate a fresh key matching what's in the PEM — actually we
         * need the public key from the context. Since we already loaded
         * the private key, extract public from it. */
        wc_ecc_free(&eccKey);
        wc_FreeRng(&rng);
    }

    /* For the SPKI, just use an uncompressed EC point.
     * Read the public_key.pem to get the actual public key. */
    XSNPRINTF(path, sizeof(path), "%s/public_key.pem", storePath);
    {
        byte *pubPem;
        long pubPemSz = 0;
        word32 inOutIdx = 0;

        pubPem = mtc_read_file(path, &pubPemSz);
        if (pubPem == NULL) {
            json_object_put(cert_json);
            printf("[MTC] failed to read public_key.pem\n");
            return WOLFSSL_FAILURE;
        }

        /* Convert PEM to DER */
        pubDerSz = wc_PubKeyPemToDer(pubPem, (int)pubPemSz, pubDer,
            (int)sizeof(pubDer));
        free(pubPem);

        if (pubDerSz < 0) {
            json_object_put(cert_json);
            printf("[MTC] PEM to DER failed: %d\n", pubDerSz);
            return WOLFSSL_FAILURE;
        }

        /* Parse SubjectPublicKeyInfo to extract just the EC point */
        wc_ecc_init(&eccKey);
        ret = wc_EccPublicKeyDecode(pubDer, &inOutIdx, &eccKey,
            (word32)pubDerSz);
        if (ret == 0) {
            /* Export uncompressed point */
            word32 pointSz = sizeof(pubDer);
            ret = wc_ecc_export_x963(&eccKey, pubDer, &pointSz);
            pubDerSz = (int)pointSz;
        }
        wc_ecc_free(&eccKey);

        if (ret != 0) {
            json_object_put(cert_json);
            printf("[MTC] EC key decode failed: %d\n", ret);
            return WOLFSSL_FAILURE;
        }
    }

    /* Build the X.509 DER with MTC proof */
    certDer = mtc_build_cert_der(cert_json, pubDer, pubDerSz, &certDerSz);
    json_object_put(cert_json);

    if (certDer == NULL || certDerSz <= 0) {
        printf("[MTC] failed to build cert DER\n");
        if (certDer) free(certDer);
        return WOLFSSL_FAILURE;
    }

    printf("[MTC] built MTC cert DER: %d bytes\n", certDerSz);

    /* Load the DER cert into the context */
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certDer, certDerSz,
        WOLFSSL_FILETYPE_ASN1);
    free(certDer);

    if (ret != WOLFSSL_SUCCESS) {
        printf("[MTC] failed to load cert: %d\n", ret);
    }
    else {
        printf("[MTC] certificate loaded successfully\n");
    }

    return ret;
}

#endif /* HAVE_MTC_API */
#endif /* HAVE_MTC */
