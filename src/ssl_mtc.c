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
/* MTC_Verify                                                              */
/* ----------------------------------------------------------------------- */

mtc_verify_t *MTC_Verify(mtc_conn_t *conn, int index) {
    char path[256];
    struct json_object *proof, *cert_json, *val, *sc, *tbs;
    mtc_verify_t *result;

    XSNPRINTF(path, sizeof(path), "/log/proof/%d", index);
    proof = mtc_http_get(conn, path);

    result = (mtc_verify_t*)calloc(1, sizeof(*result));
    result->index = index;
    result->landmark_valid = -1;

    if (!proof) {
        result->error = strdup("failed to fetch proof");
        return result;
    }

    if (json_object_object_get_ex(proof, "valid", &val))
        result->inclusion_proof = json_object_get_boolean(val);

    printf("[MTC_Verify] proof response: %s\n",
        json_object_to_json_string_ext(proof, JSON_C_TO_STRING_PRETTY));

    /* Fetch certificate for subject and cosignature check */
    XSNPRINTF(path, sizeof(path), "/certificate/%d", index);
    cert_json = mtc_http_get(conn, path);
    if (cert_json) {
        printf("[MTC_Verify] cert response keys:");
        json_object_object_foreach(cert_json, ckey, cval) {
            printf(" %s", ckey);
            (void)cval;
        }
        printf("\n");

        if (json_object_object_get_ex(cert_json, "standalone_certificate", &sc)) {
            printf("[MTC_Verify] has standalone_certificate\n");
            if (json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
                if (json_object_object_get_ex(tbs, "subject", &val))
                    result->subject = strdup(json_object_get_string(val));
                /* Check expiry */
                {
                    double now, nb = 0, na = 0;
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
                    if (json_object_object_get_ex(tbs, "not_before", &val))
                        nb = json_object_get_double(val);
                    if (json_object_object_get_ex(tbs, "not_after", &val))
                        na = json_object_get_double(val);
                    printf("[MTC_Verify] not_before=%.3f not_after=%.3f now=%.3f\n",
                           nb, na, now);
                    result->not_expired =
                        ((nb - 1.0) <= now && now <= (na + 1.0));
                    printf("[MTC_Verify] not_expired=%d\n", result->not_expired);
                }
            }
            else {
                printf("[MTC_Verify] no tbs_entry in standalone_certificate\n");
            }
            /* Cosignature presence check */
            {
                struct json_object *cosigs;
                if (json_object_object_get_ex(sc, "cosignatures", &cosigs)) {
                    printf("[MTC_Verify] cosignatures count: %zu\n",
                           json_object_array_length(cosigs));
                    result->cosignature_valid =
                        (json_object_array_length(cosigs) > 0);
                }
                else {
                    printf("[MTC_Verify] no cosignatures field\n");
                }
            }
        }
        else {
            printf("[MTC_Verify] no standalone_certificate in response\n");
        }
        json_object_put(cert_json);
    }
    else {
        printf("[MTC_Verify] failed to fetch certificate\n");
    }

    result->valid = result->inclusion_proof && result->cosignature_valid &&
                    result->not_expired;

    json_object_put(proof);
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

#endif /* HAVE_MTC_API */
#endif /* HAVE_MTC */
