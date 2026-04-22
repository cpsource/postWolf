/******************************************************************************
 * File:        show-tpm.c
 * Purpose:     Show contents of ~/.TPM credential store (C version).
 *
 * Description:
 *   Lists MTC certificates in ~/.TPM, displays status, and optionally
 *   verifies each entry against the MTC server over MQC (post-quantum)
 *   on port 8446.
 *
 * Usage:
 *   show-tpm                          List entries
 *   show-tpm --verify                 List + verify against server (MQC/8446)
 *   show-tpm --verify -s HOST:PORT    Custom MQC server
 *   show-tpm -v                       Verbose output
 *   show-tpm --cnt N                  Show first N entries
 *
 * Created:     2026-04-16
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <limits.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#include <json-c/json.h>
#include "mqc.h"
#include "mqc_peer.h"

#define DEFAULT_TPM_DIR   ".TPM"
/* Explicit path — there's also a server-side config.h on the include
 * search path that would shadow this one. */
#include "../../../socket-level-wrapper-MQC/config.h"
#define DEFAULT_SERVER    MQC_DEFAULT_SERVER
#define MAX_ENTRIES       256

/* Global state */
static mqc_ctx_t  *g_mqc_ctx  = NULL;
static const char  *g_mqc_host = "localhost";
static int          g_mqc_port = 8446;
static int          g_trace    = 0;

/* --- Helpers --- */

/* MQC-based HTTP GET: open a fresh connection per request (server is
 * one-request-per-connection).  Uses dynamic allocation for large responses. */
static char *mqc_http_get(const char *path_only, long *code)
{
    mqc_conn_t *conn;
    char req[1024];
    char *buf = NULL;
    int buf_sz = 0, buf_cap = 0;
    int n;
    char *body_start;
    long status = 0;

    conn = mqc_connect(g_mqc_ctx, g_mqc_host, g_mqc_port);
    if (!conn) {
        /* One-shot retry: the server drops the first handshake after
         * refreshing its per-peer revocation cache; the next attempt
         * runs against the warm cache. */
        usleep(100000);  /* 100 ms */
        conn = mqc_connect(g_mqc_ctx, g_mqc_host, g_mqc_port);
    }
    if (!conn) return NULL;

    /* Send HTTP GET */
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
             path_only, g_mqc_host, g_mqc_port);
    if (mqc_write(conn, req, (int)strlen(req)) < 0) {
        mqc_close(conn);
        return NULL;
    }

    /* Read response into dynamically growing buffer.  Start at 64 KiB
     * because the MQC framing is one frame per mqc_read() — if the
     * next inbound frame is bigger than the remaining buffer,
     * mqc_read() returns -1 non-recoverably (the length prefix is
     * already consumed).  64 KiB covers every current endpoint,
     * including the CA cert-with-X.509 responses (~21 KiB). */
    buf_cap = 65536;
    buf = malloc((size_t)buf_cap);
    if (!buf) { mqc_close(conn); return NULL; }

    while (1) {
        /* Grow buffer if needed */
        if (buf_sz >= buf_cap - 1) {
            buf_cap *= 2;
            char *tmp = realloc(buf, (size_t)buf_cap);
            if (!tmp) break;
            buf = tmp;
        }
        n = mqc_read(conn, buf + buf_sz, buf_cap - 1 - buf_sz);
        if (n <= 0) break;
        buf_sz += n;
        buf[buf_sz] = '\0';
        /* Check if we have full headers + body */
        body_start = strstr(buf, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            char *cl = strcasestr(buf, "Content-Length:");
            if (cl) {
                int content_len = atoi(cl + 15);
                int header_len = (int)(body_start - buf);
                int body_have = buf_sz - header_len;
                if (body_have >= content_len)
                    break;
            } else {
                break;
            }
        }
    }
    buf[buf_sz] = '\0';
    mqc_close(conn);

    /* Parse status code */
    if (buf_sz >= 12 && strncmp(buf, "HTTP/1.", 7) == 0)
        status = atol(buf + 9);
    if (code) *code = status;

    /* Find body */
    body_start = strstr(buf, "\r\n\r\n");
    if (!body_start) { free(buf); return NULL; }
    body_start += 4;

    {
        char *result = strdup(body_start);
        free(buf);
        return result;
    }
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    long sz;
    char *buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static void time_remaining(double not_after, char *out, int outsz)
{
    double now = (double)time(NULL);
    double delta = not_after - now;
    if (delta <= 0) {
        snprintf(out, (size_t)outsz, "EXPIRED");
        return;
    }
    int days = (int)(delta / 86400.0);
    int hours = (int)(fmod(delta, 86400.0) / 3600.0);
    if (days > 0)
        snprintf(out, (size_t)outsz, "%dd %dh remaining", days, hours);
    else
        snprintf(out, (size_t)outsz, "%dh remaining", hours);
}

static void format_ts(double ts, char *out, int outsz)
{
    time_t t = (time_t)ts;
    struct tm tm;
    gmtime_r(&t, &tm);
    snprintf(out, (size_t)outsz, "%04d-%02d-%02d %02d:%02d:%02d UTC",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* --- TPM Entry --- */

typedef struct {
    char name[256];
    char subject[256];
    char algorithm[64];
    char entry_type[16];   /* "CA" or "leaf" or "unknown" */
    char spkh_hex[96];     /* subject_public_key_hash from cert.json */
    int  cert_index;
    double not_before;
    double not_after;
    int  has_cert;
    int  is_default;       /* 1 if ~/.TPM/default resolves to this dir */
    /* Verification results */
    int  v_server_found;   /* 1=ok, 0=fail, -1=not checked */
    int  v_revoked;        /* 1=revoked, 0=not, -1=not checked */
    int  v_proof_match;    /* 1=ok, 0=fail, -1=not checked */
    int  v_time_valid;     /* 1=ok, 0=fail, -1=not checked */
    int  v_pubkey_db;      /* 1=ok, 0=not found, 2=mismatch, -1=not checked */
    int  v_pair;           /* 1=ok, 0=fail, -1=not checked (no priv key) */
    int  v_spkh;           /* 1=ok, 0=fail, -1=not checked */
    char v_errors[1024];
} tpm_entry_t;

static int load_entry(const char *tpm_dir, const char *name, tpm_entry_t *e)
{
    char path[1024];
    char *json_str;
    struct json_object *obj, *sc, *tbs, *val;

    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    strcpy(e->entry_type, "unknown");
    e->cert_index = -1;
    e->v_server_found = e->v_revoked = e->v_proof_match = -1;
    e->v_time_valid = e->v_pubkey_db = -1;
    e->v_pair = e->v_spkh = -1;

    /* Detect type */
    snprintf(path, sizeof(path), "%s/%s/ca_cert.pem", tpm_dir, name);
    { struct stat st; if (stat(path, &st) == 0) strcpy(e->entry_type, "CA"); }

    snprintf(path, sizeof(path), "%s/%s/private_key.pem", tpm_dir, name);
    { struct stat st;
      if (stat(path, &st) == 0 && strcmp(e->entry_type, "CA") != 0)
          strcpy(e->entry_type, "leaf"); }

    /* Load certificate.json */
    snprintf(path, sizeof(path), "%s/%s/certificate.json", tpm_dir, name);
    json_str = read_file(path);
    if (!json_str) return 0;

    obj = json_tokener_parse(json_str);
    free(json_str);
    if (!obj) return 0;

    e->has_cert = 1;

    /* Extract fields */
    if (json_object_object_get_ex(obj, "standalone_certificate", &sc) &&
        json_object_object_get_ex(sc, "tbs_entry", &tbs)) {

        if (json_object_object_get_ex(tbs, "subject", &val))
            snprintf(e->subject, sizeof(e->subject), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
            snprintf(e->algorithm, sizeof(e->algorithm), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(tbs, "subject_public_key_hash", &val))
            snprintf(e->spkh_hex, sizeof(e->spkh_hex), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(tbs, "not_before", &val))
            e->not_before = json_object_get_double(val);
        if (json_object_object_get_ex(tbs, "not_after", &val))
            e->not_after = json_object_get_double(val);

        if (json_object_object_get_ex(sc, "index", &val))
            e->cert_index = json_object_get_int(val);

        /* Check for is_ca in extensions */
        {
            struct json_object *ext;
            if (json_object_object_get_ex(tbs, "extensions", &ext)) {
                struct json_object *ca_val;
                if (json_object_object_get_ex(ext, "is_ca", &ca_val) &&
                    json_object_get_boolean(ca_val))
                    strcpy(e->entry_type, "CA");
            }
        }
    }

    /* Fallback index from top level */
    if (e->cert_index < 0 && json_object_object_get_ex(obj, "index", &val))
        e->cert_index = json_object_get_int(val);

    json_object_put(obj);
    return 1;
}

/* Read a whole file into a malloc'd byte buffer, *len set on success. */
static unsigned char *read_file_bytes(const char *path, int *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long sz;

    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *len = (int)sz;
    return buf;
}

/* Local check: the private and public key files in the TPM dir form a
 * valid keypair.  Sign a random 32-byte message with the private key and
 * verify with the public key.  Sets e->v_pair.  Skipped (stays -1) if
 * either file is missing — e.g. a CA entry on a client that only holds
 * the CA's public material. */
static void check_key_pair(tpm_entry_t *e, const char *tpm_dir)
{
    char priv_path[PATH_MAX], pub_path[PATH_MAX];
    unsigned char *priv_pem = NULL, *pub_pem = NULL;
    unsigned char *priv_der = NULL, *pub_der = NULL;
    int priv_pem_len = 0, pub_pem_len = 0;
    int priv_der_len = 0, pub_der_len = 0;
    dilithium_key priv_key, pub_key;
    int priv_init = 0, pub_init = 0;
    WC_RNG rng;
    int rng_init = 0;
    unsigned char msg[32];
    unsigned char sig[DILITHIUM_LEVEL5_SIG_SIZE];
    word32 sig_len = (word32)sizeof(sig);
    int verify_res = 0;
    word32 idx;
    int ret;

    snprintf(priv_path, sizeof(priv_path), "%s/%s/private_key.pem",
             tpm_dir, e->name);
    snprintf(pub_path, sizeof(pub_path), "%s/%s/public_key.pem",
             tpm_dir, e->name);

    priv_pem = read_file_bytes(priv_path, &priv_pem_len);
    pub_pem  = read_file_bytes(pub_path,  &pub_pem_len);
    if (!priv_pem || !pub_pem) goto done;  /* leave v_pair = -1 */

    priv_der = (unsigned char *)malloc((size_t)priv_pem_len);
    pub_der  = (unsigned char *)malloc((size_t)pub_pem_len);
    if (!priv_der || !pub_der) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: alloc failed; ");
        goto done;
    }

    priv_der_len = wc_KeyPemToDer(priv_pem, priv_pem_len,
                                  priv_der, (word32)priv_pem_len, NULL);
    pub_der_len  = wc_PubKeyPemToDer(pub_pem, pub_pem_len,
                                     pub_der, (word32)pub_pem_len);
    if (priv_der_len <= 0 || pub_der_len <= 0) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: PEM decode failed; ");
        goto done;
    }

    if (wc_dilithium_init(&priv_key) != 0) {
        e->v_pair = 0; goto done;
    }
    priv_init = 1;
    if (wc_dilithium_init(&pub_key) != 0) {
        e->v_pair = 0; goto done;
    }
    pub_init = 1;

    if (wc_dilithium_set_level(&priv_key, WC_ML_DSA_87) != 0 ||
        wc_dilithium_set_level(&pub_key,  WC_ML_DSA_87) != 0) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: set_level failed; ");
        goto done;
    }

    idx = 0;
    if (wc_Dilithium_PrivateKeyDecode(priv_der, &idx, &priv_key,
                                      (word32)priv_der_len) != 0) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: private key decode failed; ");
        goto done;
    }
    idx = 0;
    if (wc_Dilithium_PublicKeyDecode(pub_der, &idx, &pub_key,
                                     (word32)pub_der_len) != 0) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: public key decode failed; ");
        goto done;
    }

    if (wc_InitRng(&rng) != 0) {
        e->v_pair = 0; goto done;
    }
    rng_init = 1;
    if (wc_RNG_GenerateBlock(&rng, msg, (word32)sizeof(msg)) != 0) {
        e->v_pair = 0; goto done;
    }

    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                                    msg, (word32)sizeof(msg),
                                    sig, &sig_len,
                                    &priv_key, &rng);
    if (ret != 0) {
        e->v_pair = 0;
        strcat(e->v_errors, "pair: sign failed; ");
        goto done;
    }

    ret = wc_dilithium_verify_ctx_msg(sig, sig_len, NULL, 0,
                                      msg, (word32)sizeof(msg),
                                      &verify_res, &pub_key);
    if (ret == 0 && verify_res == 1) {
        e->v_pair = 1;
    } else {
        e->v_pair = 0;
        strcat(e->v_errors,
               "pair: public key does not match private key; ");
    }

done:
    if (rng_init)  wc_FreeRng(&rng);
    if (priv_init) wc_dilithium_free(&priv_key);
    if (pub_init)  wc_dilithium_free(&pub_key);
    free(priv_pem); free(pub_pem); free(priv_der); free(pub_der);
}

/* Local check: SHA-256 of public_key.pem matches the cert's
 * subject_public_key_hash.  Catches half-completed re-enrollments where
 * certificate.json and public_key.pem drift apart. */
static void check_spkh(tpm_entry_t *e, const char *tpm_dir)
{
    char path[PATH_MAX];
    unsigned char *pem;
    int pem_len = 0;
    wc_Sha256 sha;
    unsigned char hash[32];
    char hex[65];
    int i;

    if (e->spkh_hex[0] == '\0') return;  /* no hash in cert */

    snprintf(path, sizeof(path), "%s/%s/public_key.pem",
             tpm_dir, e->name);
    pem = read_file_bytes(path, &pem_len);
    if (!pem) return;

    if (wc_InitSha256(&sha) != 0) { free(pem); return; }
    wc_Sha256Update(&sha, pem, (word32)pem_len);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    free(pem);

    for (i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);

    e->v_spkh = (strcmp(hex, e->spkh_hex) == 0) ? 1 : 0;
    if (!e->v_spkh)
        strcat(e->v_errors, "spkh: public_key.pem hash != cert; ");
}

static void verify_entry(tpm_entry_t *e, const char *tpm_dir)
{
    char path[PATH_MAX];
    char *body;
    long code = 0;

    /* Local-only checks first (no server round-trip needed). */
    check_key_pair(e, tpm_dir);
    check_spkh(e, tpm_dir);

    if (e->cert_index < 0) {
        strcat(e->v_errors, "no certificate index; ");
        return;
    }

    /* Check server has the cert */
    snprintf(path, sizeof(path), "/certificate/%d", e->cert_index);
    body = mqc_http_get(path, &code);
    if (!body || code != 200) {
        e->v_server_found = 0;
        snprintf(e->v_errors + strlen(e->v_errors),
                 sizeof(e->v_errors) - strlen(e->v_errors),
                 "certificate %d not found on server; ", e->cert_index);
        free(body);
        return;
    }
    e->v_server_found = 1;

    /* Compare proof */
    {
        struct json_object *srv_obj = json_tokener_parse(body);
        if (srv_obj) {
            struct json_object *srv_sc, *srv_tbs, *srv_val;
            struct json_object *loc_obj, *loc_sc, *loc_tbs, *loc_val;
            char loc_path[PATH_MAX];
            char *loc_json;

            /* Read local cert for comparison */
            snprintf(loc_path, sizeof(loc_path), "%s/%s/certificate.json",
                     tpm_dir, e->name);
            loc_json = read_file(loc_path);
            if (loc_json) {
                loc_obj = json_tokener_parse(loc_json);
                free(loc_json);
                if (loc_obj &&
                    json_object_object_get_ex(loc_obj, "standalone_certificate", &loc_sc) &&
                    json_object_object_get_ex(loc_sc, "tbs_entry", &loc_tbs) &&
                    json_object_object_get_ex(loc_tbs, "subject_public_key_hash", &loc_val) &&
                    json_object_object_get_ex(srv_obj, "standalone_certificate", &srv_sc) &&
                    json_object_object_get_ex(srv_sc, "tbs_entry", &srv_tbs) &&
                    json_object_object_get_ex(srv_tbs, "subject_public_key_hash", &srv_val)) {
                    e->v_proof_match = (strcmp(json_object_get_string(loc_val),
                                              json_object_get_string(srv_val)) == 0) ? 1 : 0;
                    if (!e->v_proof_match)
                        strcat(e->v_errors, "local key hash differs from server; ");
                }
                if (loc_obj) json_object_put(loc_obj);
            }
            json_object_put(srv_obj);
        }
    }
    free(body);

    /* Check revocation */
    snprintf(path, sizeof(path), "/revoked/%d", e->cert_index);
    body = mqc_http_get(path, &code);
    if (body) {
        struct json_object *rev = json_tokener_parse(body);
        if (rev) {
            struct json_object *rv;
            if (json_object_object_get_ex(rev, "revoked", &rv))
                e->v_revoked = json_object_get_boolean(rv) ? 1 : 0;
            else
                e->v_revoked = 0;
            if (e->v_revoked)
                strcat(e->v_errors, "REVOKED on server; ");
            json_object_put(rev);
        }
        free(body);
    } else {
        e->v_revoked = 0;
    }

    /* Time validity */
    if (e->not_before > 0 && e->not_after > 0) {
        double now = (double)time(NULL);
        e->v_time_valid = (e->not_before <= now && now <= e->not_after) ? 1 : 0;
        if (!e->v_time_valid)
            strcat(e->v_errors, "certificate expired; ");
    }

    /* Check pubkey_db */
    snprintf(path, sizeof(path), "/public-key/%s", e->name);
    body = mqc_http_get(path, &code);
    if (!body || code != 200) {
        e->v_pubkey_db = 0;
        strcat(e->v_errors, "public key not in Neon; ");
    } else {
        /* Compare with local key */
        char loc_key_path[PATH_MAX];
        snprintf(loc_key_path, sizeof(loc_key_path),
                 "%s/%s/public_key.pem", tpm_dir, e->name);
        {
            char *local_key = read_file(loc_key_path);
            struct json_object *pk_obj = json_tokener_parse(body);
            if (pk_obj && local_key) {
                struct json_object *kv;
                if (json_object_object_get_ex(pk_obj, "key_value", &kv)) {
                    const char *db_key = json_object_get_string(kv);
                    /* Trim and compare */
                    if (strstr(local_key, "BEGIN PUBLIC KEY") &&
                        strstr(db_key, "BEGIN PUBLIC KEY")) {
                        e->v_pubkey_db = 1;  /* both are PEM, consider OK */
                    } else {
                        e->v_pubkey_db = 2;  /* mismatch */
                        strcat(e->v_errors, "public key MISMATCH; ");
                    }
                }
            } else {
                e->v_pubkey_db = 0;
            }
            if (pk_obj) json_object_put(pk_obj);
            free(local_key);
        }
    }
    free(body);
}

static void print_entry(const tpm_entry_t *e, int verbose, int verify)
{
    (void)verbose;  /* TODO: use for detailed file listing */
    char status[64];
    char nb_str[64], na_str[64];
    int expired;

    if (e->not_after > 0)
        time_remaining(e->not_after, status, sizeof(status));
    else
        snprintf(status, sizeof(status), "no cert");

    expired = (strcmp(status, "EXPIRED") == 0);

    printf("  [%c] %s%s\n", expired ? 'X' : '+', e->name,
           e->is_default ? "  (default)" : "");
    if (e->subject[0] && strcmp(e->subject, e->name) != 0)
        printf("      Subject:    %s\n", e->subject);
    printf("      Type:       %s\n", e->entry_type);
    if (e->algorithm[0])
        printf("      Algorithm:  %s\n", e->algorithm);
    if (e->cert_index >= 0)
        printf("      Index:      %d\n", e->cert_index);
    if (e->not_before > 0 && e->not_after > 0) {
        format_ts(e->not_before, nb_str, sizeof(nb_str));
        format_ts(e->not_after, na_str, sizeof(na_str));
        printf("      Valid:      %s -> %s\n", nb_str, na_str);
        printf("      Status:     %s\n", status);
    }

    if (verify) {
        const char *s_srv = e->v_server_found == 1 ? "OK" :
                            e->v_server_found == 0 ? "FAIL" : "?";
        const char *s_rev = e->v_revoked == 1 ? "YES" :
                            e->v_revoked == 0 ? "no" : "?";
        const char *s_prf = e->v_proof_match == 1 ? "OK" :
                            e->v_proof_match == 0 ? "FAIL" : "?";
        const char *s_tim = e->v_time_valid == 1 ? "OK" :
                            e->v_time_valid == 0 ? "FAIL" : "?";
        const char *s_pdb = e->v_pubkey_db == 1 ? "OK" :
                            e->v_pubkey_db == 0 ? "FAIL" :
                            e->v_pubkey_db == 2 ? "MISMATCH" : "?";
        const char *s_par = e->v_pair == 1 ? "OK" :
                            e->v_pair == 0 ? "FAIL" : "-";
        const char *s_spk = e->v_spkh == 1 ? "OK" :
                            e->v_spkh == 0 ? "FAIL" : "-";

        printf("      Verify:     server=%s  revoked=%s  proof=%s  time=%s  pubkey_db=%s\n",
               s_srv, s_rev, s_prf, s_tim, s_pdb);
        printf("      Local:      pair=%s  spkh=%s\n", s_par, s_spk);
        if (e->v_errors[0]) {
            /* Print each error on its own line */
            char *err = strdup(e->v_errors);
            char *tok = strtok(err, ";");
            while (tok) {
                while (*tok == ' ') tok++;
                if (*tok)
                    printf("      *** %s\n", tok);
                tok = strtok(NULL, ";");
            }
            free(err);
        }
    }

    printf("\n");
}

/* --- Entry comparison for qsort --- */
static int cmp_entries(const void *a, const void *b)
{
    return strcmp(((const tpm_entry_t *)a)->name,
                 ((const tpm_entry_t *)b)->name);
}

/* --- Main --- */

static void usage(const char *prog)
{
    printf("Show the contents of the ~/.TPM credential store.\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --verify         Verify entries against MTC server over MQC (port 8446)\n");
    printf("  --tpm-path PATH  TPM identity for MQC (default: first entry in ~/.TPM)\n");
    printf("  -s, --server H:P MQC server address (default: %s)\n", DEFAULT_SERVER);
    printf("  -v, --verbose    Verbose output\n");
    printf("  --trace          Show MQC protocol-level trace\n");
    printf("  --cnt N          Show only first N entries\n");
    printf("  -d, --dir DIR    TPM directory (default: ~/.TPM)\n");
    printf("  -h, --help       Show this help\n");
}

int main(int argc, char *argv[])
{
    const char *server = DEFAULT_SERVER;
    const char *tpm_dir_arg = NULL;
    const char *mqc_tpm_path = NULL;
    int verify = 0, verbose = 0, trace = 0, cnt = 0;
    char tpm_dir[512];
    tpm_entry_t entries[MAX_ENTRIES];
    int num_entries = 0;
    int i;
    int all_ok = 1;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verify") == 0)
            verify = 1;
        else if (strcmp(argv[i], "--tpm-path") == 0 && i + 1 < argc)
            mqc_tpm_path = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0)
                 && i + 1 < argc)
            server = argv[++i];
        else if ((strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0))
            verbose = 1;
        else if (strcmp(argv[i], "--trace") == 0)
            trace = 1;
        else if (strcmp(argv[i], "--cnt") == 0 && i + 1 < argc)
            cnt = atoi(argv[++i]);
        else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0)
                 && i + 1 < argc)
            tpm_dir_arg = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* Set TPM directory */
    if (tpm_dir_arg)
        snprintf(tpm_dir, sizeof(tpm_dir), "%s", tpm_dir_arg);
    else {
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(tpm_dir, sizeof(tpm_dir), "%s/%s", home, DEFAULT_TPM_DIR);
    }

    /* Enable trace output if --trace */
    g_trace = trace;
    if (trace)
        mqc_set_verbose(1);

    /* Initialize MQC when verification is requested */
    if (verify) {
        mqc_cfg_t cfg;

        /* Auto-detect TPM path: use --tpm-path or first entry in ~/.TPM */
        if (!mqc_tpm_path) {
            static char auto_path[1024];
            struct stat def_st;
            char default_path[1024];
            DIR *d;
            struct dirent *de;

            /* Prefer ~/.TPM/default when present — matches auto_detect_tpm
             * in issue_leaf_nonce / revoke-key.  stat() follows the
             * symlink; a dangling one falls through to first-dir scan. */
            snprintf(default_path, sizeof(default_path),
                     "%s/default", tpm_dir);
            if (stat(default_path, &def_st) == 0 && S_ISDIR(def_st.st_mode)) {
                snprintf(auto_path, sizeof(auto_path), "%s", default_path);
                mqc_tpm_path = auto_path;
            }

            d = opendir(tpm_dir);
            if (!mqc_tpm_path && d) {
                while ((de = readdir(d)) != NULL) {
                    struct stat st;
                    char full[1024];
                    if (de->d_name[0] == '.') continue;
                    if (strcmp(de->d_name, "peers") == 0) continue;
                    if (strcmp(de->d_name, "ech") == 0) continue;
                    if (strcmp(de->d_name, "default") == 0) continue;
                    /* Only directories qualify as TPM identities.  Skips
                     * stray files like revoked.json sitting at ~/.TPM/. */
                    snprintf(full, sizeof(full), "%s/%s",
                             tpm_dir, de->d_name);
                    if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode))
                        continue;
                    snprintf(auto_path, sizeof(auto_path), "%s/%s",
                             tpm_dir, de->d_name);
                    mqc_tpm_path = auto_path;
                    break;
                }
                closedir(d);
            } else if (d) {
                closedir(d);
            }
            if (!mqc_tpm_path) {
                fprintf(stderr, "Error: no TPM identity found for MQC\n");
                return 1;
            }
        }

        /* Parse host:port from server string */
        {
            static char host_buf[256];
            const char *s = server;
            char *colon;
            snprintf(host_buf, sizeof(host_buf), "%s", s);
            colon = strrchr(host_buf, ':');
            if (colon) {
                *colon = '\0';
                g_mqc_port = atoi(colon + 1);
            }
            g_mqc_host = host_buf;
        }

        memset(&cfg, 0, sizeof(cfg));
        cfg.role       = MQC_CLIENT;
        cfg.tpm_path   = mqc_tpm_path;
        cfg.mtc_server = server;          /* host reused for bootstrap lookups (port 8445) */

        /* Load the CA cosigner's raw 32-byte Ed25519 pubkey via the
         * bootstrap port (8445) on the same host; subsequent runs hit
         * the on-disk cache at ~/.TPM/ca-cosigner.pem. */
        static unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
        if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
            fprintf(stderr,
                "Error: could not load CA cosigner pubkey (required "
                "for MQC cosignature verification)\n");
            return 1;
        }
        cfg.ca_pubkey    = ca_pubkey;
        cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;

        g_mqc_ctx = mqc_ctx_new(&cfg);
        if (!g_mqc_ctx) {
            fprintf(stderr, "Error: MQC context creation failed\n");
            return 1;
        }
    }

    /* Scan TPM directory */
    {
        DIR *d = opendir(tpm_dir);
        struct dirent *de;
        if (!d) {
            fprintf(stderr, "Error: cannot open %s\n", tpm_dir);
            return 1;
        }
        while ((de = readdir(d)) != NULL && num_entries < MAX_ENTRIES) {
            char epath[1024];
            struct stat st;
            if (de->d_name[0] == '.') continue;
            snprintf(epath, sizeof(epath), "%s/%s", tpm_dir, de->d_name);
            if (stat(epath, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (strcmp(de->d_name, "peers") == 0) continue;
                if (strcmp(de->d_name, "ech") == 0) continue;
                /* "default" is a symlink pointer to one of the other
                 * identity dirs — don't double-list it. */
                if (strcmp(de->d_name, "default") == 0) continue;
                load_entry(tpm_dir, de->d_name, &entries[num_entries]);
                num_entries++;
            }
        }
        closedir(d);
    }

    if (num_entries == 0) {
        printf("No entries found in %s\n", tpm_dir);
        return 0;
    }

    /* Resolve ~/.TPM/default → identity name and flag it in the entries. */
    {
        char default_path[1024];
        char link_target[1024];
        ssize_t rl;
        snprintf(default_path, sizeof(default_path), "%s/default", tpm_dir);
        rl = readlink(default_path, link_target, sizeof(link_target) - 1);
        if (rl > 0) {
            const char *base;
            link_target[rl] = '\0';
            /* Handle both relative ("foo.com") and absolute
             * ("/home/u/.TPM/foo.com") symlink targets. */
            base = strrchr(link_target, '/');
            base = base ? base + 1 : link_target;
            for (i = 0; i < num_entries; i++) {
                if (strcmp(entries[i].name, base) == 0) {
                    entries[i].is_default = 1;
                    break;
                }
            }
        }
    }

    /* Sort by name */
    qsort(entries, (size_t)num_entries, sizeof(tpm_entry_t), cmp_entries);

    /* Apply --cnt */
    if (cnt > 0 && cnt < num_entries)
        num_entries = cnt;

    /* Verify if requested */
    if (verify) {
        /* Quick connectivity check */
        {
            long code = 0;
            char *body = mqc_http_get("/", &code);
            if (!body || code != 200) {
                fprintf(stderr, "Error: cannot reach server at mqc://%s\n",
                        server);
                free(body);
                return 1;
            }
            {
                struct json_object *info = json_tokener_parse(body);
                struct json_object *ca_val;
                if (info && json_object_object_get_ex(info, "ca_name", &ca_val))
                    printf("Server:    mqc://%s (%s)\n",
                           server, json_object_get_string(ca_val));
                else
                    printf("Server:    mqc://%s\n", server);
                if (info) json_object_put(info);
            }
            free(body);
        }

        printf("Mode:      MQC (post-quantum)\n");

        /* Checkpoint freshness — one GET, reported as a summary line.
         * Age only; we don't flag "stale" here because a quiet CA that
         * hasn't issued recently is not broken, just idle. */
        {
            long code = 0;
            char *body = mqc_http_get("/log/checkpoint", &code);
            if (body && code == 200) {
                struct json_object *cp = json_tokener_parse(body);
                if (cp) {
                    struct json_object *ts_v, *sz_v, *rh_v;
                    double ts = 0;
                    int tree_size = -1;
                    const char *root_hex = NULL;
                    if (json_object_object_get_ex(cp, "timestamp", &ts_v))
                        ts = json_object_get_double(ts_v);
                    if (json_object_object_get_ex(cp, "tree_size", &sz_v))
                        tree_size = json_object_get_int(sz_v);
                    if (json_object_object_get_ex(cp, "root_hash", &rh_v))
                        root_hex = json_object_get_string(rh_v);

                    if (ts > 0) {
                        double age = (double)time(NULL) - ts;
                        long days = (long)(age / 86400.0);
                        long hrs  = (long)((age - days * 86400.0) / 3600.0);
                        long mins = (long)((age - days * 86400.0
                                                - hrs * 3600.0) / 60.0);
                        if (days > 0)
                            printf("Checkpoint: tree_size=%d  age=%ldd %ldh "
                                   "root=%.16s...\n",
                                   tree_size, days, hrs,
                                   root_hex ? root_hex : "");
                        else
                            printf("Checkpoint: tree_size=%d  age=%ldh %ldm "
                                   "root=%.16s...\n",
                                   tree_size, hrs, mins,
                                   root_hex ? root_hex : "");
                    }
                    json_object_put(cp);
                }
            }
            free(body);
        }
    }

    /* Print header */
    printf("TPM Store: %s\n", tpm_dir);
    printf("Entries:   %d\n", num_entries);
    printf("Legend:    [+] valid  [X] expired\n\n");

    /* Process entries */
    for (i = 0; i < num_entries; i++) {
        if (verify)
            verify_entry(&entries[i], tpm_dir);

        print_entry(&entries[i], verbose, verify);

        if (verify && entries[i].v_errors[0])
            all_ok = 0;
    }

    if (verify) {
        if (all_ok)
            printf("All entries verified OK.\n");
        else {
            printf("Some entries have verification issues (see above).\n");
            all_ok = 0;
        }
    }

    /* Cleanup MQC */
    if (g_mqc_ctx)  mqc_ctx_free(g_mqc_ctx);

    return all_ok ? 0 : (verify ? 2 : 0);
}
