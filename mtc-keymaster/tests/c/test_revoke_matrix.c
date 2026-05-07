/******************************************************************************
 * File:        test_revoke_matrix.c
 * Purpose:     End-to-end test driver for POST /revoke (TODO #19).
 *
 *   Walks the full positive + negative authorization matrix against a live
 *   MTC CA on MQC/8446 and bootstrap-proxy GET on /8445.  Designed to run
 *   on factsorlie.com against the production CA — Bob is a sacrificial
 *   factsorlie.com leaf who gets revoked at the end of the run.  Negative
 *   rows reuse existing log entries (frflashy-ca + frflashy-leaf) and do
 *   not mutate state.  Net log cost per run: +1 leaf cert (Bob) + 1
 *   revocation row.
 *
 *   Test order is significant:
 *     - Row 5 (bob signs as a leaf) MUST run before row 1, because
 *       once bob is revoked the MQC handshake from his identity would
 *       fail at revocation check.
 *     - Row 1 (positive revoke) runs last to keep negative rows
 *       independent of state.
 *
 * Usage:
 *   test_revoke_matrix
 *     [--ca-tpm-path PATH]                 (default: auto-detect *-ca under ~/.TPM)
 *      --bob-tpm-path PATH                  (required: ~/.TPM/<bob-dir>)
 *     [--foreign-ca-domain D]               (default: frflashy.com)
 *     [-s, --server H:P]                    (default: from /etc/postWolf/config)
 *     [--trace]                             (MQC protocol trace)
 *     [-h, --help]
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "../../read-config/read-config.h"

/* Shadowed by an unrelated server-side config.h on -I path. */
#include "../../../socket-level-wrapper-MQC/config.h"
#define DEFAULT_TPM_DIR   ".TPM"

/* Shared MQC connection state — one ctx for the whole run. */
static mqc_ctx_t  *g_mqc_ctx  = NULL;
static const char *g_mqc_host = "localhost";
static int         g_mqc_port = 8446;

/* Per-row tally. */
static int g_pass = 0;
static int g_fail = 0;

/* ------------------------------------------------------------------ */
/* Identity (loaded from a TPM dir).                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    char       tpm_path[512];
    char      *privkey_pem;     /* malloc */
    char      *pubkey_pem;      /* malloc */
    char       subject[256];
    char       algo[32];
    int        cert_index;
} identity_t;

static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
    out[sz * 2] = '\0';
}

static char *read_text(const char *path)
{
    FILE *f;
    long sz;
    char *buf;
    size_t nread;

    f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0)                    { fclose(f); return NULL; }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf)                      { fclose(f); return NULL; }
    nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[nread] = '\0';
    return buf;
}

static char *auto_detect_ca_tpm(const char *tpm_dir)
{
    DIR *d;
    struct dirent *de;
    char *found = NULL;
    int count = 0;

    d = opendir(tpm_dir);
    if (!d) return NULL;
    while ((de = readdir(d)) != NULL) {
        size_t nlen;
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "default") == 0) continue;
        nlen = strlen(de->d_name);
        if (nlen < 3 || strcmp(de->d_name + nlen - 3, "-ca") != 0) continue;
        count++;
        if (found) { free(found); found = NULL; break; }
        {
            size_t plen = strlen(tpm_dir) + 1 + nlen + 1;
            found = (char *)malloc(plen);
            if (found) snprintf(found, plen, "%s/%s", tpm_dir, de->d_name);
        }
    }
    closedir(d);
    if (count > 1) {
        if (found) { free(found); found = NULL; }
    }
    return found;
}

static int load_identity(const char *tpm_path, identity_t *id)
{
    char path_buf[1024];
    char *cert_json_s = NULL, *index_str = NULL;
    struct json_object *cert_json = NULL, *sc, *tbs, *val;
    int rc = -1;

    memset(id, 0, sizeof(*id));
    snprintf(id->tpm_path, sizeof(id->tpm_path), "%s", tpm_path);

    snprintf(path_buf, sizeof(path_buf), "%s/private_key.pem", tpm_path);
    id->privkey_pem = read_text(path_buf);
    if (!id->privkey_pem) {
        fprintf(stderr, "[load_identity] missing %s\n", path_buf);
        goto out;
    }

    snprintf(path_buf, sizeof(path_buf), "%s/public_key.pem", tpm_path);
    id->pubkey_pem = read_text(path_buf);
    if (!id->pubkey_pem) {
        fprintf(stderr, "[load_identity] missing %s\n", path_buf);
        goto out;
    }

    snprintf(path_buf, sizeof(path_buf), "%s/certificate.json", tpm_path);
    cert_json_s = read_text(path_buf);
    if (!cert_json_s) {
        fprintf(stderr, "[load_identity] missing %s\n", path_buf);
        goto out;
    }
    cert_json = json_tokener_parse(cert_json_s);
    if (!cert_json ||
        !json_object_object_get_ex(cert_json, "standalone_certificate", &sc) ||
        !json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        fprintf(stderr, "[load_identity] malformed %s\n", path_buf);
        goto out;
    }
    if (json_object_object_get_ex(tbs, "subject", &val))
        snprintf(id->subject, sizeof(id->subject), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
        snprintf(id->algo, sizeof(id->algo), "%s",
                 json_object_get_string(val));
    else
        snprintf(id->algo, sizeof(id->algo), "ML-DSA-87");

    snprintf(path_buf, sizeof(path_buf), "%s/index", tpm_path);
    index_str = read_text(path_buf);
    if (!index_str) {
        fprintf(stderr, "[load_identity] missing %s\n", path_buf);
        goto out;
    }
    id->cert_index = atoi(index_str);
    rc = 0;

out:
    free(cert_json_s);
    free(index_str);
    if (cert_json) json_object_put(cert_json);
    if (rc != 0) {
        free(id->privkey_pem); id->privkey_pem = NULL;
        free(id->pubkey_pem);  id->pubkey_pem  = NULL;
    }
    return rc;
}

static void free_identity(identity_t *id)
{
    free(id->privkey_pem);
    free(id->pubkey_pem);
    memset(id, 0, sizeof(*id));
}

/* ------------------------------------------------------------------ */
/* sign_message — ML-DSA-87 only (matches mtc_bootstrap.c accept).    */
/* ------------------------------------------------------------------ */
static int sign_message(const char *privkey_pem, const char *algo,
                        const char *msg, uint8_t *sig_out, int sig_cap)
{
    uint8_t der_buf[16384];
    int der_sz;
    WC_RNG rng;
    int rng_ok = 0;
    int ret;
    word32 out_len = (word32)sig_cap;

    der_sz = wc_KeyPemToDer((const unsigned char *)privkey_pem,
                            (int)strlen(privkey_pem),
                            der_buf, (int)sizeof(der_buf), NULL);
    if (der_sz <= 0) return -1;

    if (wc_InitRng(&rng) != 0) return -1;
    rng_ok = 1;

    if (strcmp(algo, "ML-DSA-87") == 0) {
        dilithium_key dil;
        word32 idx = 0;
        wc_dilithium_init(&dil);
        wc_dilithium_set_level(&dil, WC_ML_DSA_87);
        ret = wc_Dilithium_PrivateKeyDecode(der_buf, &idx, &dil,
                                            (word32)der_sz);
        if (ret != 0) { wc_dilithium_free(&dil); goto fail; }
        ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                                        (const uint8_t *)msg,
                                        (word32)strlen(msg),
                                        sig_out, &out_len, &dil, &rng);
        wc_dilithium_free(&dil);
        if (ret != 0) goto fail;
    }
    else {
        ret = -1;
        goto fail;
    }

    wc_FreeRng(&rng);
    return (int)out_len;

fail:
    if (rng_ok) wc_FreeRng(&rng);
    return -1;
}

/* ------------------------------------------------------------------ */
/* HTTP POST over MQC (mirrors revoke-key.c::mqc_http_post).          */
/* ------------------------------------------------------------------ */
static char *mqc_http_post(const char *path, const char *body, int body_len,
                           long *code)
{
    mqc_conn_t *conn;
    char hdr[1024];
    char *buf = NULL;
    int buf_sz = 0, buf_cap = 16384;
    int n;
    char *body_start;
    long status = 0;

    if (code) *code = 0;

    conn = mqc_connect(g_mqc_ctx, g_mqc_host, g_mqc_port);
    if (!conn) {
        usleep(100000);
        conn = mqc_connect(g_mqc_ctx, g_mqc_host, g_mqc_port);
    }
    if (!conn) return NULL;

    snprintf(hdr, sizeof(hdr),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n",
             path, g_mqc_host, g_mqc_port, body_len);
    if (mqc_write(conn, hdr, (int)strlen(hdr)) < 0) {
        mqc_close(conn); return NULL;
    }
    if (body_len > 0 && mqc_write(conn, body, body_len) < 0) {
        mqc_close(conn); return NULL;
    }

    buf = malloc((size_t)buf_cap);
    if (!buf) { mqc_close(conn); return NULL; }

    while (1) {
        if (buf_sz >= buf_cap - 1) {
            char *tmp;
            buf_cap *= 2;
            tmp = realloc(buf, (size_t)buf_cap);
            if (!tmp) break;
            buf = tmp;
        }
        n = mqc_read(conn, buf + buf_sz, buf_cap - 1 - buf_sz);
        if (n <= 0) break;
        buf_sz += n;
        buf[buf_sz] = '\0';
        body_start = strstr(buf, "\r\n\r\n");
        if (body_start) {
            char *cl = strcasestr(buf, "Content-Length:");
            body_start += 4;
            if (cl) {
                int content_len = atoi(cl + 15);
                int header_len  = (int)(body_start - buf);
                int body_have   = buf_sz - header_len;
                if (body_have >= content_len) break;
            } else {
                break;
            }
        }
    }
    buf[buf_sz] = '\0';
    mqc_close(conn);

    if (buf_sz >= 12 && strncmp(buf, "HTTP/1.", 7) == 0)
        status = atol(buf + 9);
    if (code) *code = status;

    body_start = strstr(buf, "\r\n\r\n");
    if (!body_start) { free(buf); return NULL; }
    body_start += 4;
    {
        char *result = strdup(body_start);
        free(buf);
        return result;
    }
}

/* ------------------------------------------------------------------ */
/* Foreign-domain index discovery via /certificate/search.            */
/*                                                                    */
/* The server's reload_lock now blocks bootstrap forks for the entire */
/* reload window, so a single GET is authoritative — any reply we get */
/* is post-reload-stable.                                             */
/* ------------------------------------------------------------------ */
static int discover_foreign_indices(const char *server_str,
                                    const char *foreign_domain,
                                    int *out_ca_idx, int *out_leaf_idx)
{
    char path[256];
    long code = 0;
    char *resp = NULL;
    struct json_object *root = NULL, *results = NULL, *entry, *val;
    int n = 0, i;
    int rc = -1;

    snprintf(path, sizeof(path), "/certificate/search?q=%s", foreign_domain);

    resp = mqc_bootstrap_http_get(server_str, path, &code);
    if (!resp || code != 200) {
        fprintf(stderr, "[discover] GET %s: code=%ld body=%.200s\n",
                path, code, resp ? resp : "(null)");
        free(resp);
        return -1;
    }
    root = json_tokener_parse(resp);
    if (!root) {
        fprintf(stderr, "[discover] invalid JSON: %.200s\n", resp);
        free(resp);
        return -1;
    }

    free(resp);
    if (!root) return -1;

    *out_ca_idx = -1;
    *out_leaf_idx = -1;

    if (!json_object_object_get_ex(root, "results", &results)) {
        fprintf(stderr, "[discover] no 'results' field\n");
        goto out;
    }
    n = (int)json_object_array_length(results);
    for (i = 0; i < n; i++) {
        const char *subj;
        int idx;
        size_t sl;
        entry = json_object_array_get_idx(results, i);
        if (!json_object_object_get_ex(entry, "subject", &val)) continue;
        subj = json_object_get_string(val);
        if (!json_object_object_get_ex(entry, "index", &val)) continue;
        idx = json_object_get_int(val);
        sl = strlen(subj);
        if (sl >= 3 && strcmp(subj + sl - 3, "-ca") == 0) {
            /* prefer the exact "<domain>-ca" subject */
            size_t dl = strlen(foreign_domain);
            if (sl == dl + 3 && strncmp(subj, foreign_domain, dl) == 0)
                *out_ca_idx = idx;
        } else {
            if (strcmp(subj, foreign_domain) == 0)
                *out_leaf_idx = idx;
        }
    }
    if (*out_ca_idx >= 0 && *out_leaf_idx >= 0) rc = 0;
    else {
        fprintf(stderr,
            "[discover] foreign domain '%s' search incomplete: "
            "ca_idx=%d leaf_idx=%d (results=%d)\n",
            foreign_domain, *out_ca_idx, *out_leaf_idx, n);
        for (i = 0; i < n; i++) {
            const char *subj = NULL;
            int idx = -1;
            entry = json_object_array_get_idx(results, i);
            if (json_object_object_get_ex(entry, "subject", &val))
                subj = json_object_get_string(val);
            if (json_object_object_get_ex(entry, "index", &val))
                idx = json_object_get_int(val);
            fprintf(stderr, "    [%d] idx=%d subject='%s'\n",
                    i, idx, subj ? subj : "(null)");
        }
    }

out:
    json_object_put(root);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Build a /revoke request body.  Caller frees *out_body.             */
/*                                                                    */
/* All 9 negative rows are constructed by tweaking arguments; row 1   */
/* is the canonical positive case.                                    */
/* ------------------------------------------------------------------ */
static int build_revoke_body(int ca_cert_index, int target_index,
                             const char *reason, long timestamp,
                             const char *signing_priv_pem,
                             const char *signing_algo,
                             const char *body_ca_pem,
                             int poison_signature,
                             char **out_body, int *out_body_len)
{
    char sign_msg[512];
    uint8_t sig_buf[8192];
    int sig_len;
    char *sig_hex;
    struct json_object *req;
    const char *req_str;

    snprintf(sign_msg, sizeof(sign_msg), "revoke:%d:%d:%s:%ld",
             ca_cert_index, target_index, reason, timestamp);

    sig_len = sign_message(signing_priv_pem, signing_algo, sign_msg,
                           sig_buf, (int)sizeof(sig_buf));
    if (sig_len < 0) return -1;

    if (poison_signature) {
        /* flip a single bit somewhere benign (not the trailing zero pad) */
        sig_buf[sig_len / 2] ^= 0x01;
    }

    sig_hex = malloc((size_t)sig_len * 2 + 1);
    if (!sig_hex) return -1;
    to_hex(sig_buf, sig_len, sig_hex);

    req = json_object_new_object();
    json_object_object_add(req, "ca_cert_index",
        json_object_new_int(ca_cert_index));
    json_object_object_add(req, "cert_index",
        json_object_new_int(target_index));
    json_object_object_add(req, "reason",
        json_object_new_string(reason));
    json_object_object_add(req, "timestamp",
        json_object_new_int64(timestamp));
    json_object_object_add(req, "ca_public_key_pem",
        json_object_new_string(body_ca_pem));
    json_object_object_add(req, "signature",
        json_object_new_string(sig_hex));

    req_str = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);
    *out_body = strdup(req_str);
    *out_body_len = (int)strlen(*out_body);

    free(sig_hex);
    json_object_put(req);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-row dispatcher.                                                */
/*                                                                    */
/* /revoke is rate-limited at 5/min per IP (mtc_ratelimit.c).  Pace   */
/* every call after the first by 13s to fit the 5/min sliding window */
/* with a small safety margin; if we still trip 429 (e.g. shared     */
/* budget with concurrent operator activity), sleep 65s and retry    */
/* once.  Total runtime for the 9-row matrix: ~1.7 minutes.          */
/* ------------------------------------------------------------------ */
static int g_case_seen = 0;

static void run_case(const char *name,
                     int expect_status, const char *expect_substr,
                     const char *body, int body_len)
{
    long code = 0;
    char *resp;

    if (g_case_seen > 0) sleep(13);
    g_case_seen++;

    resp = mqc_http_post("/revoke", body, body_len, &code);
    if (code == 429) {
        printf("    (rate-limit hit on '%s', sleeping 65s and retrying)\n",
               name);
        free(resp);
        sleep(65);
        resp = mqc_http_post("/revoke", body, body_len, &code);
    }

    int ok_status = (code == expect_status);
    int ok_body   = (resp && expect_substr && strstr(resp, expect_substr)) ? 1 : 0;
    int pass      = ok_status && ok_body;

    printf("[%s] %s: code=%ld %s\n",
           pass ? "PASS" : "FAIL", name, code,
           ok_body ? "(body matched)" : "(body MISMATCH or NULL)");
    if (!pass) {
        printf("    expected status=%d substr='%s'\n",
               expect_status, expect_substr ? expect_substr : "(any)");
        if (resp)
            printf("    actual body: %.200s%s\n",
                   resp, strlen(resp) > 200 ? "…" : "");
        else
            printf("    actual body: (NULL)\n");
    }

    if (pass) g_pass++; else g_fail++;
    free(resp);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--ca-tpm-path PATH] --bob-tpm-path PATH\n"
        "       [--foreign-ca-domain D] [-s HOST:PORT] [--trace] [-h]\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *server          = NULL;
    const char *ca_tpm_arg      = NULL;
    const char *bob_tpm_arg     = NULL;
    const char *foreign_domain  = "frflashy.com";
    int trace = 0;
    int server_from_cli = 0;
    int i;
    char *ca_tpm_owned = NULL;
    identity_t ca_id, bob_id;
    int foreign_ca_idx = -1, foreign_leaf_idx = -1;
    char tpm_root[1024];
    const char *home;

    memset(&ca_id, 0, sizeof(ca_id));
    memset(&bob_id, 0, sizeof(bob_id));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ca-tpm-path") == 0 && i + 1 < argc)
            ca_tpm_arg = argv[++i];
        else if (strcmp(argv[i], "--bob-tpm-path") == 0 && i + 1 < argc)
            bob_tpm_arg = argv[++i];
        else if (strcmp(argv[i], "--foreign-ca-domain") == 0 && i + 1 < argc)
            foreign_domain = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 ||
                  strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server = argv[++i];
            server_from_cli = 1;
        }
        else if (strcmp(argv[i], "--trace") == 0)
            trace = 1;
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!bob_tpm_arg) {
        fprintf(stderr, "Error: --bob-tpm-path is required\n");
        usage(argv[0]);
        return 1;
    }

    if (!server_from_cli) {
        char *cfg = read_config_url("global/url-server");
        if (cfg) server = cfg;
        else     server = MQC_DEFAULT_SERVER;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(tpm_root, sizeof(tpm_root), "%s/%s", home, DEFAULT_TPM_DIR);

    if (!ca_tpm_arg) {
        ca_tpm_owned = auto_detect_ca_tpm(tpm_root);
        if (!ca_tpm_owned) {
            fprintf(stderr, "Error: no CA identity under %s\n", tpm_root);
            return 1;
        }
        ca_tpm_arg = ca_tpm_owned;
    }

    if (load_identity(ca_tpm_arg, &ca_id) != 0) {
        fprintf(stderr, "Error: cannot load CA identity %s\n", ca_tpm_arg);
        free(ca_tpm_owned);
        return 1;
    }
    if (load_identity(bob_tpm_arg, &bob_id) != 0) {
        fprintf(stderr, "Error: cannot load Bob identity %s\n", bob_tpm_arg);
        free_identity(&ca_id);
        free(ca_tpm_owned);
        return 1;
    }

    {
        size_t sl = strlen(ca_id.subject);
        if (sl < 3 || strcmp(ca_id.subject + sl - 3, "-ca") != 0) {
            fprintf(stderr, "Error: '%s' is not a CA subject\n", ca_id.subject);
            free_identity(&ca_id); free_identity(&bob_id);
            free(ca_tpm_owned);
            return 1;
        }
    }

    /* Discover foreign-domain CA + leaf via the public search endpoint. */
    if (discover_foreign_indices(server, foreign_domain,
                                 &foreign_ca_idx, &foreign_leaf_idx) != 0) {
        fprintf(stderr,
            "Error: could not discover foreign domain '%s' indices.  "
            "Some negative rows depend on this domain being in the log.\n",
            foreign_domain);
        free_identity(&ca_id); free_identity(&bob_id);
        free(ca_tpm_owned);
        return 1;
    }

    printf("\n=== test_revoke_matrix ===\n");
    printf("server:           %s\n", server);
    printf("CA identity:      %s (subject='%s' idx=%d algo=%s)\n",
           ca_id.tpm_path, ca_id.subject, ca_id.cert_index, ca_id.algo);
    printf("Bob identity:     %s (subject='%s' idx=%d algo=%s)\n",
           bob_id.tpm_path, bob_id.subject, bob_id.cert_index, bob_id.algo);
    printf("Foreign domain:   %s (ca idx=%d, leaf idx=%d)\n",
           foreign_domain, foreign_ca_idx, foreign_leaf_idx);
    printf("\n");

    /* --- Parse server "host:port" --- */
    {
        static char host_buf[256];
        char *colon;
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        if (strncmp(host_buf, "https://", 8) == 0)
            memmove(host_buf, host_buf + 8, strlen(host_buf + 8) + 1);
        else if (strncmp(host_buf, "http://", 7) == 0)
            memmove(host_buf, host_buf + 7, strlen(host_buf + 7) + 1);
        colon = strrchr(host_buf, ':');
        if (colon) { *colon = '\0'; g_mqc_port = atoi(colon + 1); }
        g_mqc_host = host_buf;
    }

    /* --- MQC ctx as the CA identity (handle_revoke ignores peer-id;
     *     we just need the handshake to succeed). --- */
    if (trace) mqc_set_verbose(1);
    {
        mqc_cfg_t cfg;
        static unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];

        if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
            fprintf(stderr, "Error: mqc_load_ca_pubkey failed\n");
            free_identity(&ca_id); free_identity(&bob_id);
            free(ca_tpm_owned);
            return 1;
        }
        memset(&cfg, 0, sizeof(cfg));
        cfg.role         = MQC_CLIENT;
        cfg.tpm_path     = ca_id.tpm_path;
        cfg.mtc_server   = server;
        cfg.ca_pubkey    = ca_pubkey;
        cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        g_mqc_ctx = mqc_ctx_new(&cfg);
        if (!g_mqc_ctx) {
            fprintf(stderr, "Error: mqc_ctx_new failed\n");
            free_identity(&ca_id); free_identity(&bob_id);
            free(ca_tpm_owned);
            return 1;
        }
    }

    /* ============================================================== */
    /* Run the matrix.                                                */
    /* ============================================================== */
    long now = (long)time(NULL);
    char *body;
    int body_len;

    /* Row 5: caller is a leaf (Bob signs as if he were a CA).  Must
     * run BEFORE row 1 — once Bob is revoked the MQC handshake from
     * his identity would fail.  Note: we are the CA at the MQC layer,
     * but the request body claims Bob's cert_index is the "CA". */
    if (build_revoke_body(bob_id.cert_index, foreign_leaf_idx,
                          "test-row5", now,
                          bob_id.privkey_pem, bob_id.algo,
                          bob_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row5_caller_not_ca", 403, "caller is not a CA",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 2: self-revoke (CA points ca_cert_index == cert_index). */
    if (build_revoke_body(ca_id.cert_index, ca_id.cert_index,
                          "test-row2", now,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row2_self_revoke", 403, "may not revoke itself",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 3: target leaf outside CA's domain (frflashy leaf). */
    if (build_revoke_body(ca_id.cert_index, foreign_leaf_idx,
                          "test-row3", now,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row3_outside_domain", 403, "not within the CA's domain",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 4: target is itself a CA (frflashy.com-ca). */
    if (build_revoke_body(ca_id.cert_index, foreign_ca_idx,
                          "test-row4", now,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row4_target_is_ca", 403, "target is not a leaf",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 6: ca_public_key_pem hash mismatch — CA's signature, but
     * body advertises Bob's PEM (different hash). */
    if (build_revoke_body(ca_id.cert_index, bob_id.cert_index,
                          "test-row6", now,
                          ca_id.privkey_pem, ca_id.algo,
                          bob_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row6_pem_hash_mismatch", 403, "does not match logged",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 7: signature invalid — flip one bit in the sig hex. */
    if (build_revoke_body(ca_id.cert_index, bob_id.cert_index,
                          "test-row7", now,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          1, /* poison_signature */
                          &body, &body_len) == 0) {
        run_case("row7_sig_invalid", 403, "signature verification failed",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 8: stale timestamp (10 minutes in the past). */
    if (build_revoke_body(ca_id.cert_index, bob_id.cert_index,
                          "test-row8", now - 600,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row8_stale_timestamp", 400, "freshness",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 9: future timestamp (10 minutes in the future). */
    if (build_revoke_body(ca_id.cert_index, bob_id.cert_index,
                          "test-row9", now + 600,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row9_future_timestamp", 400, "freshness",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Row 1 (last — mutates state): CA revokes Bob. */
    now = (long)time(NULL);
    if (build_revoke_body(ca_id.cert_index, bob_id.cert_index,
                          "test-row1-positive", now,
                          ca_id.privkey_pem, ca_id.algo,
                          ca_id.pubkey_pem,
                          0,
                          &body, &body_len) == 0) {
        run_case("row1_positive_revoke", 200, "\"revoked\":true",
                 body, body_len);
        free(body);
    } else g_fail++;

    /* Verify persisted state: GET /revoked/<bob_idx> over bootstrap.
     *
     * The server's reload_lock now blocks bootstrap forks for the
     * full reload window, so a single GET is authoritative — every
     * fork has already taken the rdlock and therefore sees the
     * post-mutation state. */
    {
        char path[64];
        long code = 0;
        char *resp = NULL;
        int ok = 0;
        snprintf(path, sizeof(path), "/revoked/%d", bob_id.cert_index);
        resp = mqc_bootstrap_http_get(server, path, &code);
        /* Match both formattings — handle_revoked_check uses
         * "revoked":true (no space) on the wire, but the bootstrap
         * http_get proxy re-serializes with a space after the colon
         * ("revoked": true). */
        if (resp && code == 200 &&
            (strstr(resp, "\"revoked\":true") ||
             strstr(resp, "\"revoked\": true"))) {
            ok = 1;
        }
        printf("[%s] verify_persisted: GET %s code=%ld %s\n",
               ok ? "PASS" : "FAIL", path, code,
               resp ? "(body retrieved)" : "(no body)");
        if (!ok && resp)
            printf("    actual: %.200s\n", resp);
        if (ok) g_pass++; else g_fail++;
        free(resp);
    }

    /* --- summary --- */
    printf("\n=== summary: %d passed, %d failed ===\n", g_pass, g_fail);

    mqc_ctx_free(g_mqc_ctx);
    free_identity(&ca_id);
    free_identity(&bob_id);
    free(ca_tpm_owned);
    return g_fail == 0 ? 0 : 1;
}
