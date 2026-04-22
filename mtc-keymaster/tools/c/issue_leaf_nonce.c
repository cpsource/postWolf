/******************************************************************************
 * File:        issue_leaf_nonce.c
 * Purpose:     CA operator tool — issue a leaf enrollment nonce over MQC/8446.
 *
 * Description:
 *   Connects to the MTC server on its MQC (post-quantum) port using the
 *   CA operator's enrolled TPM identity, POSTs to /enrollment/nonce with
 *   type=leaf, and saves the returned nonce to
 *   ~/.mtc-ca-data/<domain>/nonce.txt.
 *
 *   The on-disk contract matches tools/python/issue_leaf_nonce.py so that
 *   bootstrap_leaf can pick up either tool's output without arguments.
 *   Unlike the Python tool, this one authenticates to the server via MQC
 *   (ML-KEM-768 + ML-DSA-87 + AES-256-GCM) rather than classical TLS.
 *
 * Usage:
 *   issue_leaf_nonce --domain DOMAIN --key-file FILE
 *                    [--fingerprint sha256:HEX]
 *                    [-s, --server HOST:PORT]       (default: factsorlie.com:8446)
 *                    [--tpm-path PATH]              (default: first in ~/.TPM)
 *                    [--out DIR]                    (default: ~/.mtc-ca-data)
 *                    [--dry-run]                    (show request, don't send)
 *                    [--trace]                      (MQC protocol trace)
 *                    [-h, --help]
 *
 * Created:     2026-04-17
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"

/* Explicit path — there's also a server-side config.h on the include
 * search path that would shadow this one. */
#include "../../../socket-level-wrapper-MQC/config.h"
#define DEFAULT_SERVER    MQC_DEFAULT_SERVER
#define DEFAULT_TPM_DIR   ".TPM"
#define DEFAULT_OUT_DIR   ".mtc-ca-data"

/* Global MQC client state */
static mqc_ctx_t  *g_mqc_ctx  = NULL;
static const char *g_mqc_host = "localhost";
static int         g_mqc_port = 8446;

/******************************************************************************
 * Function:    to_hex  (static)
 ******************************************************************************/
static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
    out[sz * 2] = '\0';
}

/******************************************************************************
 * Function:    sanitize_label  (static)
 *
 * Description:
 *   Client-side validator for operator-assigned labels.  The label ends
 *   up as the suffix of an on-disk directory name (~/.TPM/<domain>-<label>)
 *   so we're strict about what can appear.  Charset [A-Za-z0-9._-] only,
 *   length 1..MTC_LABEL_MAX.  Empty and NULL are both invalid.
 *
 *   Returns 0 on success, -1 on any violation.
 ******************************************************************************/
#define MTC_LABEL_MAX 64
static int sanitize_label(const char *in)
{
    size_t len, i;
    if (!in) return -1;
    len = strlen(in);
    if (len < 1 || len > MTC_LABEL_MAX) return -1;
    for (i = 0; i < len; i++) {
        char c = in[i];
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return -1;
    }
    return 0;
}

/******************************************************************************
 * Function:    read_file  (static)
 *
 * Description:
 *   Read the full contents of a text file into a heap-allocated
 *   NUL-terminated buffer.  Returns NULL on any error.  Caller frees.
 ******************************************************************************/
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    long sz;
    char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/******************************************************************************
 * Function:    fingerprint_from_pem  (static)
 *
 * Description:
 *   Compute SHA-256 over the raw PEM text (matching
 *   issue_leaf_nonce.py's hashlib.sha256(pem_text.encode()).hexdigest()
 *   so that the two tools produce identical fingerprints for the same
 *   public-key PEM file).  Writes 64 hex chars + NUL into fp_out.
 ******************************************************************************/
static int fingerprint_from_pem(const char *pem_path, char *fp_out)
{
    char *pem;
    wc_Sha256 sha;
    uint8_t digest[WC_SHA256_DIGEST_SIZE];

    pem = read_file(pem_path);
    if (!pem) {
        fprintf(stderr, "Error: cannot read public key file '%s'\n", pem_path);
        return -1;
    }

    if (wc_InitSha256(&sha) != 0) { free(pem); return -1; }
    if (wc_Sha256Update(&sha, (const uint8_t *)pem,
                        (word32)strlen(pem)) != 0) {
        wc_Sha256Free(&sha); free(pem); return -1;
    }
    if (wc_Sha256Final(&sha, digest) != 0) {
        wc_Sha256Free(&sha); free(pem); return -1;
    }
    wc_Sha256Free(&sha);
    free(pem);

    to_hex(digest, WC_SHA256_DIGEST_SIZE, fp_out);
    return 0;
}

/******************************************************************************
 * Function:    ensure_dir  (static)
 *
 * Description:
 *   mkdir -p equivalent for a single component path — assumes parents
 *   already exist (matches the on-disk layout `<out>/<domain>/`).
 ******************************************************************************/
static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    return mkdir(path, 0700);
}

/******************************************************************************
 * Function:    mqc_http_post  (static)
 *
 * Description:
 *   Open a fresh MQC connection, send an HTTP-shaped POST with a JSON body,
 *   and return the response body as a heap-allocated string.  The MQC
 *   listener on port 8446 routes through the same handle_request
 *   dispatcher as the TLS listener on 8444, so HTTP over MQC works
 *   endpoint-for-endpoint.  Caller frees.  *code is set to the HTTP
 *   status code (or 0 on transport failure).
 ******************************************************************************/
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
        /* One-shot retry: the server drops the first handshake after
         * refreshing its per-peer revocation cache; the next attempt
         * runs against the warm cache. */
        usleep(100000);  /* 100 ms */
        conn = mqc_connect(g_mqc_ctx, g_mqc_host, g_mqc_port);
    }
    if (!conn) {
        fprintf(stderr, "Error: mqc_connect to %s:%d failed\n",
                g_mqc_host, g_mqc_port);
        return NULL;
    }

    /* Send POST header */
    snprintf(hdr, sizeof(hdr),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n",
             path, g_mqc_host, g_mqc_port, body_len);
    if (mqc_write(conn, hdr, (int)strlen(hdr)) < 0) {
        mqc_close(conn);
        return NULL;
    }
    if (body_len > 0 && mqc_write(conn, body, body_len) < 0) {
        mqc_close(conn);
        return NULL;
    }

    /* Read response into dynamically-growing buffer (Content-Length driven,
     * falls back to EOF if the server omits it). */
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

    body_start = strstr(buf, "\r\n\r\n");
    if (!body_start) { free(buf); return NULL; }
    body_start += 4;

    {
        char *result = strdup(body_start);
        free(buf);
        return result;
    }
}

/******************************************************************************
 * Function:    auto_detect_tpm  (static)
 *
 * Description:
 *   If the caller didn't specify --tpm-path, pick the first directory
 *   under ~/.TPM/ that looks like an identity (not "peers", "ech", or
 *   a hidden entry).  Matches show-tpm.c's heuristic.  The buffer is
 *   static because the returned pointer outlives the function.
 ******************************************************************************/
static const char *auto_detect_tpm(const char *tpm_dir)
{
    static char auto_path[1024];
    DIR *d;
    struct dirent *de;
    struct stat st;

    /* Prefer ~/.TPM/default if it exists and resolves to a live dir.
     * stat() follows the symlink, so a dangling one reports ENOENT
     * and we fall through to the first-dir heuristic. */
    {
        char default_path[1024];
        snprintf(default_path, sizeof(default_path), "%s/default", tpm_dir);
        if (stat(default_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(auto_path, sizeof(auto_path), "%s", default_path);
            return auto_path;
        }
    }

    d = opendir(tpm_dir);
    if (!d) return NULL;

    while ((de = readdir(d)) != NULL) {
        char full[1024];
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "peers") == 0) continue;
        if (strcmp(de->d_name, "ech") == 0) continue;
        /* Skip the default symlink during enumeration — it's a pointer,
         * not its own identity (the pre-loop block already honors it). */
        if (strcmp(de->d_name, "default") == 0) continue;
        snprintf(full, sizeof(full), "%s/%s", tpm_dir, de->d_name);
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        snprintf(auto_path, sizeof(auto_path), "%s", full);
        closedir(d);
        return auto_path;
    }
    closedir(d);
    return NULL;
}

/******************************************************************************
 * Function:    usage  (static)
 ******************************************************************************/
static void usage(const char *prog)
{
    printf("Issue a leaf enrollment nonce over MQC/8446.\n\n");
    printf("Usage: %s --domain DOMAIN (--key-file FILE | --label LABEL --ttl-days N)\n", prog);
    printf("       [options]\n\n");
    printf("  --domain DOMAIN       Subject/domain the leaf will enroll under\n");
    printf("  --key-file FILE       Leaf public key PEM (SHA-256 of text =\n");
    printf("                        fingerprint submitted to the server).  Omit for\n");
    printf("                        long-lived reservation mode (--label + --ttl-days).\n");
    printf("  --fingerprint FP      Override fingerprint (hex, sha256: prefix OK).\n");
    printf("                        Alternative to --key-file.\n");
    printf("  --ttl-days N          Issue a long-lived reservation nonce (up to 30\n");
    printf("                        days) bound to (domain, label) with fp\n");
    printf("                        late-bound at consume.  Requires --label.\n");
    printf("                        Omit for the default 15-minute TTL.\n");
    printf("  -s, --server H:P      MQC server (default: %s)\n", DEFAULT_SERVER);
    printf("  --tpm-path PATH       CA operator's TPM identity dir\n");
    printf("                        (default: first directory in ~/.TPM)\n");
    printf("  --label LABEL         Optional local label for the leaf.  Leaf identity\n");
    printf("                        lands in ~/.TPM/<domain>-<label>/.  Required when\n");
    printf("                        --ttl-days is set (reservation mode).\n");
    printf("                        Charset [A-Za-z0-9._-], length 1..64.\n");
    printf("                        Never embedded in the cert.\n");
    printf("  --out DIR             Save nonce under DIR/<domain>/nonce.txt\n");
    printf("                        (default: ~/%s)\n", DEFAULT_OUT_DIR);
    printf("  --dry-run             Print the request without sending\n");
    printf("  --trace               Show MQC protocol-level trace\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char *argv[])
{
    const char *domain      = NULL;
    const char *key_file    = NULL;
    const char *fingerprint = NULL;
    const char *server      = DEFAULT_SERVER;
    const char *tpm_path    = NULL;
    const char *out_arg     = NULL;
    const char *label_arg   = NULL;
    int dry_run = 0, trace = 0;
    int ttl_days = 0;               /* 0 = default short-lived 15-min */
    int i;

    char fp_hex[WC_SHA256_DIGEST_SIZE * 2 + 1];
    char tpm_dir[512];
    char out_base[512];
    const char *home;

    /* --- Parse args --- */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
            domain = argv[++i];
        else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc)
            key_file = argv[++i];
        else if (strcmp(argv[i], "--fingerprint") == 0 && i + 1 < argc)
            fingerprint = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0)
                 && i + 1 < argc)
            server = argv[++i];
        else if (strcmp(argv[i], "--tpm-path") == 0 && i + 1 < argc)
            tpm_path = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_arg = argv[++i];
        else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc)
            label_arg = argv[++i];
        else if (strcmp(argv[i], "--ttl-days") == 0 && i + 1 < argc) {
            ttl_days = atoi(argv[++i]);
            if (ttl_days < 1) {
                fprintf(stderr, "Error: --ttl-days must be >= 1\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--dry-run") == 0)
            dry_run = 1;
        else if (strcmp(argv[i], "--trace") == 0)
            trace = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!domain) {
        fprintf(stderr, "Error: --domain is required\n");
        usage(argv[0]);
        return 1;
    }
    /* Two modes:
     *   - immediate:    --key-file or --fingerprint (fp-bound, 15-min TTL)
     *   - reservation:  --label + --ttl-days (fp late-bound at consume)
     */
    if (!key_file && !fingerprint && ttl_days == 0) {
        fprintf(stderr, "Error: provide --key-file / --fingerprint "
                "(immediate mode) OR --label and --ttl-days "
                "(long-lived reservation)\n");
        usage(argv[0]);
        return 1;
    }
    if (ttl_days > 0 && !label_arg) {
        fprintf(stderr, "Error: --ttl-days requires --label to pin the "
                "reservation slot\n");
        return 1;
    }
    if (label_arg && sanitize_label(label_arg) != 0) {
        fprintf(stderr,
            "Error: --label must be 1..%d chars, [A-Za-z0-9._-] only\n",
            MTC_LABEL_MAX);
        return 1;
    }

    /* --- Resolve default paths --- */
    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(tpm_dir, sizeof(tpm_dir), "%s/%s", home, DEFAULT_TPM_DIR);
    if (out_arg)
        snprintf(out_base, sizeof(out_base), "%s", out_arg);
    else
        snprintf(out_base, sizeof(out_base), "%s/%s", home, DEFAULT_OUT_DIR);

    /* --- Compute fingerprint (skipped in reservation mode) --- */
    fp_hex[0] = '\0';
    if (fingerprint) {
        /* Accept "sha256:<hex>" or plain hex */
        if (strncmp(fingerprint, "sha256:", 7) == 0)
            fingerprint += 7;
        if (strlen(fingerprint) != WC_SHA256_DIGEST_SIZE * 2) {
            fprintf(stderr, "Error: fingerprint must be 64 hex chars\n");
            return 1;
        }
        snprintf(fp_hex, sizeof(fp_hex), "%s", fingerprint);
    } else if (key_file) {
        if (fingerprint_from_pem(key_file, fp_hex) != 0)
            return 1;
        printf("Leaf public key fingerprint: sha256:%s\n", fp_hex);
    }
    /* else: reservation mode — no fp to submit; server will late-bind. */

    /* --- Parse server host:port --- */
    {
        static char host_buf[256];
        char *colon;
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        colon = strrchr(host_buf, ':');
        if (colon) {
            *colon = '\0';
            g_mqc_port = atoi(colon + 1);
        }
        g_mqc_host = host_buf;
    }

    /* --- Build JSON request body --- */
    {
        struct json_object *req;
        const char *req_str;
        char *body_copy;
        int body_len;

        req = json_object_new_object();
        json_object_object_add(req, "domain",
                               json_object_new_string(domain));
        if (fp_hex[0]) {
            char sha_field[80];
            snprintf(sha_field, sizeof(sha_field), "sha256:%s", fp_hex);
            json_object_object_add(req, "public_key_fingerprint",
                                   json_object_new_string(sha_field));
        }
        json_object_object_add(req, "type",
                               json_object_new_string("leaf"));
        if (label_arg)
            json_object_object_add(req, "label",
                                   json_object_new_string(label_arg));
        if (ttl_days > 0)
            json_object_object_add(req, "ttl_days",
                                   json_object_new_int(ttl_days));

        req_str = json_object_to_json_string_ext(req,
                      JSON_C_TO_STRING_PLAIN);
        body_copy = strdup(req_str);
        body_len = (int)strlen(body_copy);
        json_object_put(req);

        if (dry_run) {
            printf("\n*** DRY RUN — would send over MQC to %s:%d:\n",
                   g_mqc_host, g_mqc_port);
            printf("  POST /enrollment/nonce\n");
            printf("  %s\n", body_copy);
            free(body_copy);
            return 0;
        }

        /* --- Resolve TPM identity --- */
        if (!tpm_path) {
            tpm_path = auto_detect_tpm(tpm_dir);
            if (!tpm_path) {
                fprintf(stderr,
                        "Error: no TPM identity found under %s "
                        "(pass --tpm-path to specify)\n", tpm_dir);
                free(body_copy);
                return 1;
            }
        }

        if (trace)
            mqc_set_verbose(1);

        /* --- Initialize MQC client context --- */
        {
            mqc_cfg_t cfg;
            static unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];

            if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
                fprintf(stderr,
                    "Error: could not load CA cosigner pubkey (first-run "
                    "TOFU via %s:8445 failed)\n", g_mqc_host);
                free(body_copy);
                return 1;
            }

            memset(&cfg, 0, sizeof(cfg));
            cfg.role         = MQC_CLIENT;
            cfg.tpm_path     = tpm_path;
            cfg.mtc_server   = server;
            cfg.ca_pubkey    = ca_pubkey;
            cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;

            g_mqc_ctx = mqc_ctx_new(&cfg);
            if (!g_mqc_ctx) {
                fprintf(stderr, "Error: MQC context creation failed\n");
                free(body_copy);
                return 1;
            }
        }

        /* --- POST /enrollment/nonce --- */
        {
            long code = 0;
            char *resp_body;
            struct json_object *resp, *jn_val;
            const char *nonce_str = NULL;
            long expires = 0;
            int ca_index = -1;

            resp_body = mqc_http_post("/enrollment/nonce",
                                      body_copy, body_len, &code);
            free(body_copy);

            if (!resp_body) {
                fprintf(stderr, "Error: POST /enrollment/nonce over MQC failed\n");
                mqc_ctx_free(g_mqc_ctx);
                return 1;
            }
            if (code != 200) {
                fprintf(stderr, "Error: server returned HTTP %ld\n%s\n",
                        code, resp_body);
                free(resp_body);
                mqc_ctx_free(g_mqc_ctx);
                return 1;
            }

            resp = json_tokener_parse(resp_body);
            if (!resp) {
                fprintf(stderr, "Error: response is not JSON:\n%s\n", resp_body);
                free(resp_body);
                mqc_ctx_free(g_mqc_ctx);
                return 1;
            }

            const char *server_label = NULL;

            if (json_object_object_get_ex(resp, "nonce", &jn_val))
                nonce_str = json_object_get_string(jn_val);
            if (json_object_object_get_ex(resp, "expires", &jn_val))
                expires = json_object_get_int64(jn_val);
            if (json_object_object_get_ex(resp, "ca_index", &jn_val))
                ca_index = json_object_get_int(jn_val);
            /* Canonical label from the server — may differ from
             * --label on idempotent reissue (first call wins). */
            if (json_object_object_get_ex(resp, "label", &jn_val))
                server_label = json_object_get_string(jn_val);

            if (!nonce_str || strlen(nonce_str) != 64) {
                fprintf(stderr, "Error: malformed nonce in response:\n%s\n",
                        resp_body);
                json_object_put(resp);
                free(resp_body);
                mqc_ctx_free(g_mqc_ctx);
                return 1;
            }

            printf("\nLeaf enrollment nonce issued:\n");
            printf("  Domain:    %s\n", domain);
            printf("  Nonce:     %s\n", nonce_str);
            {
                long now_ts = (long)time(NULL);
                long secs = expires - now_ts;
                if (secs < 3600)
                    printf("  Expires:   %ld (%ld min)\n", expires, secs / 60);
                else if (secs < 86400)
                    printf("  Expires:   %ld (%ld hours)\n", expires, secs / 3600);
                else
                    printf("  Expires:   %ld (%ld days)\n", expires, secs / 86400);
            }
            printf("  CA index:  %d\n", ca_index);
            if (server_label && server_label[0]) {
                printf("  Label:     %s\n", server_label);
                printf("  TPM dir:   ~/.TPM/%s-%s/ (on the leaf's side)\n",
                       domain, server_label);
                if (label_arg && strcmp(label_arg, server_label) != 0)
                    printf("  Note:      server returned a different label\n"
                           "             ('%s') than --label ('%s') — a\n"
                           "             pending nonce already existed\n"
                           "             for this key; label is immutable\n"
                           "             until expiry.\n",
                           server_label, label_arg);
            }

            /* --- Save to <out_base>/<domain>/nonce.txt --- */
            {
                char out_dir[768];
                char out_file[900];
                FILE *nf;

                ensure_dir(out_base);
                snprintf(out_dir, sizeof(out_dir), "%s/%s", out_base, domain);
                if (ensure_dir(out_dir) != 0 && errno != EEXIST) {
                    fprintf(stderr, "Warning: cannot create %s: %s\n",
                            out_dir, strerror(errno));
                } else {
                    snprintf(out_file, sizeof(out_file),
                             "%s/nonce.txt", out_dir);
                    nf = fopen(out_file, "w");
                    if (nf) {
                        fprintf(nf, "%s\n", nonce_str);
                        if (server_label && server_label[0])
                            fprintf(nf, "label=%s\n", server_label);
                        fclose(nf);
                        chmod(out_file, 0600);
                        printf("\n  Saved to:  %s\n", out_file);
                    } else {
                        fprintf(stderr, "Warning: cannot write %s: %s\n",
                                out_file, strerror(errno));
                    }
                }
            }

            printf("\nSend this nonce to the leaf user. They enroll with:\n");
            if (ttl_days > 0) {
                /* Reservation-mode: recipient generates their own keys
                 * locally.  register-leaf.sh cross-machine flow does
                 * exactly that. */
                printf("  register-leaf.sh --domain \"%s\" %s%s%s \\\n"
                       "                   --server %s:8445 --nonce %s\n",
                       domain,
                       label_arg ? "--label \"" : "",
                       label_arg ? label_arg : "",
                       label_arg ? "\"" : "",
                       g_mqc_host, nonce_str);
                printf("  (long-lived %dd reservation; fp will bind at "
                       "enrollment)\n", ttl_days);
            } else {
                printf("  bootstrap_leaf --domain \"%s\" --nonce %s\n",
                       domain, nonce_str);
            }

            json_object_put(resp);
            free(resp_body);
        }

        mqc_ctx_free(g_mqc_ctx);
    }

    return 0;
}
