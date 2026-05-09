/*
 * fetch-publisher-key — fetch a publisher's ML-DSA-87 public-key PEM
 * authoritatively from the MTC server over MQC.
 *
 * The verifier-side companion to sign-dir.sh / verify-dir.sh: when a
 * remote host needs to verify a directory signature from a publisher
 * it does NOT have a local identity for, this tool queries
 *   GET /public-key/<DOMAIN>
 * over MQC, optionally cross-checks the returned PEM against
 *   GET /certificate/<CERT_INDEX>
 * (so a malicious server can't return a different key than the cert
 * binds), and writes the PEM to --out (default stdout).
 *
 * Usage:
 *   fetch-publisher-key --domain DOMAIN
 *                       [--cert-index N]      # if set, verify
 *                                              # sha256(pem)==cert.spk_hash
 *                       [--out PATH]          # default: stdout
 *                       [--tpm-path PATH]     # MQC identity (auto-discover
 *                                              # under $HOME/.TPM if absent)
 *                       [-s, --server H[:P]]  # default: [global] url-server
 *                       [-v]
 *
 * Exit:  0 on success, non-zero on transport / lookup / hash mismatch.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"
#include "../../../socket-level-wrapper-MQC/config.h"
#include "config.h"

#define DEFAULT_TPM_DIR  ".TPM"

#define die(fmt, ...) do { \
    fprintf(stderr, "fetch-publisher-key: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static int g_verbose = 0;

/* ------------------------------------------------------------------ */
/* MQC HTTP GET (mirrors fips-manifest-list)                          */
/* ------------------------------------------------------------------ */

static char *mqc_http_get(mqc_ctx_t *ctx, const char *host, int port,
                          const char *path, long *code)
{
    if (code) *code = 0;
    mqc_conn_t *conn = mqc_connect(ctx, host, port);
    if (!conn) { usleep(100000); conn = mqc_connect(ctx, host, port); }
    if (!conn) return NULL;

    char req[1024];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
             path, host, port);
    if (mqc_write(conn, req, (int)strlen(req)) < 0) {
        mqc_close(conn); return NULL;
    }

    int buf_cap = 16384, buf_sz = 0, n;
    char *buf = (char *)malloc((size_t)buf_cap);
    if (!buf) { mqc_close(conn); return NULL; }
    while (1) {
        if (buf_sz >= buf_cap - 1) {
            char *tmp;
            buf_cap *= 2;
            tmp = (char *)realloc(buf, (size_t)buf_cap);
            if (!tmp) break;
            buf = tmp;
        }
        n = mqc_read(conn, buf + buf_sz, buf_cap - 1 - buf_sz);
        if (n <= 0) break;
        buf_sz += n;
        buf[buf_sz] = '\0';
        char *bs = strstr(buf, "\r\n\r\n");
        if (bs) {
            char *cl = strcasestr(buf, "Content-Length:");
            bs += 4;
            if (cl) {
                int content_len = atoi(cl + 15);
                if (buf_sz - (int)(bs - buf) >= content_len) break;
            } else break;
        }
    }
    buf[buf_sz] = '\0';
    mqc_close(conn);

    long status = 0;
    if (buf_sz >= 12 && strncmp(buf, "HTTP/1.", 7) == 0)
        status = atol(buf + 9);
    if (code) *code = status;

    char *bs = strstr(buf, "\r\n\r\n");
    if (!bs) { free(buf); return NULL; }
    bs += 4;
    char *result = strdup(bs);
    free(buf);
    return result;
}

/* ------------------------------------------------------------------ */
/* Identity discovery (auto-pick first under $HOME/.TPM)              */
/* ------------------------------------------------------------------ */

static char *autodiscover_tpm(void)
{
    const char *home = getenv("HOME");
    if (!home) return NULL;
    char tpm_dir[1024];
    snprintf(tpm_dir, sizeof(tpm_dir), "%s/%s", home, DEFAULT_TPM_DIR);
    DIR *d = opendir(tpm_dir);
    if (!d) return NULL;
    struct dirent *de;
    char *result = NULL;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "peers")   == 0) continue;
        if (strcmp(de->d_name, "ech")     == 0) continue;
        if (strcmp(de->d_name, "default") == 0) continue;
        char path[2048];
        struct stat st;
        snprintf(path, sizeof(path), "%s/%s", tpm_dir, de->d_name);
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        char p[2200];
        snprintf(p, sizeof(p), "%s/certificate.json", path);
        if (access(p, R_OK) != 0) continue;
        result = strdup(path);
        break;
    }
    closedir(d);
    return result;
}

/* ------------------------------------------------------------------ */
/* Hash + cert spk-hash extraction                                    */
/* ------------------------------------------------------------------ */

static int sha256_hex(const uint8_t *in, size_t n, char hex[65])
{
    wc_Sha256 sha;
    uint8_t out[32];
    if (wc_InitSha256(&sha) != 0) return -1;
    if (wc_Sha256Update(&sha, in, (word32)n) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    if (wc_Sha256Final(&sha, out) != 0) {
        wc_Sha256Free(&sha); return -1;
    }
    wc_Sha256Free(&sha);
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", out[i]);
    return 0;
}

/* Parses the /certificate/<N> response and returns
 * standalone_certificate.tbs_entry.subject_public_key_hash (caller frees).
 * NULL on parse failure. */
static char *extract_cert_spk_hash(const char *cert_json_str)
{
    struct json_object *o = json_tokener_parse(cert_json_str);
    if (!o) return NULL;
    struct json_object *sc, *tbs, *v;
    char *result = NULL;
    if (json_object_object_get_ex(o, "standalone_certificate", &sc) &&
        json_object_object_get_ex(sc, "tbs_entry", &tbs) &&
        json_object_object_get_ex(tbs, "subject_public_key_hash", &v))
    {
        const char *s = json_object_get_string(v);
        if (s && strlen(s) == 64) result = strdup(s);
    }
    json_object_put(o);
    return result;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --domain DOMAIN\n"
        "       [--cert-index N]    (verify sha256(pem)==cert.spk_hash)\n"
        "       [--out PATH]        (default: stdout)\n"
        "       [--tpm-path PATH]   (default: first identity under $HOME/.TPM)\n"
        "       [-s, --server H[:P]] (default: [global] url-server)\n"
        "       [-v, --verbose]\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *domain         = NULL;
    int         cert_index     = -1;
    const char *out_path       = NULL;
    const char *cli_tpm_path   = NULL;
    const char *cli_server     = NULL;

    static struct option opts[] = {
        {"domain",     required_argument, 0, 'd'},
        {"cert-index", required_argument, 0, 'i'},
        {"out",        required_argument, 0, 'o'},
        {"tpm-path",   required_argument, 0, 'T'},
        {"server",     required_argument, 0, 's'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "d:i:o:T:s:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'd': domain       = optarg;       break;
            case 'i': cert_index   = atoi(optarg); break;
            case 'o': out_path     = optarg;       break;
            case 'T': cli_tpm_path = optarg;       break;
            case 's': cli_server   = optarg;       break;
            case 'v': g_verbose    = 1;            break;
            default:  usage(argv[0]);
        }
    }
    if (!domain) {
        fprintf(stderr, "fetch-publisher-key: --domain is required\n");
        usage(argv[0]);
    }

    /* Identity */
    char *tpm_owned = NULL;
    const char *tpm_path = cli_tpm_path;
    if (!tpm_path) {
        tpm_owned = autodiscover_tpm();
        if (!tpm_owned)
            die("no TPM identity under $HOME/.TPM (use --tpm-path)");
        tpm_path = tpm_owned;
    }

    /* Server */
    char *server_owned = NULL;
    const char *server = cli_server;
    if (!server) {
        server_owned = read_config_url("global/url-server");
        server = server_owned ? server_owned : MQC_DEFAULT_SERVER;
    }
    const char *colon_slash = strstr(server, "://");
    if (colon_slash) server = colon_slash + 3;

    char host_buf[256];
    int port = MQC_DEFAULT_SERVER_PORT;
    snprintf(host_buf, sizeof(host_buf), "%s", server);
    {
        char *cn = strrchr(host_buf, ':');
        if (cn) { *cn = 0; port = atoi(cn + 1); }
    }

    /* MQC ctx */
    static unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
    if (mqc_load_ca_pubkey(host_buf, ca_pubkey) != 0)
        die("could not load CA cosigner pubkey from %s", host_buf);

    mqc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role         = MQC_CLIENT;
    cfg.tpm_path     = tpm_path;
    cfg.mtc_server   = host_buf;
    cfg.ca_pubkey    = ca_pubkey;
    cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);
    if (!ctx) die("MQC ctx creation failed (tpm_path=%s)", tpm_path);

    /* Fetch the PEM */
    char path[256];
    snprintf(path, sizeof(path), "/public-key/%s", domain);
    long code = 0;
    char *body = mqc_http_get(ctx, host_buf, port, path, &code);
    if (!body || code != 200) {
        if (g_verbose && body) fprintf(stderr, "[fetch] body: %s\n", body);
        free(body);
        mqc_ctx_free(ctx);
        die("GET %s -> HTTP %ld", path, code);
    }
    struct json_object *obj = json_tokener_parse(body);
    free(body);
    if (!obj) { mqc_ctx_free(ctx); die("publickey response not JSON"); }
    struct json_object *kv = NULL;
    if (!json_object_object_get_ex(obj, "key_value", &kv)) {
        json_object_put(obj); mqc_ctx_free(ctx);
        die("publickey response missing key_value");
    }
    const char *pem = json_object_get_string(kv);
    if (!pem || !*pem) {
        json_object_put(obj); mqc_ctx_free(ctx);
        die("publickey response key_value empty");
    }

    /* Optional cross-check against /certificate/<N>'s spk_hash. */
    if (cert_index >= 0) {
        snprintf(path, sizeof(path), "/certificate/%d", cert_index);
        char *cert_body = mqc_http_get(ctx, host_buf, port, path, &code);
        if (!cert_body || code != 200) {
            free(cert_body); json_object_put(obj); mqc_ctx_free(ctx);
            die("GET %s -> HTTP %ld", path, code);
        }
        char *expected_hex = extract_cert_spk_hash(cert_body);
        free(cert_body);
        if (!expected_hex) {
            json_object_put(obj); mqc_ctx_free(ctx);
            die("cert %d response missing/short spk_hash", cert_index);
        }
        char actual_hex[65];
        if (sha256_hex((const uint8_t *)pem, strlen(pem), actual_hex) != 0) {
            free(expected_hex); json_object_put(obj); mqc_ctx_free(ctx);
            die("sha256(pem) failed");
        }
        if (strcmp(actual_hex, expected_hex) != 0) {
            fprintf(stderr,
                "fetch-publisher-key: SPK_HASH MISMATCH for %s (cert %d)\n"
                "  cert  : %s\n"
                "  fetched pem sha256: %s\n",
                domain, cert_index, expected_hex, actual_hex);
            free(expected_hex); json_object_put(obj); mqc_ctx_free(ctx);
            return 1;
        }
        if (g_verbose)
            fprintf(stderr, "[fetch] cert %d spk_hash matches fetched PEM\n",
                    cert_index);
        free(expected_hex);
    }

    /* Emit the PEM */
    if (out_path) {
        FILE *f = fopen(out_path, "wb");
        if (!f) {
            json_object_put(obj); mqc_ctx_free(ctx);
            die("cannot write %s", out_path);
        }
        size_t plen = strlen(pem);
        if (fwrite(pem, 1, plen, f) != plen) {
            fclose(f); json_object_put(obj); mqc_ctx_free(ctx);
            die("short write to %s", out_path);
        }
        if (plen == 0 || pem[plen - 1] != '\n') fputc('\n', f);
        fclose(f);
        if (g_verbose)
            fprintf(stderr, "[fetch] wrote %s (%zu bytes)\n", out_path, plen);
    } else {
        fputs(pem, stdout);
        if (pem[strlen(pem) - 1] != '\n') fputc('\n', stdout);
    }

    json_object_put(obj);
    mqc_ctx_free(ctx);
    free(tpm_owned);
    free(server_owned);
    return 0;
}
