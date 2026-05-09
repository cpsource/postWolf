/*
 * fips-manifest-revoke — revoke a previously-submitted FIPS manifest.
 *
 * Talks to the MTC CA over MQC (port from /etc/postWolf/config) and
 * POSTs a signed envelope to /fips/revoke.  Authority model: either the
 * publisher leaf (self-revoke) OR the publisher's CA may sign — pick
 * with --as.  No backwards-compat fallbacks; the spec is at
 * fips-framework/spec-canonical-leaf.md "Manifest revocation".
 *
 * Usage:
 *   fips-manifest-revoke --log-index N --reason "..."
 *                        [--as publisher|ca]            (default publisher)
 *                        [--tpm-path PATH]              (default: $HOME/.TPM/<auto>)
 *                        [-s, --server HOST[:PORT]]
 *                        [-v]
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"
#include "../../../socket-level-wrapper-MQC/config.h"
#include "config.h"

#define DEFAULT_TPM_DIR  ".TPM"

#define die(fmt, ...) do { \
    fprintf(stderr, "fips-manifest-revoke: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static int g_verbose = 0;

/* ------------------------------------------------------------------ */
/* File reads                                                         */
/* ------------------------------------------------------------------ */

static char *read_text(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* Identity discovery (mirrors fips-manifest-list.c)                  */
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
        snprintf(p, sizeof(p), "%s/private_key.pem", path);
        if (access(p, R_OK) != 0) continue;
        result = strdup(path);
        break;
    }
    closedir(d);
    return result;
}

/* Returns the cert_index from the on-disk certificate.json. */
static int load_cert_index(const char *tpm_path)
{
    char p[2200];
    snprintf(p, sizeof(p), "%s/certificate.json", tpm_path);
    char *txt = read_text(p);
    if (!txt) return -1;
    struct json_object *o = json_tokener_parse(txt);
    free(txt);
    if (!o) return -1;
    /* postWolf's certificate.json uses `index` at the top level. */
    struct json_object *v = NULL;
    int idx = -1;
    if (json_object_object_get_ex(o, "index", &v))
        idx = json_object_get_int(v);
    json_object_put(o);
    if (idx < 0) {
        /* Fall back to a plain index file (older layouts). */
        char ip[2200];
        snprintf(ip, sizeof(ip), "%s/index", tpm_path);
        char *itxt = read_text(ip);
        if (itxt) { idx = atoi(itxt); free(itxt); }
    }
    return idx;
}

/* Returns the cert algorithm string from certificate.json (e.g. "ML-DSA-87"). */
static char *load_cert_algo(const char *tpm_path)
{
    char p[2200];
    snprintf(p, sizeof(p), "%s/certificate.json", tpm_path);
    char *txt = read_text(p);
    if (!txt) return NULL;
    struct json_object *o = json_tokener_parse(txt);
    free(txt);
    if (!o) return NULL;
    struct json_object *sc = NULL, *tbs = NULL, *v = NULL;
    char *result = NULL;
    if (json_object_object_get_ex(o, "standalone_certificate", &sc) &&
        json_object_object_get_ex(sc, "tbs_entry", &tbs) &&
        json_object_object_get_ex(tbs, "subject_public_key_algorithm", &v))
        result = strdup(json_object_get_string(v));
    json_object_put(o);
    return result;
}

/* ------------------------------------------------------------------ */
/* Sign                                                               */
/* ------------------------------------------------------------------ */

/* Produces ML-DSA-87 signature bytes over `msg` using `privkey_pem`.
 * Returns signature length, or -1 on failure.  Caller-provided
 * sig_out must be at least 4627 bytes (ML-DSA-87 signature size). */
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
    if (der_sz <= 0) {
        fprintf(stderr, "fips-manifest-revoke: PEM->DER failed (%d)\n", der_sz);
        return -1;
    }
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "fips-manifest-revoke: RNG init failed\n");
        return -1;
    }
    rng_ok = 1;

    if (strcmp(algo, "ML-DSA-87") != 0) {
        fprintf(stderr, "fips-manifest-revoke: unsupported algo '%s' "
                "(only ML-DSA-87 supported by /fips/revoke)\n", algo);
        ret = -1;
        goto fail;
    }

    dilithium_key dil;
    word32 idx = 0;
    wc_dilithium_init(&dil);
    wc_dilithium_set_level(&dil, WC_ML_DSA_87);
    ret = wc_Dilithium_PrivateKeyDecode(der_buf, &idx, &dil, (word32)der_sz);
    if (ret != 0) { wc_dilithium_free(&dil); goto fail; }
    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                                    (const uint8_t *)msg,
                                    (word32)strlen(msg),
                                    sig_out, &out_len, &dil, &rng);
    wc_dilithium_free(&dil);
    if (ret != 0) goto fail;

    wc_FreeRng(&rng);
    return (int)out_len;
fail:
    if (rng_ok) wc_FreeRng(&rng);
    return -1;
}

static void to_hex(const uint8_t *in, int n, char *out)
{
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/* MQC HTTP POST                                                      */
/* ------------------------------------------------------------------ */

static char *mqc_http_post(mqc_ctx_t *ctx, const char *host, int port,
                           const char *path, const char *body, int body_len,
                           long *code)
{
    if (code) *code = 0;
    mqc_conn_t *conn = mqc_connect(ctx, host, port);
    if (!conn) { usleep(100000); conn = mqc_connect(ctx, host, port); }
    if (!conn) return NULL;

    char hdr[1024];
    snprintf(hdr, sizeof(hdr),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n\r\n",
             path, host, port, body_len);
    if (mqc_write(conn, hdr, (int)strlen(hdr)) < 0) {
        mqc_close(conn); return NULL;
    }
    if (body_len > 0 && mqc_write(conn, body, body_len) < 0) {
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
                int header_len  = (int)(bs - buf);
                if (buf_sz - header_len >= content_len) break;
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
/* Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --log-index N --reason \"...\"\n"
        "       [--as publisher|ca]    (default publisher)\n"
        "       [--tpm-path PATH]      (default: first identity under $HOME/.TPM)\n"
        "       [-s, --server H[:P]]   (default: [global] url-server)\n"
        "       [-v, --verbose]\n"
        "       [-h, --help]\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    int  log_index   = -1;
    const char *reason  = "";
    const char *as_kind = "publisher";
    const char *cli_tpm_path = NULL;
    const char *cli_server   = NULL;

    static struct option opts[] = {
        {"log-index",  required_argument, 0, 'l'},
        {"reason",     required_argument, 0, 'r'},
        {"as",         required_argument, 0, 'a'},
        {"tpm-path",   required_argument, 0, 'T'},
        {"server",     required_argument, 0, 's'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "l:r:a:T:s:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'l': log_index    = atoi(optarg); break;
            case 'r': reason       = optarg;       break;
            case 'a': as_kind      = optarg;       break;
            case 'T': cli_tpm_path = optarg;       break;
            case 's': cli_server   = optarg;       break;
            case 'v': g_verbose    = 1;            break;
            default:  usage(argv[0]);
        }
    }
    if (log_index < 0) {
        fprintf(stderr, "fips-manifest-revoke: --log-index is required\n");
        usage(argv[0]);
    }
    if (strcmp(as_kind, "publisher") != 0 && strcmp(as_kind, "ca") != 0)
        die("--as must be 'publisher' or 'ca'");
    if (strlen(reason) > 256)
        die("--reason too long (max 256 chars)");

    /* Identity */
    char *tpm_owned = NULL;
    const char *tpm_path = cli_tpm_path;
    if (!tpm_path) {
        tpm_owned = autodiscover_tpm();
        if (!tpm_owned)
            die("no TPM identity found under $HOME/.TPM "
                "(use --tpm-path)");
        tpm_path = tpm_owned;
    }
    int revoker_cert_index = load_cert_index(tpm_path);
    if (revoker_cert_index < 0)
        die("cannot read cert_index from %s", tpm_path);
    char *algo = load_cert_algo(tpm_path);
    if (!algo) die("cannot read spk_algorithm from %s", tpm_path);

    char priv_path[2200], pub_path[2200];
    snprintf(priv_path, sizeof(priv_path), "%s/private_key.pem", tpm_path);
    snprintf(pub_path,  sizeof(pub_path),  "%s/public_key.pem",  tpm_path);
    char *priv_pem = read_text(priv_path);
    char *pub_pem  = read_text(pub_path);
    if (!priv_pem) die("cannot read %s", priv_path);
    if (!pub_pem)  die("cannot read %s", pub_path);

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

    /* Build signing input + sign */
    long timestamp = (long)time(NULL);
    char sign_msg[1024];
    snprintf(sign_msg, sizeof(sign_msg),
             "fips-revoke:%s:%d:%d:%s:%ld",
             as_kind, revoker_cert_index, log_index, reason, timestamp);
    if (g_verbose)
        fprintf(stderr, "[fips-revoke] signing: %s\n", sign_msg);

    uint8_t sig_buf[8192];
    int sig_len = sign_message(priv_pem, algo, sign_msg,
                               sig_buf, (int)sizeof(sig_buf));
    if (sig_len < 0)
        die("signing failed");
    char *sig_hex = (char *)malloc((size_t)sig_len * 2 + 1);
    if (!sig_hex) die("oom sig_hex");
    to_hex(sig_buf, sig_len, sig_hex);

    /* Build envelope */
    struct json_object *req = json_object_new_object();
    json_object_object_add(req, "log_index",
        json_object_new_int(log_index));
    json_object_object_add(req, "revoker_kind",
        json_object_new_string(as_kind));
    json_object_object_add(req, "revoker_cert_index",
        json_object_new_int(revoker_cert_index));
    json_object_object_add(req, "reason",
        json_object_new_string(reason));
    json_object_object_add(req, "timestamp",
        json_object_new_int64(timestamp));
    json_object_object_add(req, "public_key_pem",
        json_object_new_string(pub_pem));
    json_object_object_add(req, "signature",
        json_object_new_string(sig_hex));

    const char *body_str = json_object_to_json_string_ext(
        req, JSON_C_TO_STRING_PLAIN);
    char *body = strdup(body_str);
    int body_len = (int)strlen(body);

    if (g_verbose)
        fprintf(stderr, "[fips-revoke] POST %s:%d/fips/revoke (%d bytes)\n",
                host_buf, port, body_len);

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
    if (!ctx) die("MQC context creation failed (tpm_path=%s)", tpm_path);

    long code = 0;
    char *resp = mqc_http_post(ctx, host_buf, port, "/fips/revoke",
                               body, body_len, &code);
    mqc_ctx_free(ctx);

    int exit_code = 0;
    if (!resp) {
        fprintf(stderr, "fips-manifest-revoke: MQC POST failed\n");
        exit_code = 1;
    } else if (code != 200) {
        fprintf(stderr, "fips-manifest-revoke: server returned HTTP %ld\n",
                code);
        fprintf(stderr, "%s\n", resp);
        exit_code = 1;
    } else {
        struct json_object *r = json_tokener_parse(resp);
        printf("revoked log_index=%d as %s/%d  reason=\"%s\"\n",
               log_index, as_kind, revoker_cert_index, reason);
        if (g_verbose && r) {
            printf("server response: %s\n",
                   json_object_to_json_string_ext(r,
                       JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
        }
        if (r) json_object_put(r);
    }

    free(resp);
    free(body);
    free(sig_hex);
    free(priv_pem);
    free(pub_pem);
    free(algo);
    free(tpm_owned);
    free(server_owned);
    json_object_put(req);
    return exit_code;
}
