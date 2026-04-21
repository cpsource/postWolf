/******************************************************************************
 * File:        revoke-key.c
 * Purpose:     CA operator tool — revoke a leaf in your domain.
 *
 * Description:
 *   Signs a revocation request with the CA's private key and POSTs it to
 *   the MTC server over MQC (post-quantum authenticated channel).
 *
 *   Authorization (enforced server-side):
 *     - The signer's cert must be a CA (subject "<domain>-ca").
 *     - The target cert must be a leaf (subject not ending in "-ca").
 *     - The target's subject must be within the CA's domain.
 *     - A CA may not revoke itself.
 *
 *   Body sent to /revoke:
 *     {
 *       "ca_cert_index":     <your CA index>,
 *       "cert_index":        <target leaf index>,
 *       "reason":            "...",
 *       "timestamp":         <epoch>,
 *       "ca_public_key_pem": "-----BEGIN ...-----\n...",
 *       "signature":         "<hex>"
 *     }
 *
 *   sign_msg = "revoke:<ca_cert_index>:<cert_index>:<reason>:<timestamp>"
 *
 * Usage:
 *   revoke-key --target-index N [--reason "text"]
 *              [--ca-tpm-path PATH]          (default: auto-detect under ~/.TPM/)
 *              [-s, --server HOST:PORT]      (default: factsorlie.com:8446)
 *              [--dry-run]                   (show request, don't send)
 *              [--trace]                     (MQC protocol trace)
 *              [-h, --help]
 *
 * Created:     2026-04-18
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"

/* Explicit path — there's also a server-side config.h on the include
 * search path that would shadow this one. */
#include "../../../socket-level-wrapper-MQC/config.h"
#define DEFAULT_SERVER    MQC_DEFAULT_SERVER
#define DEFAULT_TPM_DIR   ".TPM"

static mqc_ctx_t  *g_mqc_ctx  = NULL;
static const char *g_mqc_host = "localhost";
static int         g_mqc_port = 8446;

/* ------------------------------------------------------------------ */
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

/*
 * auto_detect_ca_tpm:
 *   scan ~/.TPM/ for a subdirectory whose name ends in "-ca".
 *   Returns a malloc'd path on success, NULL if none or ambiguous.
 */
static char *auto_detect_ca_tpm(const char *tpm_dir)
{
    DIR *d;
    struct dirent *de;
    char *found = NULL;
    int count = 0;
    struct stat st;
    char default_path[PATH_MAX];
    char resolved[PATH_MAX];

    /* If ~/.TPM/default resolves to a CA identity (dir name ending in
     * "-ca"), prefer it.  This makes `revoke-key` consistent with the
     * operator's chosen default on boxes that enrolled multiple CAs. */
    snprintf(default_path, sizeof(default_path), "%s/default", tpm_dir);
    if (stat(default_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        ssize_t rl = readlink(default_path, resolved, sizeof(resolved) - 1);
        if (rl > 0) {
            resolved[rl] = '\0';
            size_t rlen = strlen(resolved);
            if (rlen >= 3 && strcmp(resolved + rlen - 3, "-ca") == 0) {
                size_t plen = strlen(tpm_dir) + 1 + rlen + 1;
                found = (char *)malloc(plen);
                if (found) {
                    snprintf(found, plen, "%s/%s", tpm_dir, resolved);
                    return found;
                }
            }
        }
    }

    d = opendir(tpm_dir);
    if (!d) return NULL;
    while ((de = readdir(d)) != NULL) {
        size_t nlen;
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "default") == 0) continue;  /* symlink pointer */
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
        fprintf(stderr,
                "Error: multiple CA identities found under %s — "
                "pass --ca-tpm-path to choose one, or set a default "
                "symlink with `ln -sfn <dir> %s/default`\n",
                tpm_dir, tpm_dir);
        if (found) { free(found); found = NULL; }
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* sign_message                                                       */
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
    if (der_sz <= 0) {
        fprintf(stderr, "[revoke-key] PEM→DER failed (%d)\n", der_sz);
        return -1;
    }

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "[revoke-key] RNG init failed\n");
        return -1;
    }
    rng_ok = 1;

    if (strcmp(algo, "EC-P256") == 0 || strcmp(algo, "EC-P384") == 0) {
        ecc_key ecc;
        word32 idx = 0;
        uint8_t hash[32];
        wc_Sha256 sha;

        wc_ecc_init(&ecc);
        ret = wc_EccPrivateKeyDecode(der_buf, &idx, &ecc, (word32)der_sz);
        if (ret != 0) { wc_ecc_free(&ecc); goto fail; }
        ret = wc_ecc_set_rng(&ecc, &rng);
        if (ret != 0) { wc_ecc_free(&ecc); goto fail; }

        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, (const uint8_t *)msg, (word32)strlen(msg));
        wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);

        ret = wc_ecc_sign_hash(hash, 32, sig_out, &out_len, &rng, &ecc);
        wc_ecc_free(&ecc);
        if (ret != 0) goto fail;
    }
    else if (strcmp(algo, "Ed25519") == 0) {
        ed25519_key ed;
        word32 idx = 0;

        wc_ed25519_init(&ed);
        ret = wc_Ed25519PrivateKeyDecode(der_buf, &idx, &ed, (word32)der_sz);
        if (ret != 0) { wc_ed25519_free(&ed); goto fail; }
        ret = wc_ed25519_sign_msg((const uint8_t *)msg, (word32)strlen(msg),
                                  sig_out, &out_len, &ed);
        wc_ed25519_free(&ed);
        if (ret != 0) goto fail;
    }
    else if (strncmp(algo, "ML-DSA-", 7) == 0) {
        dilithium_key dil;
        byte level;
        word32 idx = 0;

        if (strcmp(algo, "ML-DSA-44") == 0)       level = WC_ML_DSA_44;
        else if (strcmp(algo, "ML-DSA-65") == 0)  level = WC_ML_DSA_65;
        else if (strcmp(algo, "ML-DSA-87") == 0)  level = WC_ML_DSA_87;
        else { ret = -1; goto fail; }

        wc_dilithium_init(&dil);
        wc_dilithium_set_level(&dil, level);
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
        fprintf(stderr, "[revoke-key] unsupported algorithm '%s'\n", algo);
        ret = -1;
        goto fail;
    }

    wc_FreeRng(&rng);
    return (int)out_len;

fail:
    if (rng_ok) wc_FreeRng(&rng);
    fprintf(stderr, "[revoke-key] signing failed (%d)\n", ret);
    return -1;
}

/* ------------------------------------------------------------------ */
/* mqc_http_post                                                      */
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
    if (!conn) {
        fprintf(stderr, "Error: mqc_connect to %s:%d failed\n",
                g_mqc_host, g_mqc_port);
        return NULL;
    }

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
/* usage + main                                                       */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Revoke a leaf certificate, list revoked certs in a domain, or\n"
        "refresh the local per-peer revocation cache.\n"
        "\n"
        "Usage:\n"
        "  %s --target-index N [--reason \"text\"] [options]   Revoke one leaf\n"
        "  %s --list DOMAIN [options]                        List revoked leaves in DOMAIN\n"
        "  %s --refresh [options]                            Refresh ~/.TPM/peers/*/revoked.json\n"
        "\n"
        "  --target-index N      Log index of the leaf to revoke\n"
        "  --list DOMAIN         Enumerate revoked leaves whose subject is\n"
        "                         DOMAIN or *.DOMAIN\n"
        "  --refresh             Re-pull /revoked and update every cached peer's\n"
        "                         ~/.TPM/peers/<n>/revoked.json (resets TTL)\n"
        "  --reason TEXT         Human-readable revocation reason (default: empty)\n"
        "  --ca-tpm-path PATH    Override CA identity dir for revoke mode\n"
        "                         (default: auto-detect *-ca under ~/.TPM/)\n"
        "  -s, --server H:P      Server (default: factsorlie.com:8446).  --list and\n"
        "                         --refresh use the bootstrap port (8445) on the\n"
        "                         same host — no CA identity needed.\n"
        "  --dry-run             Print the revoke request without sending\n"
        "                         (no effect with --list or --refresh)\n"
        "  --trace               Show MQC protocol-level trace\n"
        "  -h, --help            Show this help\n",
        prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/* --list <domain>  handler                                           */
/* ------------------------------------------------------------------ */

/*
 * Return 1 if subject equals domain or ends in ".domain", else 0.
 */
static int subject_in_domain(const char *subject, const char *domain)
{
    size_t sl = strlen(subject);
    size_t dl = strlen(domain);
    if (sl == dl && strcmp(subject, domain) == 0) return 1;
    if (sl > dl + 1 &&
        subject[sl - dl - 1] == '.' &&
        strcmp(subject + sl - dl, domain) == 0) return 1;
    return 0;
}

static int do_list_mode(const char *domain, const char *server_arg)
{
    long code = 0;
    char *body = NULL;
    struct json_object *rev = NULL, *arr = NULL, *count_val = NULL;
    int i, total, matched = 0;

    /* GET /revoked over bootstrap port (no identity needed) */
    body = mqc_bootstrap_http_get(server_arg, "/revoked", &code);
    if (!body || code != 200) {
        fprintf(stderr, "Error: GET /revoked failed (code=%ld)\n", code);
        free(body);
        return 1;
    }
    rev = json_tokener_parse(body);
    free(body);
    if (!rev || !json_object_object_get_ex(rev, "revoked", &arr) ||
        json_object_get_type(arr) != json_type_array) {
        fprintf(stderr, "Error: malformed /revoked response\n");
        if (rev) json_object_put(rev);
        return 1;
    }

    total = (int)json_object_array_length(arr);
    if (json_object_object_get_ex(rev, "count", &count_val))
        total = json_object_get_int(count_val);

    printf("Revoked leaves in domain '%s':\n", domain);
    printf("  (scanning %d revoked cert(s) in the log)\n", total);

    for (i = 0; i < (int)json_object_array_length(arr); i++) {
        struct json_object *idx_val = json_object_array_get_idx(arr, i);
        int cert_index = json_object_get_int(idx_val);
        char path[64];
        char *cert_body;
        long cert_code = 0;
        struct json_object *cert = NULL, *sc, *tbs, *s_val, *alg_val;

        snprintf(path, sizeof(path), "/certificate/%d", cert_index);
        cert_body = mqc_bootstrap_http_get(server_arg, path, &cert_code);
        if (!cert_body || cert_code != 200) {
            fprintf(stderr, "  [skip] cert %d: fetch failed (code=%ld)\n",
                    cert_index, cert_code);
            free(cert_body);
            continue;
        }
        cert = json_tokener_parse(cert_body);
        free(cert_body);
        if (!cert ||
            !json_object_object_get_ex(cert, "standalone_certificate", &sc) ||
            !json_object_object_get_ex(sc, "tbs_entry", &tbs) ||
            !json_object_object_get_ex(tbs, "subject", &s_val)) {
            if (cert) json_object_put(cert);
            continue;
        }
        {
            const char *subject = json_object_get_string(s_val);
            const char *algo = "?";
            if (json_object_object_get_ex(tbs,
                    "subject_public_key_algorithm", &alg_val))
                algo = json_object_get_string(alg_val);
            if (subject_in_domain(subject, domain)) {
                /* Also filter out CAs — -ca subjects aren't leaves */
                size_t sl = strlen(subject);
                if (sl >= 3 && strcmp(subject + sl - 3, "-ca") == 0) {
                    /* CA revocations shouldn't happen via this tool, but
                     * show them anyway in case the log has historical ones. */
                    printf("  #%-4d  %-40s  %s  [CA — unusual]\n",
                           cert_index, subject, algo);
                } else {
                    printf("  #%-4d  %-40s  %s\n",
                           cert_index, subject, algo);
                }
                matched++;
            }
        }
        json_object_put(cert);
    }

    printf("  %d match%s.\n", matched, matched == 1 ? "" : "es");
    json_object_put(rev);
    return 0;
}

/* ------------------------------------------------------------------ */
/* --refresh  handler                                                 */
/* ------------------------------------------------------------------ */

static int is_revoked_in_list(struct json_object *arr, int idx)
{
    int n = (int)json_object_array_length(arr);
    int i;
    for (i = 0; i < n; i++) {
        if (json_object_get_int(json_object_array_get_idx(arr, i)) == idx)
            return 1;
    }
    return 0;
}

static int do_refresh_mode(const char *server_arg)
{
    long code = 0;
    char *body = NULL;
    struct json_object *rev = NULL, *arr = NULL;
    const char *home;
    char peers_dir[512];
    DIR *d;
    struct dirent *de;
    int updated = 0, marked_revoked = 0;

    /* Single GET /revoked — gives us the whole index set in one round trip. */
    body = mqc_bootstrap_http_get(server_arg, "/revoked", &code);
    if (!body || code != 200) {
        fprintf(stderr, "Error: GET /revoked failed (code=%ld)\n", code);
        free(body);
        return 1;
    }
    rev = json_tokener_parse(body);
    free(body);
    if (!rev || !json_object_object_get_ex(rev, "revoked", &arr) ||
        json_object_get_type(arr) != json_type_array) {
        fprintf(stderr, "Error: malformed /revoked response\n");
        if (rev) json_object_put(rev);
        return 1;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(peers_dir, sizeof(peers_dir), "%s/.TPM/peers", home);

    d = opendir(peers_dir);
    if (!d) {
        printf("No peer cache at %s — nothing to refresh.\n", peers_dir);
        json_object_put(rev);
        return 0;
    }

    while ((de = readdir(d)) != NULL) {
        char cache_path[768];
        int cert_index;
        int revoked_flag;
        struct stat st;
        FILE *f;

        if (de->d_name[0] == '.') continue;
        /* Only numeric subdirs are per-peer caches. */
        cert_index = atoi(de->d_name);
        if (cert_index < 0) continue;
        if (cert_index == 0 && strcmp(de->d_name, "0") != 0) continue;

        snprintf(cache_path, sizeof(cache_path), "%s/%d",
                 peers_dir, cert_index);
        if (stat(cache_path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        revoked_flag = is_revoked_in_list(arr, cert_index);

        snprintf(cache_path, sizeof(cache_path), "%s/%d/revoked.json",
                 peers_dir, cert_index);
        f = fopen(cache_path, "w");
        if (!f) {
            fprintf(stderr, "  [warn] cannot write %s: %s\n",
                    cache_path, strerror(errno));
            continue;
        }
        fprintf(f, "{\"revoked\":%s}\n", revoked_flag ? "true" : "false");
        fclose(f);
        updated++;
        if (revoked_flag) marked_revoked++;
    }
    closedir(d);

    printf("Refreshed %d peer revocation cache entr%s "
           "(%d marked revoked, %d clean).\n",
           updated, updated == 1 ? "y" : "ies",
           marked_revoked, updated - marked_revoked);
    json_object_put(rev);
    return 0;
}

int main(int argc, char **argv)
{
    const char *server       = DEFAULT_SERVER;
    const char *ca_tpm_path  = NULL;
    const char *reason       = "";
    const char *list_domain  = NULL;
    int target_index = -1;
    int dry_run = 0;
    int trace   = 0;
    int refresh_mode = 0;
    int i;
    const char *home;
    char tpm_root[1024];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target-index") == 0 && i + 1 < argc)
            target_index = atoi(argv[++i]);
        else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc)
            list_domain = argv[++i];
        else if (strcmp(argv[i], "--refresh") == 0)
            refresh_mode = 1;
        else if (strcmp(argv[i], "--reason") == 0 && i + 1 < argc)
            reason = argv[++i];
        else if (strcmp(argv[i], "--ca-tpm-path") == 0 && i + 1 < argc)
            ca_tpm_path = argv[++i];
        else if ((strcmp(argv[i], "-s") == 0 ||
                  strcmp(argv[i], "--server") == 0) && i + 1 < argc)
            server = argv[++i];
        else if (strcmp(argv[i], "--dry-run") == 0)
            dry_run = 1;
        else if (strcmp(argv[i], "--trace") == 0)
            trace = 1;
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* Mutually-exclusive mode check */
    {
        int modes = (list_domain ? 1 : 0) + (refresh_mode ? 1 : 0)
                  + (target_index >= 0 ? 1 : 0);
        if (modes > 1) {
            fprintf(stderr,
                "Error: --list, --refresh, and --target-index are "
                "mutually exclusive\n");
            return 1;
        }
    }

    /* --list mode: no CA identity needed, pure public read */
    if (list_domain) {
        return do_list_mode(list_domain, server);
    }

    /* --refresh mode: no CA identity needed, pure public read */
    if (refresh_mode) {
        return do_refresh_mode(server);
    }

    if (target_index < 0) {
        fprintf(stderr,
            "Error: one of --target-index, --list, or --refresh is required\n");
        usage(argv[0]);
        return 1;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(tpm_root, sizeof(tpm_root), "%s/%s", home, DEFAULT_TPM_DIR);

    char *ca_tpm_owned = NULL;
    if (!ca_tpm_path) {
        ca_tpm_owned = auto_detect_ca_tpm(tpm_root);
        if (!ca_tpm_owned) {
            fprintf(stderr,
                "Error: no CA identity found under %s (looking for *-ca) — "
                "pass --ca-tpm-path\n", tpm_root);
            return 1;
        }
        ca_tpm_path = ca_tpm_owned;
    }

    /* Load CA identity */
    char path_buf[1100];
    char *privkey_pem = NULL;
    char *pubkey_pem  = NULL;
    char *cert_json_s = NULL;
    char *index_str   = NULL;
    int   ca_cert_index = -1;
    struct json_object *cert_json = NULL, *sc = NULL, *tbs = NULL, *val = NULL;
    const char *algo     = "EC-P256";
    const char *ca_subj  = NULL;

    snprintf(path_buf, sizeof(path_buf), "%s/private_key.pem", ca_tpm_path);
    privkey_pem = read_text(path_buf);
    if (!privkey_pem) {
        fprintf(stderr, "Error: cannot read %s\n", path_buf);
        free(ca_tpm_owned);
        return 1;
    }

    snprintf(path_buf, sizeof(path_buf), "%s/public_key.pem", ca_tpm_path);
    pubkey_pem = read_text(path_buf);
    if (!pubkey_pem) {
        fprintf(stderr, "Error: cannot read %s\n", path_buf);
        free(privkey_pem); free(ca_tpm_owned);
        return 1;
    }

    snprintf(path_buf, sizeof(path_buf), "%s/certificate.json", ca_tpm_path);
    cert_json_s = read_text(path_buf);
    if (!cert_json_s) {
        fprintf(stderr, "Error: cannot read %s\n", path_buf);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }
    cert_json = json_tokener_parse(cert_json_s);
    free(cert_json_s);
    if (!cert_json ||
        !json_object_object_get_ex(cert_json, "standalone_certificate", &sc) ||
        !json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        fprintf(stderr, "Error: malformed CA certificate.json\n");
        if (cert_json) json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }
    if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
        algo = strdup(json_object_get_string(val));
    if (json_object_object_get_ex(tbs, "subject", &val))
        ca_subj = strdup(json_object_get_string(val));

    snprintf(path_buf, sizeof(path_buf), "%s/index", ca_tpm_path);
    index_str = read_text(path_buf);
    if (!index_str) {
        fprintf(stderr, "Error: cannot read %s\n", path_buf);
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }
    ca_cert_index = atoi(index_str);
    free(index_str);

    /* Sanity checks the server will also enforce */
    if (ca_subj) {
        size_t sl = strlen(ca_subj);
        if (sl < 3 || strcmp(ca_subj + sl - 3, "-ca") != 0) {
            fprintf(stderr,
                "Error: loaded identity '%s' is not a CA "
                "(subject must end in -ca)\n", ca_subj);
            json_object_put(cert_json);
            free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
            return 1;
        }
    }
    if (ca_cert_index == target_index) {
        fprintf(stderr, "Error: a CA may not revoke itself\n");
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }

    /* --- Parse --server host:port --- */
    {
        static char host_buf[256];
        char *colon;
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        colon = strrchr(host_buf, ':');
        if (colon) { *colon = '\0'; g_mqc_port = atoi(colon + 1); }
        g_mqc_host = host_buf;
    }

    /* --- Build sign_msg + sign with CA's key --- */
    long timestamp = (long)time(NULL);
    char sign_msg[512];
    snprintf(sign_msg, sizeof(sign_msg), "revoke:%d:%d:%s:%ld",
             ca_cert_index, target_index, reason, timestamp);

    uint8_t sig_buf[8192];
    int sig_len = sign_message(privkey_pem, algo, sign_msg,
                               sig_buf, (int)sizeof(sig_buf));
    if (sig_len < 0) {
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }
    char *sig_hex = (char *)malloc((size_t)sig_len * 2 + 1);
    if (!sig_hex) {
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 1;
    }
    to_hex(sig_buf, sig_len, sig_hex);

    /* --- Build request JSON --- */
    struct json_object *req = json_object_new_object();
    json_object_object_add(req, "ca_cert_index",
                           json_object_new_int(ca_cert_index));
    json_object_object_add(req, "cert_index",
                           json_object_new_int(target_index));
    json_object_object_add(req, "reason",
                           json_object_new_string(reason));
    json_object_object_add(req, "timestamp",
                           json_object_new_int64(timestamp));
    json_object_object_add(req, "ca_public_key_pem",
                           json_object_new_string(pubkey_pem));
    json_object_object_add(req, "signature",
                           json_object_new_string(sig_hex));

    const char *req_str = json_object_to_json_string_ext(
        req, JSON_C_TO_STRING_PLAIN);
    char *body_copy = strdup(req_str);
    int   body_len  = (int)strlen(body_copy);

    printf("\nRevoke request:\n");
    printf("  CA subject:     %s\n", ca_subj ? ca_subj : "(unknown)");
    printf("  CA index:       %d\n", ca_cert_index);
    printf("  Target index:   %d\n", target_index);
    printf("  Algorithm:      %s\n", algo);
    printf("  Reason:         %s\n", reason[0] ? reason : "(none)");
    printf("  Timestamp:      %ld\n", timestamp);
    printf("  Signature:      %.32s... (%d bytes)\n", sig_hex, sig_len);

    free(sig_hex);
    json_object_put(req);

    if (dry_run) {
        printf("\n*** DRY RUN — would POST /revoke to %s:%d ***\n",
               g_mqc_host, g_mqc_port);
        free(body_copy);
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return 0;
    }

    /* --- MQC context — connect as the CA identity --- */
    if (trace) mqc_set_verbose(1);

    {
        mqc_cfg_t cfg;
        static unsigned char ca_pubkey[32];

        if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
            fprintf(stderr, "Error: could not load CA cosigner pubkey\n");
            free(body_copy);
            json_object_put(cert_json);
            free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
            return 1;
        }

        memset(&cfg, 0, sizeof(cfg));
        cfg.role         = MQC_CLIENT;
        cfg.tpm_path     = ca_tpm_path;
        cfg.mtc_server   = server;
        cfg.ca_pubkey    = ca_pubkey;
        cfg.ca_pubkey_sz = 32;

        g_mqc_ctx = mqc_ctx_new(&cfg);
        if (!g_mqc_ctx) {
            fprintf(stderr, "Error: MQC context creation failed\n");
            free(body_copy);
            json_object_put(cert_json);
            free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
            return 1;
        }
    }

    {
        long code = 0;
        char *resp_body;
        struct json_object *resp;
        int rc = 0;

        resp_body = mqc_http_post("/revoke", body_copy, body_len, &code);
        free(body_copy);
        if (!resp_body) {
            fprintf(stderr, "Error: POST /revoke over MQC failed\n");
            rc = 1;
            goto done;
        }
        if (code != 200) {
            fprintf(stderr, "\nServer returned HTTP %ld:\n%s\n",
                    code, resp_body);
            free(resp_body);
            rc = 1;
            goto done;
        }

        resp = json_tokener_parse(resp_body);
        printf("\nRevocation accepted:\n%s\n",
               resp ? json_object_to_json_string_ext(resp,
                         JSON_C_TO_STRING_PRETTY) : resp_body);
        if (resp) json_object_put(resp);
        free(resp_body);

    done:
        mqc_ctx_free(g_mqc_ctx);
        json_object_put(cert_json);
        free(privkey_pem); free(pubkey_pem); free(ca_tpm_owned);
        return rc;
    }
}
