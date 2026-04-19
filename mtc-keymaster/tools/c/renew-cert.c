/******************************************************************************
 * File:        renew-cert.c
 * Purpose:     MQC client — request a renewed certificate.
 *
 * Description:
 *   Opens an MQC connection from an existing TPM identity, POSTs the new
 *   public key to /renew-cert, writes the resulting standalone_certificate
 *   JSON to stdout or --out.
 *
 *   Authorization is entirely the MQC handshake: the server reads
 *   mqc_get_peer_index() from the authenticated connection and renews that
 *   cert_index.  The request body carries only the new public key (and an
 *   optional validity_days).  There is no cert_index, no signature, and no
 *   nonce in the body.
 *
 * Usage:
 *   renew-cert --new-pubkey FILE.pem
 *              [--tpm-path PATH]            (default: ~/.TPM/default or first
 *                                            non-reserved dir under ~/.TPM)
 *              [--validity-days N]          (default: server-side, 90)
 *              [-s, --server HOST:PORT]     (default: factsorlie.com:8446)
 *              [--out PATH]                 (default: stdout)
 *              [--trace]                    (MQC protocol trace)
 *              [-h, --help]
 *
 * Created:     2026-04-19
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"

#include "../../../socket-level-wrapper-MQC/config.h"
#define DEFAULT_SERVER    MQC_DEFAULT_SERVER
#define DEFAULT_TPM_DIR   ".TPM"

static mqc_ctx_t  *g_mqc_ctx  = NULL;
static const char *g_mqc_host = "localhost";
static int         g_mqc_port = 8446;

/* ------------------------------------------------------------------ */
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
 * auto_detect_tpm:
 *   Prefer ~/.TPM/default if it resolves; otherwise return the first
 *   non-reserved subdirectory.  Returns a malloc'd path, NULL on failure.
 */
static char *auto_detect_tpm(const char *tpm_dir)
{
    struct stat st;
    char default_path[2048];
    DIR *d;
    struct dirent *de;

    snprintf(default_path, sizeof(default_path), "%s/default", tpm_dir);
    if (stat(default_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return strdup(default_path);
    }

    d = opendir(tpm_dir);
    if (!d) return NULL;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "default") == 0) continue;
        if (strcmp(de->d_name, "peers")   == 0) continue;
        if (strcmp(de->d_name, "ech")     == 0) continue;
        {
            size_t plen = strlen(tpm_dir) + 1 + strlen(de->d_name) + 1;
            char *found = (char *)malloc(plen);
            if (!found) { closedir(d); return NULL; }
            snprintf(found, plen, "%s/%s", tpm_dir, de->d_name);
            closedir(d);
            return found;
        }
    }
    closedir(d);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* mqc_http_post — identical pattern to revoke-key.c:267              */
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
/* usage                                                              */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Renew a certificate via MQC (post-quantum authenticated) POST\n"
        "/renew-cert.  Authentication is the MQC handshake itself — no\n"
        "nonce, no old-key signature.  The caller's peer_index is what\n"
        "gets renewed.\n"
        "\n"
        "Usage:\n"
        "  %s --new-pubkey FILE.pem [options]\n"
        "\n"
        "  --new-pubkey FILE    New public key (PEM) to bind to the renewed cert\n"
        "  --tpm-path PATH      TPM identity to renew (default: ~/.TPM/default\n"
        "                        or first non-reserved dir under ~/.TPM)\n"
        "  --validity-days N    Requested validity window, 1..3650 (default 90)\n"
        "  -s, --server H:P     Server (default: factsorlie.com:8446)\n"
        "  --out PATH           Write standalone_certificate JSON here\n"
        "                        (default: stdout)\n"
        "  --trace              Show MQC protocol-level trace\n"
        "  -h, --help           Show this help\n",
        prog);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *tpm_path    = NULL;
    const char *new_pubkey  = NULL;
    const char *server      = DEFAULT_SERVER;
    const char *out_path    = NULL;
    int         validity    = 0;   /* 0 = don't send; server default */
    int         trace       = 0;
    char        tpm_root[1024];
    const char *home;
    char       *tpm_owned   = NULL;
    char       *new_pubkey_pem = NULL;
    int         rc = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--new-pubkey") == 0 && i + 1 < argc) {
            new_pubkey = argv[++i];
        } else if (strcmp(argv[i], "--tpm-path") == 0 && i + 1 < argc) {
            tpm_path = argv[++i];
        } else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc) {
            validity = atoi(argv[++i]);
            if (validity < 1 || validity > 3650) {
                fprintf(stderr, "Error: --validity-days must be 1..3650\n");
                return 2;
            }
        } else if ((strcmp(argv[i], "-s") == 0 ||
                    strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--trace") == 0) {
            trace = 1;
        } else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!new_pubkey) {
        fprintf(stderr, "Error: --new-pubkey is required\n");
        usage(argv[0]);
        return 2;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(tpm_root, sizeof(tpm_root), "%s/%s", home, DEFAULT_TPM_DIR);

    if (!tpm_path) {
        tpm_owned = auto_detect_tpm(tpm_root);
        if (!tpm_owned) {
            fprintf(stderr,
                "Error: no TPM identity found under %s — pass --tpm-path\n",
                tpm_root);
            return 2;
        }
        tpm_path = tpm_owned;
    }

    new_pubkey_pem = read_text(new_pubkey);
    if (!new_pubkey_pem) {
        fprintf(stderr, "Error: cannot read %s: %s\n",
                new_pubkey, strerror(errno));
        free(tpm_owned);
        return 2;
    }

    /* Log what we're about to renew */
    {
        char path_buf[1100];
        char *idx_str;
        snprintf(path_buf, sizeof(path_buf), "%s/index", tpm_path);
        idx_str = read_text(path_buf);
        fprintf(stderr, "[renew-cert] tpm=%s index=%s → %s:%s\n",
                tpm_path,
                idx_str ? idx_str : "(?)",
                server, "/renew-cert");
        if (idx_str) free(idx_str);
    }

    /* Parse --server host:port */
    {
        static char host_buf[256];
        char *colon;
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        colon = strrchr(host_buf, ':');
        if (colon) { *colon = '\0'; g_mqc_port = atoi(colon + 1); }
        g_mqc_host = host_buf;
    }

    /* Build request JSON */
    {
        struct json_object *req = json_object_new_object();
        const char *req_str;
        char *body_copy;
        int body_len;
        long code = 0;
        char *resp_body = NULL;

        json_object_object_add(req, "new_public_key_pem",
                               json_object_new_string(new_pubkey_pem));
        if (validity > 0)
            json_object_object_add(req, "validity_days",
                                   json_object_new_int(validity));

        req_str = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);
        body_copy = strdup(req_str);
        body_len = (int)strlen(body_copy);
        json_object_put(req);

        /* Build MQC context using this TPM identity */
        if (trace) mqc_set_verbose(1);
        {
            mqc_cfg_t cfg;
            static unsigned char ca_pubkey[32];

            if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
                fprintf(stderr, "Error: could not load CA cosigner pubkey\n");
                free(body_copy);
                free(new_pubkey_pem);
                free(tpm_owned);
                return 1;
            }

            memset(&cfg, 0, sizeof(cfg));
            cfg.role         = MQC_CLIENT;
            cfg.tpm_path     = tpm_path;
            cfg.mtc_server   = server;
            cfg.ca_pubkey    = ca_pubkey;
            cfg.ca_pubkey_sz = 32;

            g_mqc_ctx = mqc_ctx_new(&cfg);
            if (!g_mqc_ctx) {
                fprintf(stderr, "Error: MQC context creation failed\n");
                free(body_copy);
                free(new_pubkey_pem);
                free(tpm_owned);
                return 1;
            }
        }

        resp_body = mqc_http_post("/renew-cert", body_copy, body_len, &code);
        free(body_copy);

        if (!resp_body) {
            fprintf(stderr, "Error: POST /renew-cert over MQC failed\n");
            rc = 1;
            goto done;
        }

        if (code != 200 && code != 201) {
            fprintf(stderr, "Server returned HTTP %ld:\n%s\n",
                    code, resp_body);
            free(resp_body);
            rc = 1;
            goto done;
        }

        if (out_path) {
            FILE *f = fopen(out_path, "wb");
            if (!f) {
                fprintf(stderr, "Error: cannot write %s: %s\n",
                        out_path, strerror(errno));
                free(resp_body);
                rc = 1;
                goto done;
            }
            fwrite(resp_body, 1, strlen(resp_body), f);
            fclose(f);
            fprintf(stderr, "[renew-cert] wrote %s (%zu bytes)\n",
                    out_path, strlen(resp_body));
        } else {
            fputs(resp_body, stdout);
            fputc('\n', stdout);
        }
        free(resp_body);

    done:
        mqc_ctx_free(g_mqc_ctx);
    }

    free(new_pubkey_pem);
    free(tpm_owned);
    return rc;
}
