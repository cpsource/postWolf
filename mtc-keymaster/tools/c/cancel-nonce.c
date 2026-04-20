/******************************************************************************
 * File:        cancel-nonce.c
 * Purpose:     CA operator tool — retract a pending reservation nonce early.
 *
 * Description:
 *   A reservation nonce (`issue_leaf_nonce --ttl-days N --label L`) binds
 *   the slot (domain, label) until it's consumed or the TTL expires.
 *   If the recipient loses the nonce, leaves the team, or was issued the
 *   wrong label, the CA operator needs a way to free the slot before TTL
 *   expiry so they can issue a fresh reservation.
 *
 *   This tool does exactly that: it opens an MQC connection as the CA
 *   identity, POSTs /cancel-nonce on port 8446 with the (domain, label)
 *   to cancel.  The server verifies the caller's MQC peer_index matches
 *   the nonce's stored ca_index (only the issuing CA can cancel) and
 *   atomically flips the row from 'pending' to 'expired'.  Once
 *   cancelled, issue_leaf_nonce can re-issue for the same label.
 *
 *   Authorization (enforced server-side):
 *     - Caller must present a valid MQC identity (no TLS/DH fallback).
 *     - Caller's cert subject must end in "-ca".
 *     - Caller's cert_index must match the nonce's stored ca_index.
 *
 * Usage:
 *   cancel-nonce --domain DOMAIN --label LABEL [options]
 *
 *     --domain DOMAIN       Domain the reservation was issued for
 *     --label LABEL         Label the reservation was pinned to
 *     --ca-tpm-path PATH    CA identity dir (default: auto-detect under ~/.TPM)
 *     -s, --server H:P      Server (default: factsorlie.com:8446)
 *     --trace               MQC protocol trace
 *     -h, --help            Show this help
 *
 * Created:     2026-04-20
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>

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
/* auto_detect_ca_tpm — same semantics as revoke-key.c's helper:
 *   Prefer ~/.TPM/default if it resolves to a *-ca directory.
 *   Otherwise scan ~/.TPM for a single *-ca entry.
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
/* mqc_http_post — same shape as revoke-key.c / renew-cert.c          */
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
static void usage(const char *prog)
{
    fprintf(stderr,
        "Cancel a pending reservation nonce (long-lived nonce issued\n"
        "by `issue_leaf_nonce --ttl-days N --label L`).  Only the CA\n"
        "that issued the reservation can cancel it.\n"
        "\n"
        "Usage:\n"
        "  %s --domain DOMAIN --label LABEL [options]\n"
        "\n"
        "  --domain DOMAIN       Domain the reservation was issued for\n"
        "  --label LABEL         Label the reservation was pinned to\n"
        "  --ca-tpm-path PATH    CA identity dir\n"
        "                        (default: auto-detect *-ca under ~/.TPM/)\n"
        "  -s, --server H:P      Server (default: %s)\n"
        "  --dry-run             Print the request but don't send it\n"
        "                        (no MQC connect, no DB change)\n"
        "  --trace               Show MQC protocol-level trace\n"
        "  -h, --help            Show this help\n",
        prog, DEFAULT_SERVER);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *domain = NULL;
    const char *label = NULL;
    const char *server = DEFAULT_SERVER;
    const char *ca_tpm_path = NULL;
    int trace = 0;
    int dry_run = 0;
    int i, rc = 0;
    char tpm_root[1024];
    const char *home;
    char *ca_tpm_owned = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            domain = argv[++i];
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            label = argv[++i];
        } else if ((strcmp(argv[i], "-s") == 0 ||
                    strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--ca-tpm-path") == 0 && i + 1 < argc) {
            ca_tpm_path = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--trace") == 0) {
            trace = 1;
        } else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!domain || !label) {
        fprintf(stderr, "Error: --domain and --label are both required\n");
        usage(argv[0]);
        return 2;
    }

    /* --- Resolve CA identity dir --- */
    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(tpm_root, sizeof(tpm_root), "%s/%s", home, DEFAULT_TPM_DIR);

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

    /* --- Parse --server host:port --- */
    {
        static char host_buf[256];
        char *colon;
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        colon = strrchr(host_buf, ':');
        if (colon) { *colon = '\0'; g_mqc_port = atoi(colon + 1); }
        g_mqc_host = host_buf;
    }

    /* --- Build request JSON --- */
    char *body_copy;
    int body_len;
    {
        struct json_object *req = json_object_new_object();
        const char *req_str;
        json_object_object_add(req, "domain", json_object_new_string(domain));
        json_object_object_add(req, "label",  json_object_new_string(label));
        req_str = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);
        body_copy = strdup(req_str);
        body_len = (int)strlen(body_copy);
        json_object_put(req);
    }

    printf("Cancel reservation:\n");
    printf("  Domain:       %s\n", domain);
    printf("  Label:        %s\n", label);
    printf("  CA identity:  %s\n", ca_tpm_path);
    printf("  Server:       %s:%d\n", g_mqc_host, g_mqc_port);

    if (dry_run) {
        printf("\n*** DRY RUN — would POST /cancel-nonce over MQC ***\n");
        printf("Request body: %s\n", body_copy);
        free(body_copy);
        free(ca_tpm_owned);
        return 0;
    }

    /* --- MQC context using the CA identity --- */
    if (trace) mqc_set_verbose(1);
    {
        mqc_cfg_t cfg;
        static unsigned char ca_pubkey[32];

        if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
            fprintf(stderr, "Error: could not load CA cosigner pubkey\n");
            free(body_copy);
            free(ca_tpm_owned);
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
            free(ca_tpm_owned);
            return 1;
        }
    }

    {
        long code = 0;
        char *resp_body;

        resp_body = mqc_http_post("/cancel-nonce", body_copy, body_len, &code);
        free(body_copy);
        if (!resp_body) {
            fprintf(stderr, "Error: POST /cancel-nonce over MQC failed\n");
            rc = 1;
            goto done;
        }
        if (code == 200) {
            printf("\nCancelled.\n%s\n", resp_body);
            rc = 0;
        } else if (code == 404) {
            fprintf(stderr, "\nNo matching pending reservation "
                    "(HTTP %ld):\n%s\n", code, resp_body);
            rc = 1;  /* distinct failure code */
        } else {
            fprintf(stderr, "\nServer returned HTTP %ld:\n%s\n",
                    code, resp_body);
            rc = 1;
        }
        free(resp_body);
    }

done:
    if (g_mqc_ctx) mqc_ctx_free(g_mqc_ctx);
    free(ca_tpm_owned);
    return rc;
}
