/******************************************************************************
 * File:        check-renewal-cert.c
 * Purpose:     Daily driver — walk ~/.TPM and renew any identity that's within
 *              MTC_RENEWAL_WINDOW_DAYS of expiry and not revoked.
 *
 * Description:
 *   For each identity dir under ~/.TPM (skipping peers, ech, default,
 *   hidden):
 *     1. Read certificate.json, extract not_after.
 *     2. If not within the renewal window, skip.
 *     3. Open MQC to the server as this identity, GET /revoked/<index>.
 *        If revoked, log a warning and skip — operator must re-enroll.
 *     4. Classify CA vs leaf (dir name ending in -ca).
 *     5. Invoke create_leaf_keypair.py or create_ca_cert.py to produce a new
 *        keypair in ~/.mtc-ca-data/<subject>/.
 *     6. Invoke renew-cert to fetch a fresh standalone_certificate bound
 *        to the new public key.
 *     7. Atomically swap new material into ~/.TPM/<dir>/, keeping the old
 *        material in <dir>/.renew.bak/ until the swap completes.
 *
 *   Exit codes:
 *     0 — every identity was either renewed or intentionally skipped (no
 *         revocations, no failures)
 *     1 — at least one identity failed (revoked, renew-cert error, swap
 *         failure) — cron mail should page
 *     2 — config / invocation error
 *
 * Usage:
 *   check-renewal-cert [--dry-run] [--force DIR] [--window-days N]
 *                      [--tpm-base PATH] [-s, --server H:P]
 *                      [--trace] [-v] [-h, --help]
 *
 * Created:     2026-04-19
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"

#include "../../../socket-level-wrapper-MQC/config.h"
#include "../../server2/c/config.h"   /* MTC_RENEWAL_WINDOW_DAYS */

#define DEFAULT_SERVER   MQC_DEFAULT_SERVER
#define DEFAULT_TPM_DIR  ".TPM"
#define PYTHON_LEAF      "/usr/local/bin/create_leaf_keypair.py"
#define PYTHON_CA        "/usr/local/bin/create_ca_cert.py"
#define RENEW_CERT_BIN   "/usr/local/bin/renew-cert"

static int g_verbose = 0;
static int g_trace   = 0;

/* ------------------------------------------------------------------ */
static char *read_text(const char *path)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;
    size_t nread;
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

static int write_text(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fputs(data, f) < 0) { fclose(f); return -1; }
    return fclose(f) == 0 ? 0 : -1;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
    FILE *in = fopen(src, "rb");
    FILE *out;
    char buf[4096];
    size_t n;
    if (!in) return -1;
    out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in); fclose(out); return -1;
        }
    }
    fclose(in); fclose(out);
    if (chmod(dst, mode) != 0) return -1;
    return 0;
}

/* Run an argv through fork/execv, return child exit status (or -1). */
static int run_command(char *const argv[])
{
    pid_t pid;
    int status;

    if (g_verbose) {
        fprintf(stderr, "[check-renewal-cert] exec:");
        for (int i = 0; argv[i]; i++)
            fprintf(stderr, " %s", argv[i]);
        fputc('\n', stderr);
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[check-renewal-cert] fork failed: %s\n",
                strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execv(argv[0], argv);
        fprintf(stderr, "[check-renewal-cert] execv %s failed: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

/* ------------------------------------------------------------------ */
/* mqc_http_get — per-identity, one connection each                   */
/* ------------------------------------------------------------------ */

static char *mqc_http_get_once(mqc_ctx_t *ctx, const char *host, int port,
                               const char *path_only, long *code)
{
    mqc_conn_t *conn;
    char req[1024];
    char *buf;
    int buf_sz = 0, buf_cap = 16384;
    int n;
    char *body_start;
    long status = 0;

    if (code) *code = 0;

    conn = mqc_connect(ctx, host, port);
    if (!conn) { usleep(100000); conn = mqc_connect(ctx, host, port); }
    if (!conn) return NULL;

    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
             path_only, host, port);
    if (mqc_write(conn, req, (int)strlen(req)) < 0) {
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
            } else break;
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

/* Ask the server whether a cert_index is revoked. Uses an MQC connection
 * as the identity at tpm_path (which is still valid at this point, since
 * we're renewing it *before* expiry). Returns 1 revoked, 0 not, -1 error. */
static int server_is_revoked(const char *server, const char *tpm_path,
                             int cert_index)
{
    char host_buf[256];
    char *colon;
    int port = 8446;
    mqc_cfg_t cfg;
    static unsigned char ca_pubkey[32];
    mqc_ctx_t *ctx;
    char path[64];
    char *body;
    long code = 0;
    int revoked = -1;
    struct json_object *resp, *val;

    snprintf(host_buf, sizeof(host_buf), "%s", server);
    colon = strrchr(host_buf, ':');
    if (colon) { *colon = '\0'; port = atoi(colon + 1); }

    if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) return -1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.role         = MQC_CLIENT;
    cfg.tpm_path     = tpm_path;
    cfg.mtc_server   = server;
    cfg.ca_pubkey    = ca_pubkey;
    cfg.ca_pubkey_sz = 32;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) return -1;

    snprintf(path, sizeof(path), "/revoked/%d", cert_index);
    body = mqc_http_get_once(ctx, host_buf, port, path, &code);
    mqc_ctx_free(ctx);
    if (!body || code != 200) { free(body); return -1; }

    resp = json_tokener_parse(body);
    free(body);
    if (resp && json_object_object_get_ex(resp, "revoked", &val))
        revoked = json_object_get_boolean(val) ? 1 : 0;
    if (resp) json_object_put(resp);
    return revoked;
}

/* ------------------------------------------------------------------ */
/* Identity classification + discovery                                */
/* ------------------------------------------------------------------ */

/* Return 1 if the directory basename ends in "-ca" (at a segment
 * boundary).  Matches "foo.com-ca", "foo.com-prod-ca", but not "foo-cap". */
static int dir_is_ca(const char *dir_name)
{
    size_t n = strlen(dir_name);
    return n >= 3 && strcmp(dir_name + n - 3, "-ca") == 0;
}

/* Entry describes one identity to be considered for renewal. */
typedef struct {
    char  dir_path[2048];    /* e.g. ~/.TPM/factsorlie.com-prod */
    char  dir_name[256];     /* basename, e.g. factsorlie.com-prod */
    char  subject[256];      /* from cert TBS, e.g. factsorlie.com */
    char  algorithm[64];     /* e.g. ML-DSA-87 */
    int   cert_index;
    double not_after;
    int   is_ca;
} identity_t;

/* Read cert metadata into e. Returns 0 on success, -1 on failure. */
static int load_identity(identity_t *e)
{
    char path[4096];
    char *idx_str;
    char *cert_txt;
    struct json_object *root, *sc, *tbs, *val;

    snprintf(path, sizeof(path), "%s/index", e->dir_path);
    idx_str = read_text(path);
    if (idx_str) { e->cert_index = atoi(idx_str); free(idx_str); }
    else e->cert_index = -1;

    snprintf(path, sizeof(path), "%s/certificate.json", e->dir_path);
    cert_txt = read_text(path);
    if (!cert_txt) return -1;

    root = json_tokener_parse(cert_txt);
    free(cert_txt);
    if (!root) return -1;

    if (!json_object_object_get_ex(root, "standalone_certificate", &sc) ||
        !json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
        json_object_put(root); return -1;
    }
    if (e->cert_index < 0 &&
        json_object_object_get_ex(sc, "index", &val))
        e->cert_index = json_object_get_int(val);

    if (json_object_object_get_ex(tbs, "subject", &val))
        snprintf(e->subject, sizeof(e->subject), "%s",
                 json_object_get_string(val));
    if (json_object_object_get_ex(tbs, "subject_public_key_algorithm", &val))
        snprintf(e->algorithm, sizeof(e->algorithm), "%s",
                 json_object_get_string(val));
    else
        snprintf(e->algorithm, sizeof(e->algorithm), "EC-P256");
    if (json_object_object_get_ex(tbs, "not_after", &val))
        e->not_after = json_object_get_double(val);

    json_object_put(root);
    e->is_ca = dir_is_ca(e->dir_name);
    return 0;
}

/* Enumerate identity dirs under tpm_base. Caller frees *out. */
static int discover_identities(const char *tpm_base,
                               identity_t **out, int *n_out)
{
    DIR *d = opendir(tpm_base);
    struct dirent *de;
    identity_t *arr = NULL;
    int n = 0, cap = 0;

    if (!d) return -1;
    while ((de = readdir(d)) != NULL) {
        struct stat st;
        char full[2048];
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "default") == 0) continue;
        if (strcmp(de->d_name, "peers")   == 0) continue;
        if (strcmp(de->d_name, "ech")     == 0) continue;
        snprintf(full, sizeof(full), "%s/%s", tpm_base, de->d_name);
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        if (n >= cap) {
            cap = cap ? cap * 2 : 8;
            arr = realloc(arr, (size_t)cap * sizeof(*arr));
            if (!arr) { closedir(d); return -1; }
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        snprintf(arr[n].dir_path, sizeof(arr[n].dir_path), "%s", full);
        snprintf(arr[n].dir_name, sizeof(arr[n].dir_name), "%s", de->d_name);
        n++;
    }
    closedir(d);
    *out = arr;
    *n_out = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Renewal driver for one identity                                    */
/* ------------------------------------------------------------------ */

static int generate_new_keypair(const identity_t *e, char *pubkey_out,
                                size_t pubkey_out_sz)
{
    const char *script = e->is_ca ? PYTHON_CA : PYTHON_LEAF;
    char *const argv[] = {
        (char *)script,
        "--domain",    (char *)e->subject,
        "--algorithm", (char *)e->algorithm,
        NULL
    };
    int rc;
    const char *home;

    if (access(script, X_OK) != 0) {
        fprintf(stderr, "[check-renewal-cert] %s: not executable (%s)\n",
                script, strerror(errno));
        return -1;
    }
    rc = run_command(argv);
    if (rc != 0) {
        fprintf(stderr, "[check-renewal-cert] %s exited %d\n", script, rc);
        return -1;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(pubkey_out, pubkey_out_sz,
             "%s/.mtc-ca-data/%s/public_key.pem", home, e->subject);
    if (access(pubkey_out, R_OK) != 0) {
        fprintf(stderr, "[check-renewal-cert] %s: missing new pubkey\n",
                pubkey_out);
        return -1;
    }
    return 0;
}

/* Invoke renew-cert to get a new certificate.json in the tmp dir. */
static int run_renew_cert(const identity_t *e, const char *server,
                          const char *new_pubkey_path,
                          const char *out_cert_path)
{
    char *server_arg = (char *)server;
    char validity_buf[16];
    snprintf(validity_buf, sizeof(validity_buf), "%d",
             MTC_RECERT_VALIDITY_DAYS);
    char *const argv[] = {
        (char *)RENEW_CERT_BIN,
        "--tpm-path",      (char *)e->dir_path,
        "--new-pubkey",    (char *)new_pubkey_path,
        "--server",        server_arg,
        "--validity-days", validity_buf,
        "--out",           (char *)out_cert_path,
        g_trace ? "--trace" : NULL,
        NULL
    };
    int rc = run_command(argv);
    if (rc != 0) {
        fprintf(stderr, "[check-renewal-cert] renew-cert exited %d\n", rc);
        return -1;
    }
    if (access(out_cert_path, R_OK) != 0) {
        fprintf(stderr, "[check-renewal-cert] %s: missing after renew-cert\n",
                out_cert_path);
        return -1;
    }
    return 0;
}

/* Extract the index from a standalone_certificate JSON file. */
static int extract_index_from_cert(const char *cert_path, int *out_idx)
{
    char *txt = read_text(cert_path);
    struct json_object *root, *sc, *val;
    int rc = -1;
    if (!txt) return -1;
    root = json_tokener_parse(txt);
    free(txt);
    if (!root) return -1;
    if (json_object_object_get_ex(root, "standalone_certificate", &sc) &&
        json_object_object_get_ex(sc, "index", &val)) {
        *out_idx = json_object_get_int(val);
        rc = 0;
    } else if (json_object_object_get_ex(root, "index", &val)) {
        *out_idx = json_object_get_int(val);
        rc = 0;
    }
    json_object_put(root);
    return rc;
}

/* Atomically swap the staged .renew.tmp/ contents into the identity dir,
 * preserving the old material under .renew.bak/ until the swap commits.
 * On any failure, restores from .renew.bak/ and returns -1. */
static int commit_swap(const char *dir_path, int is_ca)
{
    const char *files[] = {
        "private_key.pem", "public_key.pem", "certificate.json", "index",
        NULL, NULL
    };
    int n = 4;
    if (is_ca) { files[n++] = "ca_cert.pem"; }
    files[n] = NULL;

    char bak[4096], tmp[4096], live[4096];
    snprintf(bak, sizeof(bak), "%s/.renew.bak", dir_path);
    snprintf(tmp, sizeof(tmp), "%s/.renew.tmp", dir_path);

    if (mkdir(bak, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "[check-renewal-cert] mkdir %s: %s\n",
                bak, strerror(errno));
        return -1;
    }

    /* Move old → bak */
    int i;
    for (i = 0; files[i]; i++) {
        char src[4096], dst[4096];
        snprintf(src, sizeof(src), "%s/%s", dir_path, files[i]);
        snprintf(dst, sizeof(dst), "%s/%s", bak, files[i]);
        if (access(src, F_OK) != 0) continue;  /* not present, skip */
        if (rename(src, dst) != 0) {
            fprintf(stderr, "[check-renewal-cert] rename %s → %s: %s\n",
                    src, dst, strerror(errno));
            goto rollback;
        }
    }

    /* Move tmp → live */
    for (i = 0; files[i]; i++) {
        char src[4096];
        snprintf(src, sizeof(src), "%s/%s", tmp, files[i]);
        snprintf(live, sizeof(live), "%s/%s", dir_path, files[i]);
        if (access(src, F_OK) != 0) {
            /* File not staged (optional, e.g. ca_cert.pem for leaf) */
            continue;
        }
        if (rename(src, live) != 0) {
            fprintf(stderr, "[check-renewal-cert] rename %s → %s: %s\n",
                    src, live, strerror(errno));
            goto rollback;
        }
    }

    /* Success — purge bak */
    for (i = 0; files[i]; i++) {
        char b[1300];
        snprintf(b, sizeof(b), "%s/%s", bak, files[i]);
        unlink(b);  /* ignore errors */
    }
    rmdir(bak);
    rmdir(tmp);
    return 0;

rollback:
    fprintf(stderr, "[check-renewal-cert] rolling back from %s\n", bak);
    for (i = 0; files[i]; i++) {
        char src[4096], dst[4096];
        snprintf(src, sizeof(src), "%s/%s", bak, files[i]);
        snprintf(dst, sizeof(dst), "%s/%s", dir_path, files[i]);
        if (access(src, F_OK) != 0) continue;
        if (rename(src, dst) != 0) {
            fprintf(stderr, "[check-renewal-cert] ROLLBACK FAILED for %s — "
                    "operator must inspect %s\n", files[i], dir_path);
        }
    }
    return -1;
}

static int renew_one(identity_t *e, const char *server)
{
    char tmp_dir[4096];
    char new_pubkey_path[4096];
    char src[4096], dst[4096];
    char index_txt[32];
    char cert_out[4096];
    const char *home;
    int new_idx = -1;
    struct stat st;

    home = getenv("HOME");
    if (!home) home = "/tmp";

    /* Step 1: generate new keypair */
    if (generate_new_keypair(e, new_pubkey_path,
                             sizeof(new_pubkey_path)) != 0) {
        return -1;
    }

    /* Step 2: stage under .renew.tmp */
    snprintf(tmp_dir, sizeof(tmp_dir), "%s/.renew.tmp", e->dir_path);
    if (stat(tmp_dir, &st) == 0) {
        /* Leftover from a previous failed run — clear it. */
        char p[4096];
        const char *stale[] = {
            "private_key.pem", "public_key.pem", "certificate.json",
            "index", "ca_cert.pem", NULL
        };
        int i;
        for (i = 0; stale[i]; i++) {
            snprintf(p, sizeof(p), "%s/%s", tmp_dir, stale[i]);
            unlink(p);
        }
        rmdir(tmp_dir);
    }
    if (mkdir(tmp_dir, 0700) != 0) {
        fprintf(stderr, "[check-renewal-cert] mkdir %s: %s\n",
                tmp_dir, strerror(errno));
        return -1;
    }

    /* Copy new keypair into .renew.tmp */
    snprintf(src, sizeof(src), "%s/.mtc-ca-data/%s/private_key.pem",
             home, e->subject);
    snprintf(dst, sizeof(dst), "%s/private_key.pem", tmp_dir);
    if (copy_file(src, dst, 0600) != 0) {
        fprintf(stderr, "[check-renewal-cert] copy %s → %s failed\n", src, dst);
        return -1;
    }
    snprintf(src, sizeof(src), "%s/.mtc-ca-data/%s/public_key.pem",
             home, e->subject);
    snprintf(dst, sizeof(dst), "%s/public_key.pem", tmp_dir);
    if (copy_file(src, dst, 0644) != 0) {
        fprintf(stderr, "[check-renewal-cert] copy %s → %s failed\n", src, dst);
        return -1;
    }
    if (e->is_ca) {
        snprintf(src, sizeof(src), "%s/.mtc-ca-data/%s/ca_cert.pem",
                 home, e->subject);
        snprintf(dst, sizeof(dst), "%s/ca_cert.pem", tmp_dir);
        if (access(src, R_OK) == 0 && copy_file(src, dst, 0644) != 0) {
            fprintf(stderr, "[check-renewal-cert] copy %s → %s failed\n",
                    src, dst);
            return -1;
        }
    }

    /* Step 3: hit /renew-cert */
    snprintf(cert_out, sizeof(cert_out), "%s/certificate.json", tmp_dir);
    if (run_renew_cert(e, server, new_pubkey_path, cert_out) != 0) {
        return -1;
    }

    /* Step 4: write index file */
    if (extract_index_from_cert(cert_out, &new_idx) != 0) {
        fprintf(stderr, "[check-renewal-cert] no index in %s\n", cert_out);
        return -1;
    }
    snprintf(index_txt, sizeof(index_txt), "%d\n", new_idx);
    snprintf(dst, sizeof(dst), "%s/index", tmp_dir);
    if (write_text(dst, index_txt) != 0) {
        fprintf(stderr, "[check-renewal-cert] write %s failed\n", dst);
        return -1;
    }

    /* Step 5: atomic swap */
    if (commit_swap(e->dir_path, e->is_ca) != 0) return -1;

    fprintf(stderr,
            "[check-renewal-cert] renewed %s (%s): index %d → %d\n",
            e->dir_name, e->subject, e->cert_index, new_idx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Scan ~/.TPM, renew any identity within the renewal window via MQC.\n"
        "\n"
        "Usage:\n"
        "  %s [--dry-run] [--force DIR] [--window-days N] [--tpm-base PATH]\n"
        "         [-s, --server H:P] [--trace] [-v] [-h, --help]\n"
        "\n"
        "  --dry-run          Report only; do not renew or touch disk\n"
        "  --force DIR        Bypass the window check for this identity\n"
        "                     (pass the directory name under ~/.TPM/)\n"
        "  --window-days N    Override MTC_RENEWAL_WINDOW_DAYS=%d\n"
        "  --tpm-base PATH    Alternate ~/.TPM root (tests use a scratch dir)\n"
        "  -s, --server H:P   MTC server (default: %s)\n"
        "  --trace            Propagate --trace to renew-cert\n"
        "  -v                 Verbose (log skips + exec lines)\n"
        "  -h, --help         This help\n",
        prog, MTC_RENEWAL_WINDOW_DAYS, DEFAULT_SERVER);
}

int main(int argc, char **argv)
{
    int i;
    int dry_run = 0;
    int window_days = MTC_RENEWAL_WINDOW_DAYS;
    const char *force = NULL;
    const char *tpm_base = NULL;
    const char *server = DEFAULT_SERVER;
    char tpm_root[1024];
    const char *home;
    identity_t *ids = NULL;
    int n_ids = 0;
    int n_skipped = 0, n_renewed = 0, n_failed = 0, n_revoked = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--force") == 0 && i + 1 < argc) {
            force = argv[++i];
        } else if (strcmp(argv[i], "--window-days") == 0 && i + 1 < argc) {
            window_days = atoi(argv[++i]);
            if (window_days < 0 || window_days > 3650) {
                fprintf(stderr, "Error: --window-days out of range\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--tpm-base") == 0 && i + 1 < argc) {
            tpm_base = argv[++i];
        } else if ((strcmp(argv[i], "-s") == 0 ||
                    strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--trace") == 0) {
            g_trace = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            usage(argv[0]); return 2;
        }
    }

    if (tpm_base) {
        snprintf(tpm_root, sizeof(tpm_root), "%s", tpm_base);
    } else {
        home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(tpm_root, sizeof(tpm_root), "%s/%s", home, DEFAULT_TPM_DIR);
    }

    if (g_verbose)
        fprintf(stderr,
                "[check-renewal-cert] scan %s window=%dd server=%s%s%s\n",
                tpm_root, window_days, server,
                dry_run ? " (dry-run)" : "",
                force ? " (force)" : "");

    if (discover_identities(tpm_root, &ids, &n_ids) != 0) {
        fprintf(stderr, "Error: cannot scan %s: %s\n",
                tpm_root, strerror(errno));
        return 2;
    }
    if (n_ids == 0) {
        fprintf(stderr, "[check-renewal-cert] no identities under %s\n",
                tpm_root);
        free(ids);
        return 0;
    }

    double now = (double)time(NULL);
    double window_secs = (double)window_days * 86400.0;

    for (i = 0; i < n_ids; i++) {
        identity_t *e = &ids[i];
        int this_force = force && strcmp(force, e->dir_name) == 0;

        if (load_identity(e) != 0) {
            fprintf(stderr, "[skip] %s: cannot read certificate.json\n",
                    e->dir_name);
            n_skipped++;
            continue;
        }

        double remaining = e->not_after - now;
        int days_left = (int)(remaining / 86400.0);

        if (!this_force && remaining > window_secs) {
            if (g_verbose)
                fprintf(stderr,
                        "[skip] %s: expires in %dd (outside window)\n",
                        e->dir_name, days_left);
            n_skipped++;
            continue;
        }

        /* Check server-side revocation using this identity's MQC */
        if (e->cert_index < 0) {
            fprintf(stderr,
                    "[fail] %s: no cert_index recorded; manual repair\n",
                    e->dir_name);
            n_failed++;
            continue;
        }
        int rev = server_is_revoked(server, e->dir_path, e->cert_index);
        if (rev < 0) {
            fprintf(stderr,
                    "[fail] %s: revocation lookup failed — not renewing\n",
                    e->dir_name);
            n_failed++;
            continue;
        }
        if (rev == 1) {
            fprintf(stderr,
                    "[skip] %s: cert %d is REVOKED — re-enroll required\n",
                    e->dir_name, e->cert_index);
            n_revoked++;
            continue;
        }

        if (dry_run) {
            fprintf(stderr,
                    "[dry-run] would renew %s (%s, %s, idx %d, %dd left)\n",
                    e->dir_name, e->subject, e->algorithm,
                    e->cert_index, days_left);
            n_renewed++;   /* count intent */
            continue;
        }

        if (renew_one(e, server) != 0) {
            fprintf(stderr, "[fail] %s: renewal failed\n", e->dir_name);
            n_failed++;
        } else {
            n_renewed++;
        }
    }

    fprintf(stderr,
            "[check-renewal-cert] summary: %d renewed, %d skipped, "
            "%d revoked, %d failed\n",
            n_renewed, n_skipped, n_revoked, n_failed);

    free(ids);
    return (n_failed > 0 || n_revoked > 0) ? 1 : 0;
}
