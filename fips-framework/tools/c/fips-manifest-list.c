/*
 * fips-manifest-list — browse the FIPS-manifest log via MQC.
 *
 * Read-only browser over the server's /fips/list endpoint.  Talks to
 * the MTC CA over MQC on port 8446 using a local TPM identity from
 * ~/.TPM/<dir>/.  No direct database credentials are required, so this
 * tool runs on any host that holds a valid leaf identity.
 *
 * Usage:
 *   fips-manifest-list                       # table view, all rows
 *   fips-manifest-list --package P           # filter by package
 *   fips-manifest-list --publisher D
 *   fips-manifest-list --version V
 *   fips-manifest-list --limit N             # default 50, server-capped at 1000
 *   fips-manifest-list --json                # emit JSON instead of table
 *   fips-manifest-list <log_index>           # detail view for one entry
 *   fips-manifest-list --tpm-path PATH       # explicit identity dir
 *                                              (default: first identity
 *                                               under $HOME/.TPM)
 *   fips-manifest-list -s HOST[:PORT]        # default: [global] url-server
 *                                              from /etc/postWolf/config
 *   fips-manifest-list -v                    # verbose detail (per-file list)
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

#include <json-c/json.h>

#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"
#include "../../../socket-level-wrapper-MQC/config.h"  /* MQC_DEFAULT_SERVER */
#include "config.h"  /* MQC_DEFAULT_SERVER_PORT fallback if MQC header absent */

#define DEFAULT_TPM_DIR  ".TPM"

#define die(fmt, ...) do { \
    fprintf(stderr, "fips-manifest-list: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static int g_verbose = 0;

/* ------------------------------------------------------------------ */
/* MQC HTTP GET (mirrors check-renewal-cert.c::mqc_http_get_once)     */
/* ------------------------------------------------------------------ */

static char *mqc_http_get(mqc_ctx_t *ctx, const char *host, int port,
                          const char *path, long *code)
{
    mqc_conn_t *conn;
    char req[2048];
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
             path, host, port);
    if (mqc_write(conn, req, (int)strlen(req)) < 0) {
        mqc_close(conn); return NULL;
    }

    buf = (char *)malloc((size_t)buf_cap);
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

/* ------------------------------------------------------------------ */
/* Identity discovery                                                 */
/* ------------------------------------------------------------------ */

/* Pick the first usable identity dir under $HOME/.TPM, skipping the
 * special entries (peers, ech, default symlink, hidden).  Returns a
 * heap-allocated path string the caller must free, or NULL. */
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

        char cert_path[2200];
        snprintf(cert_path, sizeof(cert_path), "%s/certificate.json", path);
        if (access(cert_path, R_OK) != 0) continue;

        result = strdup(path);
        break;
    }
    closedir(d);
    return result;
}

/* ------------------------------------------------------------------ */
/* Query-string assembly                                              */
/* ------------------------------------------------------------------ */

/* Append one key=val pair to the URL.  Values are passed through
 * unchanged; the server's pre-DB charset filter rejects anything that
 * could be problematic, so we don't need a percent-encoder here.
 * The CLI itself rejects values containing '&' or '?'. */
static int append_param(char *url, size_t cap, int *first,
                        const char *key, const char *val)
{
    if (!val) return 0;
    char sep = *first ? '?' : '&';
    *first = 0;
    int n = snprintf(url + strlen(url), cap - strlen(url),
                     "%c%s=%s", sep, key, val);
    return (n > 0 && (size_t)n < cap - strlen(url));
}

static void cli_check_value(const char *key, const char *val)
{
    if (!val) return;
    for (const char *p = val; *p; p++) {
        if (*p == '&' || *p == '?' || *p == '=' || *p == '#' ||
            (unsigned char)*p < 0x20) {
            die("--%s value contains a disallowed character", key);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Renderers                                                          */
/* ------------------------------------------------------------------ */

static const char *jstr(struct json_object *o, const char *key)
{
    struct json_object *v;
    return (o && json_object_object_get_ex(o, key, &v))
        ? json_object_get_string(v) : "";
}

static int jint(struct json_object *o, const char *key)
{
    struct json_object *v;
    return (o && json_object_object_get_ex(o, key, &v))
        ? json_object_get_int(v) : 0;
}

static int jbool(struct json_object *o, const char *key)
{
    struct json_object *v;
    return (o && json_object_object_get_ex(o, key, &v))
        ? json_object_get_boolean(v) : 0;
}

static void render_table(struct json_object *resp)
{
    struct json_object *arr = NULL;
    if (!json_object_object_get_ex(resp, "entries", &arr) ||
        !json_object_is_type(arr, json_type_array))
    {
        puts("(no entries)");
        return;
    }
    size_t n = json_object_array_length(arr);

    /* Column widths */
    int wi[5] = { 9, 20, 16, 16, 12 };  /* idx submitted publisher pkg ver */
    for (size_t i = 0; i < n; i++) {
        struct json_object *e = json_object_array_get_idx(arr, i);
        char ix[16];
        snprintf(ix, sizeof(ix), "%d", jint(e, "log_index"));
        int l;
        l = (int)strlen(ix); if (l > wi[0]) wi[0] = l;
        l = (int)strlen(jstr(e, "submitted_at")); if (l > wi[1]) wi[1] = l;
        l = (int)strlen(jstr(e, "publisher"));    if (l > wi[2]) wi[2] = l;
        l = (int)strlen(jstr(e, "package"));      if (l > wi[3]) wi[3] = l;
        l = (int)strlen(jstr(e, "version"));      if (l > wi[4]) wi[4] = l;
    }

    printf("%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
           wi[0], "log_index", wi[1], "submitted_at",
           wi[2], "publisher", wi[3], "package", wi[4], "version", "rev");
    int totw = wi[0] + wi[1] + wi[2] + wi[3] + wi[4] + 13;
    for (int i = 0; i < totw; i++) putchar('-');
    putchar('\n');

    for (size_t i = 0; i < n; i++) {
        struct json_object *e = json_object_array_get_idx(arr, i);
        char ix[16];
        snprintf(ix, sizeof(ix), "%d", jint(e, "log_index"));
        int cr = jbool(e, "publisher_cert_revoked");
        int mr = jbool(e, "manifest_revoked");
        const char *rev =
            (cr && mr) ? "BOTH"  :
             cr        ? "CERT"  :
             mr        ? "MANIF" : "";
        printf("%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
               wi[0], ix,
               wi[1], jstr(e, "submitted_at"),
               wi[2], jstr(e, "publisher"),
               wi[3], jstr(e, "package"),
               wi[4], jstr(e, "version"),
               rev);
    }
    if (n == 0) puts("(no rows)");
    else printf("\n%zu row%s\n", n, n == 1 ? "" : "s");
}

static void render_detail(struct json_object *resp)
{
    struct json_object *e = NULL;
    if (!json_object_object_get_ex(resp, "entry", &e)) {
        puts("(no entry in response)");
        return;
    }
    printf("log_index:            %d\n", jint(e, "log_index"));
    printf("publisher:            %s\n", jstr(e, "publisher"));
    printf("package:              %s\n", jstr(e, "package"));
    printf("version:              %s\n", jstr(e, "version"));
    printf("submitted_at:         %s\n", jstr(e, "submitted_at"));
    printf("publisher_cert_index: %d%s\n",
           jint(e, "publisher_cert_index"),
           jbool(e, "publisher_cert_revoked") ? "  (cert REVOKED)" : "");
    printf("manifest_revoked:     %s\n",
           jbool(e, "manifest_revoked") ? "yes" : "no");
    {
        struct json_object *rev = NULL;
        if (json_object_object_get_ex(e, "revocation", &rev) && rev) {
            printf("  revoker_kind:       %s\n", jstr(rev, "revoker_kind"));
            printf("  revoker_cert_index: %d\n",
                   jint(rev, "revoker_cert_index"));
            printf("  reason:             %s\n", jstr(rev, "reason"));
            struct json_object *v;
            if (json_object_object_get_ex(rev, "revoked_at", &v))
                printf("  revoked_at:         %.0f\n",
                       json_object_get_double(v));
        }
    }

    struct json_object *m = NULL;
    if (json_object_object_get_ex(e, "manifest", &m) && m) {
        struct json_object *v;
        if (json_object_object_get_ex(m, "alg", &v))
            printf("alg:                  %s\n", json_object_get_string(v));
        if (json_object_object_get_ex(m, "schema_version", &v))
            printf("schema_version:       %d\n", json_object_get_int(v));
        if (json_object_object_get_ex(m, "not_before", &v))
            printf("not_before:           %.0f\n", json_object_get_double(v));
        if (json_object_object_get_ex(m, "expires", &v))
            printf("expires:              %.0f\n", json_object_get_double(v));
        if (json_object_object_get_ex(m, "git_commit", &v))
            printf("git_commit:           %s\n", json_object_get_string(v));

        struct json_object *files = NULL;
        if (json_object_object_get_ex(m, "files", &files) && files)
            printf("files:                %zu\n",
                   (size_t)json_object_array_length(files));

        if (g_verbose && files) {
            size_t nf = json_object_array_length(files);
            for (size_t i = 0; i < nf; i++) {
                struct json_object *fe = json_object_array_get_idx(files, i);
                struct json_object *p_v = NULL, *h_v = NULL;
                json_object_object_get_ex(fe, "path",   &p_v);
                json_object_object_get_ex(fe, "sha256", &h_v);
                printf("  [%3zu] %.16s...  %s\n", i,
                       h_v ? json_object_get_string(h_v) : "",
                       p_v ? json_object_get_string(p_v) : "");
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [<log_index>] [options]\n"
        "  --package P         Filter by package\n"
        "  --publisher D       Filter by publisher\n"
        "  --version V         Filter by version\n"
        "  --limit N           Cap rows (default 50, server-max 1000)\n"
        "  --json              Emit raw JSON instead of table/detail\n"
        "  --tpm-path PATH     TPM identity dir (default: first under $HOME/.TPM)\n"
        "  -s, --server H[:P]  MQC server (default: [global] url-server)\n"
        "  -v, --verbose       Show extra fields in detail view\n"
        "  -h, --help\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *filter_package   = NULL;
    const char *filter_publisher = NULL;
    const char *filter_version   = NULL;
    const char *cli_tpm_path     = NULL;
    const char *cli_server       = NULL;
    int limit = 0;
    int as_json = 0;
    int detail_index = -1;

    static struct option opts[] = {
        {"package",    required_argument, 0, 'p'},
        {"publisher",  required_argument, 0, 'P'},
        {"version",    required_argument, 0, 'V'},
        {"limit",      required_argument, 0, 'l'},
        {"json",       no_argument,       0, 'j'},
        {"tpm-path",   required_argument, 0, 'T'},
        {"server",     required_argument, 0, 's'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:P:V:l:jT:s:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'p': filter_package   = optarg; break;
            case 'P': filter_publisher = optarg; break;
            case 'V': filter_version   = optarg; break;
            case 'l': limit = atoi(optarg);      break;
            case 'j': as_json = 1;               break;
            case 'T': cli_tpm_path = optarg;     break;
            case 's': cli_server = optarg;       break;
            case 'v': g_verbose = 1;             break;
            default:  usage(argv[0]);
        }
    }
    if (optind < argc) {
        char *end;
        long v = strtol(argv[optind], &end, 10);
        if (*end != 0 || v < 0) usage(argv[0]);
        detail_index = (int)v;
    }

    cli_check_value("package",   filter_package);
    cli_check_value("publisher", filter_publisher);
    cli_check_value("version",   filter_version);

    /* Identity */
    char *tpm_path_owned = NULL;
    const char *tpm_path = cli_tpm_path;
    if (!tpm_path) {
        tpm_path_owned = autodiscover_tpm();
        if (!tpm_path_owned)
            die("no TPM identity found under $HOME/.TPM "
                "(use --tpm-path to specify one)");
        tpm_path = tpm_path_owned;
    }

    /* Server */
    char *server_from_cfg = NULL;
    const char *server = cli_server;
    if (!server) {
        server_from_cfg = read_config_url("global/url-server");
        server = server_from_cfg ? server_from_cfg : MQC_DEFAULT_SERVER;
    }

    /* Strip leading scheme if present (e.g. "https://factsorlie.com:8446"). */
    const char *colon_slash = strstr(server, "://");
    if (colon_slash) server = colon_slash + 3;

    char host_buf[256];
    int port = MQC_DEFAULT_SERVER_PORT;
    {
        snprintf(host_buf, sizeof(host_buf), "%s", server);
        char *colon = strrchr(host_buf, ':');
        if (colon) { *colon = 0; port = atoi(colon + 1); }
    }

    /* Build URL */
    char url[1536];
    snprintf(url, sizeof(url), "/fips/list");
    int first = 1;
    if (detail_index >= 0) {
        char ix[32];
        snprintf(ix, sizeof(ix), "%d", detail_index);
        append_param(url, sizeof(url), &first, "log_index", ix);
    } else {
        if (filter_publisher) append_param(url, sizeof(url), &first, "publisher", filter_publisher);
        if (filter_package)   append_param(url, sizeof(url), &first, "package",   filter_package);
        if (filter_version)   append_param(url, sizeof(url), &first, "version",   filter_version);
        if (limit > 0) {
            char lb[32];
            snprintf(lb, sizeof(lb), "%d", limit);
            append_param(url, sizeof(url), &first, "limit", lb);
        }
    }

    /* MQC context */
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
    char *body = mqc_http_get(ctx, host_buf, port, url, &code);
    mqc_ctx_free(ctx);

    if (!body)
        die("MQC GET %s://%s:%d%s failed", "mqc", host_buf, port, url);
    if (code != 200) {
        fprintf(stderr, "fips-manifest-list: server returned HTTP %ld\n", code);
        fprintf(stderr, "%s\n", body);
        free(body);
        free(tpm_path_owned);
        free(server_from_cfg);
        return 1;
    }

    struct json_object *resp = json_tokener_parse(body);
    free(body);
    if (!resp)
        die("server response was not valid JSON");

    if (as_json) {
        printf("%s\n", json_object_to_json_string_ext(resp,
            JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
    } else if (detail_index >= 0) {
        render_detail(resp);
    } else {
        render_table(resp);
    }

    json_object_put(resp);
    free(tpm_path_owned);
    free(server_from_cfg);
    return 0;
}
