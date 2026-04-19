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

#include <json-c/json.h>
#include "mqc.h"
#include "mqc_peer.h"

#define DEFAULT_TPM_DIR   ".TPM"
#include "config.h"
#define DEFAULT_SERVER    MQC_DEFAULT_SERVER   /* MQC endpoint (config.h) */
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

    /* Read response into dynamically growing buffer */
    buf_cap = 16384;
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
    int  cert_index;
    double not_before;
    double not_after;
    int  has_cert;
    /* Verification results */
    int  v_server_found;   /* 1=ok, 0=fail, -1=not checked */
    int  v_revoked;        /* 1=revoked, 0=not, -1=not checked */
    int  v_proof_match;    /* 1=ok, 0=fail, -1=not checked */
    int  v_time_valid;     /* 1=ok, 0=fail, -1=not checked */
    int  v_pubkey_db;      /* 1=ok, 0=not found, 2=mismatch, -1=not checked */
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

static void verify_entry(tpm_entry_t *e)
{
    char path[512];
    char *body;
    long code = 0;

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
            char loc_path[1024];
            char *loc_json;

            /* Read local cert for comparison */
            {
                const char *home = getenv("HOME");
                if (!home) home = "/tmp";
                snprintf(loc_path, sizeof(loc_path), "%s/.TPM/%s/certificate.json",
                         home, e->name);
            }
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
        char loc_key_path[1024];
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";
        snprintf(loc_key_path, sizeof(loc_key_path),
                 "%s/.TPM/%s/public_key.pem", home, e->name);
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

    printf("  [%c] %s\n", expired ? 'X' : '+', e->name);
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

        printf("      Verify:     server=%s  revoked=%s  proof=%s  time=%s  pubkey_db=%s\n",
               s_srv, s_rev, s_prf, s_tim, s_pdb);
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
            DIR *d = opendir(tpm_dir);
            struct dirent *de;
            if (d) {
                while ((de = readdir(d)) != NULL) {
                    struct stat st;
                    char full[1024];
                    if (de->d_name[0] == '.') continue;
                    if (strcmp(de->d_name, "peers") == 0) continue;
                    if (strcmp(de->d_name, "ech") == 0) continue;
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
        static unsigned char ca_pubkey[32];
        if (mqc_load_ca_pubkey(server, ca_pubkey) != 0) {
            fprintf(stderr,
                "Error: could not load CA cosigner pubkey (required "
                "for MQC cosignature verification)\n");
            return 1;
        }
        cfg.ca_pubkey    = ca_pubkey;
        cfg.ca_pubkey_sz = 32;

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
    }

    /* Print header */
    printf("TPM Store: %s\n", tpm_dir);
    printf("Entries:   %d\n", num_entries);
    printf("Legend:    [+] valid  [X] expired\n\n");

    /* Process entries */
    for (i = 0; i < num_entries; i++) {
        if (verify)
            verify_entry(&entries[i]);

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
