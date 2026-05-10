/*
 * fips-manifest-submit — wrap an already-signed MANIFEST.sha256 as a
 * FIPS canonical leaf and (by default) POST it to the MTC log over MQC.
 *
 * Reads the file→hash table from <source-dir>/MANIFEST.sha256 (which
 * sign-dir.sh produced — typically with -g, so gitignored artefacts
 * are excluded) instead of re-walking + re-hashing.  Adds the FIPS-
 * specific metadata (package, version, validity window, schema_version,
 * publisher_cert_index from the manifest header), wraps as the canonical
 * leaf JSON per fips-framework/spec-canonical-leaf.md, signs it with
 * the publisher's ML-DSA-87 key from ~/.TPM/<DOMAIN>-<LABEL>/, and
 * (default mode) POSTs the canonical JSON to /fips/manifest.
 *
 * Why read MANIFEST.sha256 instead of walking?  sign-dir.sh has already
 * produced and signed the file→hash table for the publisher's chosen
 * "kit" (the .gitignore-respecting set when invoked with -g).  Walking
 * again would duplicate that work and risk producing a different file
 * set than what verify-dir.sh would check.  Single source of truth.
 *
 * The server's JSON receipt is persisted under
 * <tpm_dir>/fips-receipts/<package>-<version>-<log_index>.json
 * so it can be fed straight into `fips-manifest-verify --receipt`.
 *
 * --dry-run preserves the offline mode: builds and signs but does not
 * POST; emits raw leaf bytes (0x02 || canonical_json) to stdout (or --out).
 *
 * Usage:
 *   fips-manifest-submit --domain DOMAIN --label LABEL \
 *                        --package PKG --version VER \
 *                        --source-dir DIR
 *                        [--manifest PATH]      (default: <source-dir>/MANIFEST.sha256)
 *                        [--out FILE]           (also save raw leaf)
 *                        [--receipt-out FILE]   (override receipt path)
 *                        [--validity-days N]    (default: 30, max: 365)
 *                        [--dry-run]            (build + sign, skip POST)
 *                        [--pretty]             (indented JSON to stderr)
 *                        [-s, --server H[:P]]   (default: [global] url-server)
 *
 * Exit code: 0 on success, non-zero on any failure.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>     /* Base64_Encode */

#include <json-c/json.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* MQC plumbing for the wire-submit path (default mode).  Pulled in
 * unconditionally; the network code only executes when --dry-run is
 * off.  mqc_http_post lives at the bottom of this file (same pattern
 * as fips-manifest-revoke.c — each tool keeps its own inline copy
 * pending a future shared-helper refactor). */
#define _GNU_SOURCE   /* strcasestr */
#include "mqc.h"
#include "mqc_peer.h"
#include "read-config.h"
#include "../../../socket-level-wrapper-MQC/config.h"
#include "config.h"

#define FIPS_ENTRY_TYPE       0x02
#define MTC_HASH_SIZE         32
#define LABEL_MAX             64
#define PACKAGE_MAX           64
#define VERSION_MAX           64
#define PUBLISHER_MAX         253
#define PATH_FIELD_MAX        512
#define FILES_MAX             65535
#define VALIDITY_DAYS_MAX     365
#define VALIDITY_DAYS_DEFAULT 30
#define SCHEMA_VERSION        1

/* ML-DSA-87 raw signature size — same constant the bootstrap path
 * uses.  Keeps us off any sizeof(struct) drift from upstream. */
#define MLDSA87_SIG_SIZE      4627
/* Base64 of 4627 bytes = ceil(4627/3)*4 = 6172 chars (no padding) or
 * 6172 with `=` padding. */
#define MLDSA87_SIG_B64_MAX   8192

#define die(fmt, ...) do { \
    fprintf(stderr, "fips-manifest-submit: " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while (0)

static int g_pretty = 0;

/* -------- byte buffer ------------------------------------------------ */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} buf_t;

static void buf_init(buf_t *b)             { b->data = NULL; b->len = b->cap = 0; }
static void buf_free(buf_t *b)             { free(b->data); b->data = NULL; b->len = b->cap = 0; }
static void buf_reserve(buf_t *b, size_t n) {
    if (b->cap >= n) return;
    size_t nc = b->cap ? b->cap : 64;
    while (nc < n) nc *= 2;
    void *p = realloc(b->data, nc);
    if (!p) die("oom (buf_reserve %zu)", nc);
    b->data = p; b->cap = nc;
}
static void buf_append(buf_t *b, const void *src, size_t n) {
    buf_reserve(b, b->len + n);
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

/* -------- helpers ---------------------------------------------------- */

static int read_whole_file(const char *path, uint8_t **out, size_t *out_sz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);
    uint8_t *p = malloc((size_t)sz + 1);
    if (!p) { fclose(fp); return -1; }
    if (sz > 0 && fread(p, 1, (size_t)sz, fp) != (size_t)sz) {
        free(p); fclose(fp); return -1;
    }
    p[sz] = 0;
    fclose(fp);
    *out = p; *out_sz = (size_t)sz;
    return 0;
}

static int validate_label(const char *s)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > LABEL_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return -1;
    }
    return 0;
}

/* package: [A-Za-z0-9._-]{1,64} */
static int validate_package(const char *s)
{
    return validate_label(s);   /* identical charset */
}

/* version: [A-Za-z0-9._+~-]{1,64} */
static int validate_version(const char *s)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > VERSION_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '+' || c == '~' || c == '-'))
            return -1;
    }
    return 0;
}

/* publisher: lowercase ASCII LDH per RFC 1035. */
static int validate_publisher(const char *s)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > PUBLISHER_MAX) return -1;
    if (s[0] == '.' || s[n-1] == '.') return -1;
    int label_len = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.') {
            if (label_len == 0 || label_len > 63) return -1;
            label_len = 0;
            continue;
        }
        if (label_len == 0 && (c == '-' || c == '_')) return -1;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-')) return -1;
        label_len++;
    }
    if (label_len == 0 || label_len > 63) return -1;
    return 0;
}

/* path: per spec §"Files array" — UTF-8 1..512, no leading /, no
 * `.` or `..` segments, no embedded NUL, no //, no trailing /. */
static int validate_relpath(const char *s)
{
    if (!s) return -1;
    size_t n = strlen(s);
    if (n < 1 || n > PATH_FIELD_MAX) return -1;
    if (s[0] == '/' || s[n-1] == '/') return -1;
    if (strstr(s, "//")) return -1;
    if (strstr(s, "/../") || !strncmp(s, "../", 3)) return -1;
    if (n >= 3 && !strcmp(s + n - 3, "/..")) return -1;
    if (!strcmp(s, ".") || !strcmp(s, "..")) return -1;
    if (strstr(s, "/./") || !strncmp(s, "./", 2)) return -1;
    if (n >= 2 && !strcmp(s + n - 2, "/.")) return -1;
    return 0;
}

/* -------- recursive directory walk ---------------------------------- */

typedef struct {
    char  path[PATH_FIELD_MAX + 1];
    char  sha256[65];
} file_entry;

typedef struct {
    file_entry *items;
    size_t      n;
    size_t      cap;
} file_list;

static void fl_init(file_list *fl)        { fl->items = NULL; fl->n = fl->cap = 0; }
static void fl_free(file_list *fl)        { free(fl->items); fl->items = NULL; fl->n = fl->cap = 0; }
static void fl_push(file_list *fl, const file_entry *e)
{
    if (fl->n == FILES_MAX)
        die("too many files (max %d)", FILES_MAX);
    if (fl->n >= fl->cap) {
        size_t nc = fl->cap ? fl->cap * 2 : 256;
        void *p = realloc(fl->items, nc * sizeof(file_entry));
        if (!p) die("oom (fl_push %zu)", nc);
        fl->items = p; fl->cap = nc;
    }
    fl->items[fl->n++] = *e;
}

static int fl_cmp(const void *a, const void *b)
{
    return strcmp(((const file_entry *)a)->path,
                  ((const file_entry *)b)->path);
}

/* read_manifest — populate `fl` from a sign-dir.sh-style MANIFEST.sha256.
 *
 * Format produced by fips-framework/tools/sh/sign-dir.sh:
 *   # publisher: <DOMAIN>
 *   # publisher-cert-index: <N>
 *   # git-commit: <HEAD>[-dirty]      (optional)
 *   <sha256-hex>  <relpath>
 *   <sha256-hex>  <relpath>
 *   ...
 *
 * Out-params (any may be NULL): publisher_out, cert_index_out,
 * git_commit_out (each receive heap-allocated strings except
 * cert_index_out which is an int*).  Lines starting with '#' are
 * header lines; the three known headers above are parsed, others
 * are ignored.  Blank lines skipped.  Body lines must be exactly
 * "<64-hex-chars>  <path>" (two-space separator, sha256sum format).
 */
static void read_manifest(const char *manifest_path,
                          file_list *fl,
                          char **publisher_out,
                          int  *cert_index_out,
                          char **git_commit_out)
{
    FILE *f = fopen(manifest_path, "r");
    if (!f) die("cannot open MANIFEST: %s: %s",
                manifest_path, strerror(errno));

    if (publisher_out)  *publisher_out  = NULL;
    if (cert_index_out) *cert_index_out = -1;
    if (git_commit_out) *git_commit_out = NULL;

    char line[PATH_FIELD_MAX + 128];
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = 0;
        if (n == 0) continue;

        if (line[0] == '#') {
            const char *p = line + 1;
            while (*p == ' ' || *p == '\t') p++;
            if (publisher_out && !*publisher_out &&
                strncmp(p, "publisher:", 10) == 0) {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
                *publisher_out = strdup(p);
            } else if (cert_index_out && *cert_index_out < 0 &&
                       strncmp(p, "publisher-cert-index:", 21) == 0) {
                p += 21;
                while (*p == ' ' || *p == '\t') p++;
                *cert_index_out = atoi(p);
            } else if (git_commit_out && !*git_commit_out &&
                       strncmp(p, "git-commit:", 11) == 0) {
                p += 11;
                while (*p == ' ' || *p == '\t') p++;
                *git_commit_out = strdup(p);
            }
            continue;
        }

        /* Body line: <64-hex>  <path>  (sha256sum format) */
        if (n < 67 || line[64] != ' ' || line[65] != ' ') {
            fclose(f);
            die("MANIFEST line not in <64-hex>'  '<path> form: %s", line);
        }
        char hash[65];
        memcpy(hash, line, 64);
        hash[64] = 0;
        for (int i = 0; i < 64; i++) {
            char c = hash[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                fclose(f);
                die("MANIFEST hash not lowercase hex: %s", hash);
            }
        }
        const char *path = line + 66;
        size_t path_len = n - 66;
        if (path_len > PATH_FIELD_MAX) {
            fclose(f);
            die("MANIFEST path > %d bytes: %s", PATH_FIELD_MAX, path);
        }
        if (validate_relpath(path) != 0) {
            fclose(f);
            die("MANIFEST has invalid path: %s", path);
        }

        file_entry e;
        snprintf(e.path,   sizeof(e.path),   "%s", path);
        snprintf(e.sha256, sizeof(e.sha256), "%s", hash);
        fl_push(fl, &e);
    }
    fclose(f);
}

/* -------- key loading ----------------------------------------------- */

typedef struct {
    dilithium_key priv;
    dilithium_key pub;
    int           priv_init;
    int           pub_init;
    int           cert_index;
    char          subject[PUBLISHER_MAX + 1];
} publisher_key;

static int read_index_file(const char *path)
{
    uint8_t *buf = NULL;
    size_t   sz  = 0;
    if (read_whole_file(path, &buf, &sz) != 0) return -1;
    int idx = atoi((const char *)buf);
    free(buf);
    return idx;
}

static int load_publisher_key(const char *tpm_dir, publisher_key *pk)
{
    char path[2080];
    uint8_t *priv_pem = NULL, *pub_pem = NULL;
    size_t priv_pem_sz = 0, pub_pem_sz = 0;

    snprintf(path, sizeof(path), "%s/private_key.pem", tpm_dir);
    if (read_whole_file(path, &priv_pem, &priv_pem_sz) != 0)
        die("cannot read %s: %s", path, strerror(errno));
    snprintf(path, sizeof(path), "%s/public_key.pem", tpm_dir);
    if (read_whole_file(path, &pub_pem, &pub_pem_sz) != 0)
        die("cannot read %s: %s", path, strerror(errno));

    uint8_t *priv_der = malloc(priv_pem_sz);
    uint8_t *pub_der  = malloc(pub_pem_sz);
    if (!priv_der || !pub_der) die("oom (key der)");

    int priv_der_sz = wc_KeyPemToDer(priv_pem, (int)priv_pem_sz,
                                     priv_der, (word32)priv_pem_sz, NULL);
    int pub_der_sz  = wc_PubKeyPemToDer(pub_pem, (int)pub_pem_sz,
                                        pub_der, (word32)pub_pem_sz);
    free(priv_pem); free(pub_pem);
    if (priv_der_sz <= 0 || pub_der_sz <= 0)
        die("PEM decode failed (priv=%d pub=%d)", priv_der_sz, pub_der_sz);

    if (wc_dilithium_init(&pk->priv) != 0) die("dilithium_init priv");
    pk->priv_init = 1;
    if (wc_dilithium_init(&pk->pub) != 0)  die("dilithium_init pub");
    pk->pub_init = 1;

    if (wc_dilithium_set_level(&pk->priv, WC_ML_DSA_87) != 0 ||
        wc_dilithium_set_level(&pk->pub,  WC_ML_DSA_87) != 0)
        die("set_level WC_ML_DSA_87");

    word32 idx = 0;
    if (wc_Dilithium_PrivateKeyDecode(priv_der, &idx, &pk->priv,
                                      (word32)priv_der_sz) != 0)
        die("PrivateKeyDecode");
    idx = 0;
    if (wc_Dilithium_PublicKeyDecode(pub_der, &idx, &pk->pub,
                                     (word32)pub_der_sz) != 0)
        die("PublicKeyDecode");

    free(priv_der); free(pub_der);

    /* cert_index from ~/.TPM/<dir>/index */
    snprintf(path, sizeof(path), "%s/index", tpm_dir);
    pk->cert_index = read_index_file(path);
    if (pk->cert_index < 0) die("missing or unreadable %s", path);

    /* subject from ~/.TPM/<dir>/certificate.json — read tbs_entry.subject */
    snprintf(path, sizeof(path), "%s/certificate.json", tpm_dir);
    uint8_t *cj_buf = NULL; size_t cj_sz = 0;
    if (read_whole_file(path, &cj_buf, &cj_sz) != 0)
        die("cannot read %s: %s", path, strerror(errno));
    struct json_object *cj = json_tokener_parse((const char *)cj_buf);
    free(cj_buf);
    if (!cj) die("certificate.json is not valid JSON");
    struct json_object *sc, *tbs, *subj;
    if (!json_object_object_get_ex(cj, "standalone_certificate", &sc) ||
        !json_object_object_get_ex(sc, "tbs_entry", &tbs) ||
        !json_object_object_get_ex(tbs, "subject", &subj)) {
        json_object_put(cj);
        die("certificate.json missing standalone_certificate.tbs_entry.subject");
    }
    const char *s = json_object_get_string(subj);
    if (!s || strlen(s) > PUBLISHER_MAX)
        { json_object_put(cj); die("invalid subject"); }
    snprintf(pk->subject, sizeof(pk->subject), "%s", s);
    json_object_put(cj);
    return 0;
}

static void free_publisher_key(publisher_key *pk)
{
    if (pk->priv_init) { wc_dilithium_free(&pk->priv); pk->priv_init = 0; }
    if (pk->pub_init)  { wc_dilithium_free(&pk->pub);  pk->pub_init  = 0; }
}

/* -------- canonical JSON build -------------------------------------- */

/* Build the manifest object with keys added in alphabetical order.
 * json-c emits in insertion order with JSON_C_TO_STRING_PLAIN, so
 * insertion-alphabetical = output-alphabetical. */
static struct json_object *build_manifest(
    const char *publisher, int cert_index,
    const char *package, const char *version,
    const char *git_commit_or_null,
    double not_before, double expires,
    const file_list *files,
    const char *signature_b64)    /* "" for signing, real for final */
{
    struct json_object *m = json_object_new_object();

    /* alphabetical: alg, expires, files, git_commit?, not_before,
     * package, publisher, publisher_cert_index, schema_version,
     * signature, version */
    json_object_object_add(m, "alg", json_object_new_string("ML-DSA-87"));
    json_object_object_add(m, "expires", json_object_new_double(expires));

    struct json_object *arr = json_object_new_array();
    for (size_t i = 0; i < files->n; i++) {
        struct json_object *fe = json_object_new_object();
        json_object_object_add(fe, "path",
            json_object_new_string(files->items[i].path));
        json_object_object_add(fe, "sha256",
            json_object_new_string(files->items[i].sha256));
        json_object_array_add(arr, fe);
    }
    json_object_object_add(m, "files", arr);

    if (git_commit_or_null && git_commit_or_null[0])
        json_object_object_add(m, "git_commit",
            json_object_new_string(git_commit_or_null));

    json_object_object_add(m, "not_before", json_object_new_double(not_before));
    json_object_object_add(m, "package",    json_object_new_string(package));
    json_object_object_add(m, "publisher",  json_object_new_string(publisher));
    json_object_object_add(m, "publisher_cert_index",
        json_object_new_int(cert_index));
    json_object_object_add(m, "schema_version",
        json_object_new_int(SCHEMA_VERSION));
    json_object_object_add(m, "signature",
        json_object_new_string(signature_b64 ? signature_b64 : ""));
    json_object_object_add(m, "version",    json_object_new_string(version));

    return m;
}

static void serialize_canonical(struct json_object *m,
                                buf_t *out)
{
    /* JSON_C_TO_STRING_PLAIN emits in insertion order with no
     * whitespace.  Spec requires alphabetical key order with no
     * whitespace; we pre-insert in alphabetical order so this matches.
     * NOSLASHESCAPE: spec §"Canonical JSON" rejects `\/`; emit literal
     * `/` instead.  Base64 signature payload contains many `/`. */
    const char *s = json_object_to_json_string_ext(m,
        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!s) die("json_object_to_json_string failed");
    buf_append(out, s, strlen(s));
}

/* git_commit comes from MANIFEST.sha256's `# git-commit:` header
 * (recorded by sign-dir.sh).  No git probes here. */

/* -------- mqc HTTP POST (mirrors fips-manifest-revoke.c::mqc_http_post) -- */

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

    /* mqc_read consumes the frame length prefix BEFORE checking that
     * the frame fits in the caller's buffer; if total_len > sz, it
     * returns -1 with the frame data already off the wire (lost).
     * The server packs HTTP header + body into a single AEAD frame
     * (mtc_http.c::http_send_json comment), so a fips-manifest receipt
     * with the full canonical leaf + inclusion proof + cosignatures
     * easily exceeds 16 KB.  Pre-size to MQC_MAX_MSG (1 MiB, the
     * single-frame ceiling) so the first read can always fit. */
    int buf_cap = 1024 * 1024, buf_sz = 0, n;
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

/* -------- main ------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --domain D [--label L] --package P --version V \\\n"
        "                            --source-dir DIR\n"
        "                            [--manifest PATH]      (default: <source-dir>/MANIFEST.sha256)\n"
        "                            [--out FILE]           (also save raw leaf)\n"
        "                            [--receipt-out FILE]   (override receipt path)\n"
        "                            [--validity-days N]    (default: 30, max: 365)\n"
        "                            [--dry-run]            (build + sign, skip POST)\n"
        "                            [--pretty]             (indented JSON to stderr)\n"
        "                            [-s, --server H[:P]]   (default: [global] url-server)\n"
        "                            [--now EPOCH]\n"
        "\n"
        "Reads <source-dir>/MANIFEST.sha256 (produced by sign-dir.sh,\n"
        "typically with -g so gitignored files are excluded), wraps the\n"
        "file→hash table as a FIPS canonical leaf with the FIPS-specific\n"
        "metadata (package, version, validity window, schema_version),\n"
        "signs it with the publisher key at ~/.TPM/<DOMAIN>-<LABEL>/, and\n"
        "(default mode) POSTs to /fips/manifest over MQC.  Server's\n"
        "receipt persisted under\n"
        "<tpm_dir>/fips-receipts/<package>-<version>-<log_index>.json.\n"
        "\n"
        "--dry-run skips the network step; emits raw leaf bytes\n"
        "(0x02 || canonical_json) on stdout (or --out).\n"
        "\n"
        "Pre-req: run `sign-dir.sh -g <DOMAIN> <source-dir>` first to\n"
        "produce MANIFEST.sha256 + MANIFEST.sig.\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *domain = NULL, *label = NULL, *package = NULL;
    const char *version = NULL, *source_dir = NULL, *out_path = NULL;
    const char *receipt_out_path = NULL;
    const char *manifest_path_cli = NULL;
    const char *cli_server = NULL;
    int validity_days = VALIDITY_DAYS_DEFAULT;
    int dry_run = 0;
    long now_override = -1;   /* >=0 pins not_before; for reproducible test vectors */

    static struct option opts[] = {
        {"domain",            required_argument, 0, 'd'},
        {"label",             required_argument, 0, 'l'},
        {"package",           required_argument, 0, 'p'},
        {"version",           required_argument, 0, 'v'},
        {"source-dir",        required_argument, 0, 'S'},
        {"manifest",          required_argument, 0, 'M'},
        {"out",               required_argument, 0, 'o'},
        {"receipt-out",       required_argument, 0, 'R'},
        {"validity-days",     required_argument, 0, 't'},
        {"dry-run",           no_argument,       0, 'n'},
        {"pretty",            no_argument,       0, 'P'},
        {"server",            required_argument, 0, 's'},
        {"now",               required_argument, 0, 'N'},
        {"help",              no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv,
                            "d:l:p:v:S:M:o:R:t:nPs:N:h", opts, NULL)) != -1) {
        switch (c) {
            case 'd': domain = optarg; break;
            case 'l': label = optarg; break;
            case 'p': package = optarg; break;
            case 'v': version = optarg; break;
            case 'S': source_dir = optarg; break;
            case 'M': manifest_path_cli = optarg; break;
            case 'o': out_path = optarg; break;
            case 'R': receipt_out_path = optarg; break;
            case 't': validity_days = atoi(optarg); break;
            case 'n': dry_run = 1; break;
            case 'P': g_pretty = 1; break;
            case 's': cli_server = optarg; break;
            case 'N': now_override = atol(optarg); break;
            default:  usage(argv[0]);
        }
    }

    if (!domain || !package || !version || !source_dir)
        usage(argv[0]);
    if (validity_days < 1 || validity_days > VALIDITY_DAYS_MAX)
        die("--validity-days out of range (1..%d)", VALIDITY_DAYS_MAX);
    if (label && validate_label(label) != 0)
        die("invalid --label");
    if (validate_package(package) != 0)
        die("invalid --package");
    if (validate_version(version) != 0)
        die("invalid --version");
    if (validate_publisher(domain) != 0)
        die("invalid --domain (must be lowercase ASCII LDH)");

    /* Locate the TPM identity.  --label is optional: when omitted, the
     * identity dir is ~/.TPM/<DOMAIN>/ (matches sign-dir.sh's
     * convention).  When set, ~/.TPM/<DOMAIN>-<LABEL>/. */
    const char *home = getenv("HOME");
    if (!home) die("HOME unset");
    char tpm_dir[2048];
    if (label && label[0])
        snprintf(tpm_dir, sizeof(tpm_dir), "%s/.TPM/%s-%s",
                 home, domain, label);
    else
        snprintf(tpm_dir, sizeof(tpm_dir), "%s/.TPM/%s", home, domain);
    struct stat st;
    if (stat(tpm_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        die("TPM identity not found: %s", tpm_dir);

    /* Resolve source dir */
    char src_abs[4096];
    if (!realpath(source_dir, src_abs))
        die("realpath(%s): %s", source_dir, strerror(errno));

    /* Load keys + cert metadata */
    publisher_key pk = {0};
    load_publisher_key(tpm_dir, &pk);

    if (strcmp(pk.subject, domain) != 0)
        die("subject mismatch: cert says '%s' but --domain is '%s'",
            pk.subject, domain);

    /* Read sign-dir.sh-produced MANIFEST.sha256 instead of re-walking
     * the source tree.  Single source of truth: whatever set sign-dir.sh
     * decided to include (with -g, .gitignored artefacts are excluded). */
    char default_manifest[8192];
    const char *manifest_path = manifest_path_cli;
    if (!manifest_path) {
        snprintf(default_manifest, sizeof(default_manifest),
                 "%s/MANIFEST.sha256", src_abs);
        manifest_path = default_manifest;
    }

    file_list files;
    fl_init(&files);
    char *m_publisher = NULL;
    int   m_cert_index = -1;
    char *m_git_commit = NULL;
    read_manifest(manifest_path, &files,
                  &m_publisher, &m_cert_index, &m_git_commit);
    if (files.n == 0)
        die("MANIFEST contained no file entries: %s", manifest_path);

    /* Cross-check the manifest header against CLI / cert. */
    if (m_publisher && strcmp(m_publisher, domain) != 0)
        die("MANIFEST publisher '%s' != --domain '%s'", m_publisher, domain);
    if (m_cert_index >= 0 && m_cert_index != pk.cert_index)
        die("MANIFEST publisher-cert-index %d != cert.json index %d",
            m_cert_index, pk.cert_index);

    qsort(files.items, files.n, sizeof(file_entry), fl_cmp);

    /* Reject duplicates after sort */
    for (size_t i = 1; i < files.n; i++) {
        if (strcmp(files.items[i-1].path, files.items[i].path) == 0)
            die("duplicate path after sort: %s", files.items[i].path);
    }

    /* git_commit comes from MANIFEST header (sign-dir.sh records it).
     * If the source dir wasn't a git repo at sign time, the header is
     * absent and the canonical leaf simply omits the field. */
    char git_commit[80] = {0};
    int has_git = 0;
    if (m_git_commit && m_git_commit[0] &&
        strlen(m_git_commit) < sizeof(git_commit)) {
        snprintf(git_commit, sizeof(git_commit), "%s", m_git_commit);
        has_git = 1;
    }

    /* Validity window.  --now pins not_before for reproducible
     * canonical bytes (test vectors); default is wall-clock time. */
    double now = (now_override >= 0)
        ? (double)now_override
        : (double)time(NULL);
    double expires = now + (double)validity_days * 86400.0;

    /* Build manifest with signature="" */
    struct json_object *m_signing = build_manifest(
        domain, pk.cert_index, package, version,
        has_git ? git_commit : NULL,
        now, expires, &files, "");

    buf_t signing_bytes; buf_init(&signing_bytes);
    serialize_canonical(m_signing, &signing_bytes);
    json_object_put(m_signing);

    /* Sign */
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) die("wc_InitRng");
    uint8_t sig[MLDSA87_SIG_SIZE];
    word32 sig_sz = sizeof(sig);
    int rc = wc_dilithium_sign_ctx_msg(NULL, 0,
        signing_bytes.data, (word32)signing_bytes.len,
        sig, &sig_sz, &pk.priv, &rng);
    wc_FreeRng(&rng);
    if (rc != 0) die("dilithium_sign rc=%d", rc);

    /* base64 the sig */
    char sig_b64[MLDSA87_SIG_B64_MAX];
    word32 sig_b64_sz = sizeof(sig_b64);
    if (Base64_Encode_NoNl(sig, sig_sz, (byte *)sig_b64, &sig_b64_sz) != 0)
        die("Base64_Encode_NoNl");
    if (sig_b64_sz >= sizeof(sig_b64)) die("base64 buffer overflow");
    sig_b64[sig_b64_sz] = 0;

    /* Self-verify before emission */
    {
        int verify_res = 0;
        rc = wc_dilithium_verify_ctx_msg(sig, sig_sz, NULL, 0,
            signing_bytes.data, (word32)signing_bytes.len,
            &verify_res, &pk.pub);
        if (rc != 0 || verify_res != 1)
            die("self-verify failed (rc=%d res=%d)", rc, verify_res);
    }

    /* Build final manifest with real signature */
    struct json_object *m_final = build_manifest(
        domain, pk.cert_index, package, version,
        has_git ? git_commit : NULL,
        now, expires, &files, sig_b64);

    buf_t final_bytes; buf_init(&final_bytes);
    serialize_canonical(m_final, &final_bytes);

    /* Round-trip canonicalization check (spec §"Server-side validation
     * order" step 3, "Re-canonicalize and byte-compare").  Parse the
     * canonical bytes back and re-serialize; any drift in
     * insertion-order vs alphabetical order, escape choices, or
     * number formatting will surface here, before the leaf reaches
     * the wire. */
    {
        struct json_object *m_parsed = json_tokener_parse(
            (const char *)final_bytes.data);
        if (!m_parsed)
            die("self round-trip: tokener_parse failed");
        buf_t roundtrip; buf_init(&roundtrip);
        serialize_canonical(m_parsed, &roundtrip);
        json_object_put(m_parsed);
        if (roundtrip.len != final_bytes.len ||
            memcmp(roundtrip.data, final_bytes.data, final_bytes.len) != 0) {
            for (size_t i = 0;
                 i < (roundtrip.len < final_bytes.len ?
                      roundtrip.len : final_bytes.len);
                 i++) {
                if (roundtrip.data[i] != final_bytes.data[i]) {
                    fprintf(stderr,
                        "fips-manifest-submit: canonical-form drift at "
                        "byte %zu (built=%02x parsed=%02x)\n",
                        i, final_bytes.data[i], roundtrip.data[i]);
                    break;
                }
            }
            buf_free(&roundtrip);
            die("self round-trip canonicalization mismatch "
                "(built=%zu parsed=%zu bytes)", final_bytes.len, roundtrip.len);
        }
        buf_free(&roundtrip);
    }

    /* Optional pretty dump to stderr */
    if (g_pretty) {
        const char *p = json_object_to_json_string_ext(m_final,
            JSON_C_TO_STRING_PRETTY);
        fprintf(stderr, "%s\n", p);
    }
    json_object_put(m_final);

    /* Build the leaf bytes (0x02 prefix + canonical JSON).  The
     * server's /fips/manifest body excludes the prefix — that's
     * a leaf-internal marker the server prepends before
     * mtc_store_add_entry — but --out and --dry-run stdout emit
     * the full leaf for offline inspection / piping into verify. */
    buf_t leaf; buf_init(&leaf);
    uint8_t prefix = FIPS_ENTRY_TYPE;
    buf_append(&leaf, &prefix, 1);
    buf_append(&leaf, final_bytes.data, final_bytes.len);

    /* Optional: also save the raw leaf bytes locally. */
    if (out_path) {
        FILE *of = fopen(out_path, "wb");
        if (!of) die("cannot write %s: %s", out_path, strerror(errno));
        if (fwrite(leaf.data, 1, leaf.len, of) != leaf.len)
            die("fwrite failed");
        fclose(of);
    }

    if (dry_run) {
        /* Offline mode: emit raw leaf bytes to stdout if --out wasn't
         * given.  Don't network. */
        if (!out_path) {
            if (fwrite(leaf.data, 1, leaf.len, stdout) != leaf.len)
                die("fwrite failed");
        }
        fprintf(stderr,
            "fips-manifest-submit: [dry-run] built %zu-byte canonical leaf "
            "(%zu files from %s, signature %zu B64-chars, cert_index %d)\n",
            leaf.len, files.n, manifest_path,
            (size_t)sig_b64_sz, pk.cert_index);
        buf_free(&signing_bytes); buf_free(&final_bytes); buf_free(&leaf);
        fl_free(&files);
        free_publisher_key(&pk);
        free(m_publisher); free(m_git_commit);
        return 0;
    }

    /* ---- wire-POST mode (default) -------------------------------- */

    /* Resolve server: --server, then [global] url-server, then default. */
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

    static unsigned char ca_pubkey[DILITHIUM_LEVEL5_PUB_KEY_SIZE];
    if (mqc_load_ca_pubkey(host_buf, ca_pubkey) != 0)
        die("could not load CA cosigner pubkey from %s", host_buf);

    mqc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role         = MQC_CLIENT;
    cfg.tpm_path     = tpm_dir;
    cfg.mtc_server   = host_buf;
    cfg.ca_pubkey    = ca_pubkey;
    cfg.ca_pubkey_sz = DILITHIUM_LEVEL5_PUB_KEY_SIZE;

    mqc_ctx_t *ctx = mqc_ctx_new(&cfg);
    if (!ctx) die("MQC context creation failed (tpm_path=%s)", tpm_dir);

    /* Server expects canonical JSON only, NOT the 0x02-prefixed leaf. */
    long code = 0;
    char *resp = mqc_http_post(ctx, host_buf, port, "/fips/manifest",
                               (const char *)final_bytes.data,
                               (int)final_bytes.len, &code);
    mqc_ctx_free(ctx);

    if (!resp) {
        free(server_owned);
        free(m_publisher); free(m_git_commit);
        die("MQC POST %s:%d/fips/manifest failed", host_buf, port);
    }
    if (code != 200) {
        fprintf(stderr,
            "fips-manifest-submit: server returned HTTP %ld\n%s\n",
            code, resp);
        free(resp);
        free(server_owned);
        buf_free(&signing_bytes); buf_free(&final_bytes); buf_free(&leaf);
        fl_free(&files);
        free_publisher_key(&pk);
        free(m_publisher); free(m_git_commit);
        return 1;
    }

    /* Parse the receipt to pull out leaf_index for the persistence path. */
    struct json_object *r = json_tokener_parse(resp);
    if (!r) {
        fprintf(stderr,
            "fips-manifest-submit: server reply not valid JSON: %s\n", resp);
        free(resp);
        free(server_owned);
        free(m_publisher); free(m_git_commit);
        return 1;
    }
    int leaf_index = -1;
    {
        struct json_object *v;
        if (json_object_object_get_ex(r, "leaf_index", &v))
            leaf_index = json_object_get_int(v);
    }

    /* Persist the receipt.  Default path:
     *   <tpm_dir>/fips-receipts/<package>-<version>-<log_index>.json
     * --receipt-out overrides. */
    char default_receipt_path[4096];
    if (!receipt_out_path) {
        char dir[2200];
        snprintf(dir, sizeof(dir), "%s/fips-receipts", tpm_dir);
        if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            fprintf(stderr,
                "fips-manifest-submit: warning: mkdir %s: %s\n",
                dir, strerror(errno));
        snprintf(default_receipt_path, sizeof(default_receipt_path),
                 "%s/%s-%s-%d.json",
                 dir, package, version, leaf_index);
        receipt_out_path = default_receipt_path;
    }

    {
        FILE *rf = fopen(receipt_out_path, "wb");
        if (!rf) {
            fprintf(stderr,
                "fips-manifest-submit: warning: cannot write %s: %s\n",
                receipt_out_path, strerror(errno));
        } else {
            const char *pretty = json_object_to_json_string_ext(
                r, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
            size_t pn = strlen(pretty);
            if (fwrite(pretty, 1, pn, rf) != pn ||
                fwrite("\n", 1, 1, rf) != 1) {
                fprintf(stderr,
                    "fips-manifest-submit: warning: write to %s failed\n",
                    receipt_out_path);
            }
            fclose(rf);
            chmod(receipt_out_path, 0600);
        }
    }

    fprintf(stderr,
        "fips-manifest-submit: submitted: log_index=%d "
        "(%zu files, %zu-byte canonical leaf, cert_index %d)\n"
        "fips-manifest-submit: receipt: %s\n",
        leaf_index, files.n, leaf.len, pk.cert_index, receipt_out_path);

    json_object_put(r);
    free(resp);
    free(server_owned);
    free(m_publisher); free(m_git_commit);

    buf_free(&signing_bytes); buf_free(&final_bytes); buf_free(&leaf);
    fl_free(&files);
    free_publisher_key(&pk);
    return 0;
}
