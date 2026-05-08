/*
 * fips-manifest-submit — build a FIPS-manifest canonical leaf.
 *
 * Phase-1 (this revision): --dry-run only.  Builds the
 * canonical-leaf bytes per fips-framework/spec-canonical-leaf.md,
 * signs them with the publisher's ML-DSA-87 key from
 * ~/.TPM/<DOMAIN>-<LABEL>/, self-verifies the signature, and writes
 * the result to stdout (or --out).  No network.
 *
 * Phase-2 (later): same construction, then POST to /fips/manifest
 * over MQC and persist the receipt.
 *
 * Usage:
 *   fips-manifest-submit --domain DOMAIN --label LABEL \
 *                        --package PKG  --version VER \
 *                        --source-dir DIR \
 *                        [--out FILE]            (default: stdout)
 *                        [--validity-days N]     (default: 30, max: 365)
 *                        [--dry-run]             (default: on; only mode)
 *                        [--pretty]              (also emit indented JSON to stderr)
 *
 * Output (stdout):
 *   final canonical leaf bytes — 0x02 || canonical_json — raw binary.
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

static int sha256_file_hex(const char *path, char out_hex[65])
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) { fclose(fp); return -1; }
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (wc_Sha256Update(&sha, buf, (word32)n) != 0) {
            wc_Sha256Free(&sha); fclose(fp); return -1;
        }
    }
    uint8_t h[32];
    if (wc_Sha256Final(&sha, h) != 0) {
        wc_Sha256Free(&sha); fclose(fp); return -1;
    }
    wc_Sha256Free(&sha);
    fclose(fp);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out_hex[i*2]   = hex[(h[i] >> 4) & 0xf];
        out_hex[i*2+1] = hex[h[i] & 0xf];
    }
    out_hex[64] = 0;
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

/* base_dir: absolute path; rel_prefix: relative prefix accumulated
 * as we descend (empty at top level).  Same exclusions as
 * sign-dir.sh: skip .git/, MANIFEST.sha256, MANIFEST.sig,
 * private_key.pem.  Symlinks followed. */
static void walk_dir(const char *base_dir, const char *rel_prefix,
                     file_list *fl)
{
    char abs[4096];
    if (rel_prefix[0])
        snprintf(abs, sizeof(abs), "%s/%s", base_dir, rel_prefix);
    else
        snprintf(abs, sizeof(abs), "%s", base_dir);

    DIR *d = opendir(abs);
    if (!d) die("opendir(%s): %s", abs, strerror(errno));

    struct dirent *de;
    while ((de = readdir(d))) {
        const char *name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if (!strcmp(name, ".git")) continue;
        if (!strcmp(name, "MANIFEST.sha256") ||
            !strcmp(name, "MANIFEST.sig") ||
            !strcmp(name, "private_key.pem")) continue;

        char rel[PATH_FIELD_MAX + 64];
        if (rel_prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", rel_prefix, name);
        else
            snprintf(rel, sizeof(rel), "%s", name);

        char child_abs[4096];
        snprintf(child_abs, sizeof(child_abs), "%s/%s", base_dir, rel);

        struct stat st;
        if (stat(child_abs, &st) != 0) continue;   /* broken symlink */

        if (S_ISDIR(st.st_mode)) {
            walk_dir(base_dir, rel, fl);
        } else if (S_ISREG(st.st_mode)) {
            file_entry e;
            if (strlen(rel) > PATH_FIELD_MAX)
                die("path > %d bytes: %s", PATH_FIELD_MAX, rel);
            if (validate_relpath(rel) != 0)
                die("invalid path: %s", rel);
            snprintf(e.path, sizeof(e.path), "%s", rel);
            if (sha256_file_hex(child_abs, e.sha256) != 0)
                die("sha256 failed for %s", child_abs);
            fl_push(fl, &e);
        }
    }
    closedir(d);
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

static int git_head_commit(const char *src_dir, char out[80])
{
    char cmd[4200];
    snprintf(cmd, sizeof(cmd),
        "git -C '%s' rev-parse HEAD 2>/dev/null", src_dir);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    if (!fgets(out, 80, p)) { pclose(p); return -1; }
    pclose(p);
    size_t n = strlen(out);
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
    if (n != 40 && n != 64) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = out[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
    }
    /* dirty? */
    snprintf(cmd, sizeof(cmd),
        "git -C '%s' diff-index --quiet HEAD -- . 2>/dev/null", src_dir);
    if (system(cmd) != 0)
        snprintf(out + n, 80 - n, "-dirty");
    return 0;
}

/* -------- main ------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --domain D --label L --package P --version V \\\n"
        "                            --source-dir DIR [--out FILE]\n"
        "                            [--validity-days N] [--dry-run] [--pretty]\n"
        "                            [--now EPOCH]\n"
        "\n"
        "Builds canonical FIPS-manifest leaf bytes per\n"
        "fips-framework/spec-canonical-leaf.md and signs with the\n"
        "publisher key at ~/.TPM/<DOMAIN>-<LABEL>/.  Currently\n"
        "--dry-run is the only mode (network submission lands in\n"
        "phase 2).  Default output: raw canonical-leaf bytes\n"
        "(0x02 || canonical_json) on stdout.  --pretty also writes\n"
        "indented JSON to stderr for inspection.\n",
        prog);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *domain = NULL, *label = NULL, *package = NULL;
    const char *version = NULL, *source_dir = NULL, *out_path = NULL;
    int validity_days = VALIDITY_DAYS_DEFAULT;
    int dry_run = 1;   /* phase 1: only mode */
    long now_override = -1;   /* >=0 pins not_before; for reproducible test vectors */

    static struct option opts[] = {
        {"domain",         required_argument, 0, 'd'},
        {"label",          required_argument, 0, 'l'},
        {"package",        required_argument, 0, 'p'},
        {"version",        required_argument, 0, 'v'},
        {"source-dir",     required_argument, 0, 's'},
        {"out",            required_argument, 0, 'o'},
        {"validity-days",  required_argument, 0, 't'},
        {"dry-run",        no_argument,       0, 'n'},
        {"pretty",         no_argument,       0, 'P'},
        {"now",            required_argument, 0, 'N'},
        {"help",           no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "d:l:p:v:s:o:t:nPN:h", opts, NULL)) != -1) {
        switch (c) {
            case 'd': domain = optarg; break;
            case 'l': label = optarg; break;
            case 'p': package = optarg; break;
            case 'v': version = optarg; break;
            case 's': source_dir = optarg; break;
            case 'o': out_path = optarg; break;
            case 't': validity_days = atoi(optarg); break;
            case 'n': dry_run = 1; break;
            case 'P': g_pretty = 1; break;
            case 'N': now_override = atol(optarg); break;
            default:  usage(argv[0]);
        }
    }

    if (!domain || !label || !package || !version || !source_dir)
        usage(argv[0]);
    if (validity_days < 1 || validity_days > VALIDITY_DAYS_MAX)
        die("--validity-days out of range (1..%d)", VALIDITY_DAYS_MAX);
    if (validate_label(label) != 0)
        die("invalid --label");
    if (validate_package(package) != 0)
        die("invalid --package");
    if (validate_version(version) != 0)
        die("invalid --version");
    if (validate_publisher(domain) != 0)
        die("invalid --domain (must be lowercase ASCII LDH)");

    if (!dry_run)
        die("non-dry-run not implemented in phase 1");

    /* Locate the TPM identity */
    const char *home = getenv("HOME");
    if (!home) die("HOME unset");
    char tpm_dir[2048];
    snprintf(tpm_dir, sizeof(tpm_dir), "%s/.TPM/%s-%s", home, domain, label);
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

    /* Walk + hash files */
    file_list files;
    fl_init(&files);
    walk_dir(src_abs, "", &files);
    if (files.n == 0) die("no files under %s", src_abs);
    qsort(files.items, files.n, sizeof(file_entry), fl_cmp);

    /* Reject duplicates after sort */
    for (size_t i = 1; i < files.n; i++) {
        if (strcmp(files.items[i-1].path, files.items[i].path) == 0)
            die("duplicate path after sort: %s", files.items[i].path);
    }

    /* Optional git_commit */
    char git_commit[80] = {0};
    int has_git = (git_head_commit(src_abs, git_commit) == 0);

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

    /* Emit final canonical leaf bytes: 0x02 prefix + canonical JSON */
    buf_t leaf; buf_init(&leaf);
    uint8_t prefix = FIPS_ENTRY_TYPE;
    buf_append(&leaf, &prefix, 1);
    buf_append(&leaf, final_bytes.data, final_bytes.len);

    FILE *out = stdout;
    if (out_path) {
        out = fopen(out_path, "wb");
        if (!out) die("cannot write %s: %s", out_path, strerror(errno));
    }
    if (fwrite(leaf.data, 1, leaf.len, out) != leaf.len)
        die("fwrite failed");
    if (out_path) fclose(out);

    fprintf(stderr,
        "fips-manifest-submit: built %zu-byte canonical leaf "
        "(%zu files, signature %zu B64-chars, cert_index %d)\n",
        leaf.len, files.n, (size_t)sig_b64_sz, pk.cert_index);

    buf_free(&signing_bytes); buf_free(&final_bytes); buf_free(&leaf);
    fl_free(&files);
    free_publisher_key(&pk);
    return 0;
}
