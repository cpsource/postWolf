/******************************************************************************
 * File:        mqc.c
 * Purpose:     Symmetric encrypt/decrypt pipe tool.
 *
 * Description:
 *   `mqc --encode | --decode` reads plaintext from stdin (or --file),
 *   derives an AES-256 key from a password via scrypt, seals with
 *   AES-256-GCM, and emits a single-line JSON envelope on stdout.
 *   Decode reverses the process.
 *
 *   JSON envelope:
 *     {"v":"mqc-1","domain":"<d>","kdf":"scrypt","N":32768,"r":8,"p":1,
 *      "salt":"<hex>","iv":"<hex>","ct":"<hex>","tag":"<hex>"}
 *
 *   Password sources (in order):
 *     1. --password PW on the command line
 *     2. cache at ~/.TPM/<domain>/mqc-password.pw  (unless --no-cache)
 *     3. interactive prompt via /dev/tty
 *     4. error
 *
 *   Domain resolution:
 *     1. --domain D on the command line
 *     2. readlink ~/.TPM/default → basename
 *
 *   --complex-password generates a shell-safe 16-char password, uses
 *   it, caches it, and prints it to stderr once for operator backup.
 *
 *   --file PATH reads from a file; without --encode/--decode the mode
 *   is autodetected from the file's first KB (valid JSON with
 *   "v":"mqc-1" → decode, else encode).
 *
 * Created:     2026-04-20
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <json-c/json.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#define MQC_VERSION       "mqc-1"       /* envelope/wire-format version */
#define MQC_TOOL_VERSION  "mqc/0.1.0"   /* producing-tool version string */
#define MQC_KDF_LOG2N     15           /* 2^15 = 32768 */
#define MQC_KDF_N         (1 << MQC_KDF_LOG2N)
#define MQC_KDF_R         8
#define MQC_KDF_P         1
#define MQC_AES_KEY_SZ    32           /* AES-256 */
#define MQC_GCM_IV_SZ     12
#define MQC_GCM_TAG_SZ    16
#define MQC_SALT_SZ       16
#define MQC_PW_MAX        512
#define MQC_COMPLEX_LEN   16

static const char MQC_PW_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_-.+=@";           /* 68 chars; shell-safe in all bash quoting contexts */
#define MQC_PW_ALPHABET_LEN 68

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static void to_hex(const uint8_t *in, int n, char *out)
{
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = h[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = h[in[i] & 0xf];
    }
    out[n * 2] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Returns number of bytes decoded, or -1 on parse error or overflow. */
static int from_hex(const char *in, uint8_t *out, int max_out)
{
    int n = (int)strlen(in);
    int i;
    if (n & 1) return -1;
    if (n / 2 > max_out) return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_nibble(in[i * 2]);
        int lo = hex_nibble(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

static char *read_all_fd(int fd, size_t *out_sz)
{
    size_t cap = 4096, sz = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (sz >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
        ssize_t n = read(fd, buf + sz, cap - sz);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); return NULL;
        }
        if (n == 0) break;
        sz += (size_t)n;
    }
    *out_sz = sz;
    return buf;
}

static int derive_key(const char *password, const uint8_t *salt, int salt_sz,
                      uint8_t *key_out)
{
    int ret = wc_scrypt(key_out,
                        (const byte *)password, (word32)strlen(password),
                        salt, salt_sz,
                        MQC_KDF_LOG2N, MQC_KDF_R, MQC_KDF_P,
                        MQC_AES_KEY_SZ);
    return ret == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* encode / decode                                                    */
/* ------------------------------------------------------------------ */

static int encode_blob(const char *domain, const char *password,
                       const uint8_t *pt, size_t pt_sz)
{
    uint8_t salt[MQC_SALT_SZ];
    uint8_t iv[MQC_GCM_IV_SZ];
    uint8_t key[MQC_AES_KEY_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t *ct = NULL;
    WC_RNG rng;
    int rng_ok = 0;
    Aes aes;
    int aes_ok = 0;
    int ret, rc = 1;
    char *salt_hex = NULL, *iv_hex = NULL, *tag_hex = NULL, *ct_hex = NULL;
    struct json_object *env = NULL;

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "mqc: RNG init failed\n");
        return 1;
    }
    rng_ok = 1;
    if (wc_RNG_GenerateBlock(&rng, salt, sizeof(salt)) != 0 ||
        wc_RNG_GenerateBlock(&rng, iv, sizeof(iv)) != 0) {
        fprintf(stderr, "mqc: RNG generate failed\n");
        goto done;
    }

    if (derive_key(password, salt, sizeof(salt), key) != 0) {
        fprintf(stderr, "mqc: scrypt key derivation failed\n");
        goto done;
    }

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "mqc: AES init failed\n");
        goto done;
    }
    aes_ok = 1;
    if (wc_AesGcmSetKey(&aes, key, MQC_AES_KEY_SZ) != 0) {
        fprintf(stderr, "mqc: AES SetKey failed\n");
        goto done;
    }

    ct = malloc(pt_sz ? pt_sz : 1);
    if (!ct) {
        fprintf(stderr, "mqc: out of memory\n");
        goto done;
    }
    ret = wc_AesGcmEncrypt(&aes, ct, pt, (word32)pt_sz,
                           iv, sizeof(iv),
                           tag, sizeof(tag),
                           NULL, 0);
    if (ret != 0) {
        fprintf(stderr, "mqc: AES-GCM encrypt failed (%d)\n", ret);
        goto done;
    }

    /* Hex-encode everything */
    salt_hex = malloc(sizeof(salt) * 2 + 1);
    iv_hex   = malloc(sizeof(iv)   * 2 + 1);
    tag_hex  = malloc(sizeof(tag)  * 2 + 1);
    ct_hex   = malloc(pt_sz * 2 + 1);
    if (!salt_hex || !iv_hex || !tag_hex || !ct_hex) {
        fprintf(stderr, "mqc: out of memory\n");
        goto done;
    }
    to_hex(salt, sizeof(salt), salt_hex);
    to_hex(iv,   sizeof(iv),   iv_hex);
    to_hex(tag,  sizeof(tag),  tag_hex);
    to_hex(ct,   (int)pt_sz,   ct_hex);

    /* ISO-8601 UTC timestamp "YYYY-MM-DDTHH:MM:SSZ" (20 chars + NUL) */
    char created[32];
    {
        time_t now = time(NULL);
        struct tm tm_utc;
        gmtime_r(&now, &tm_utc);
        strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    }

    env = json_object_new_object();
    json_object_object_add(env, "v",       json_object_new_string(MQC_VERSION));
    json_object_object_add(env, "tool",    json_object_new_string(MQC_TOOL_VERSION));
    json_object_object_add(env, "created", json_object_new_string(created));
    json_object_object_add(env, "domain",  json_object_new_string(domain));
    json_object_object_add(env, "kdf",     json_object_new_string("scrypt"));
    json_object_object_add(env, "N",      json_object_new_int(MQC_KDF_N));
    json_object_object_add(env, "r",      json_object_new_int(MQC_KDF_R));
    json_object_object_add(env, "p",      json_object_new_int(MQC_KDF_P));
    json_object_object_add(env, "salt",   json_object_new_string(salt_hex));
    json_object_object_add(env, "iv",     json_object_new_string(iv_hex));
    json_object_object_add(env, "ct",     json_object_new_string(ct_hex));
    json_object_object_add(env, "tag",    json_object_new_string(tag_hex));

    const char *json_str = json_object_to_json_string_ext(env,
        JSON_C_TO_STRING_PLAIN);
    fputs(json_str, stdout);
    fputc('\n', stdout);
    rc = 0;

done:
    if (env) json_object_put(env);
    free(salt_hex); free(iv_hex); free(tag_hex); free(ct_hex); free(ct);
    if (aes_ok) wc_AesFree(&aes);
    if (rng_ok) wc_FreeRng(&rng);
    /* Zeroise key material */
    memset(key, 0, sizeof(key));
    return rc;
}

static int decode_blob(const char *password, struct json_object *env,
                       char *domain_out, size_t domain_out_sz)
{
    struct json_object *val;
    const char *v, *kdf, *salt_hex, *iv_hex, *ct_hex, *tag_hex, *dom;
    uint8_t salt[MQC_SALT_SZ];
    uint8_t iv[MQC_GCM_IV_SZ];
    uint8_t tag[MQC_GCM_TAG_SZ];
    uint8_t key[MQC_AES_KEY_SZ];
    uint8_t *ct = NULL, *pt = NULL;
    int ct_sz;
    Aes aes;
    int aes_ok = 0;
    int ret, rc = 1;

    if (!json_object_object_get_ex(env, "v", &val) ||
        (v = json_object_get_string(val)) == NULL ||
        strcmp(v, MQC_VERSION) != 0) {
        fprintf(stderr, "mqc: unsupported mqc format version "
                "(expected '%s')\n", MQC_VERSION);
        return 1;
    }

    if (!json_object_object_get_ex(env, "kdf", &val) ||
        (kdf = json_object_get_string(val)) == NULL ||
        strcmp(kdf, "scrypt") != 0) {
        fprintf(stderr, "mqc: unsupported KDF (only 'scrypt' is supported)\n");
        return 1;
    }

    if (json_object_object_get_ex(env, "domain", &val) &&
        (dom = json_object_get_string(val)) != NULL &&
        domain_out && domain_out_sz > 0) {
        snprintf(domain_out, domain_out_sz, "%s", dom);
    }

    /* scrypt params — require exact match for now; could generalise
     * if we ever bump defaults.  Cheap sanity check against junk
     * input. */
    {
        int N = 0, r = 0, p = 0;
        if (json_object_object_get_ex(env, "N", &val))
            N = json_object_get_int(val);
        if (json_object_object_get_ex(env, "r", &val))
            r = json_object_get_int(val);
        if (json_object_object_get_ex(env, "p", &val))
            p = json_object_get_int(val);
        if (N != MQC_KDF_N || r != MQC_KDF_R || p != MQC_KDF_P) {
            fprintf(stderr, "mqc: non-default scrypt params not yet "
                    "supported (got N=%d r=%d p=%d; expected %d/%d/%d)\n",
                    N, r, p, MQC_KDF_N, MQC_KDF_R, MQC_KDF_P);
            return 1;
        }
    }

    if (!json_object_object_get_ex(env, "salt", &val) ||
        (salt_hex = json_object_get_string(val)) == NULL ||
        from_hex(salt_hex, salt, sizeof(salt)) != sizeof(salt)) {
        fprintf(stderr, "mqc: malformed 'salt' field\n");
        return 1;
    }
    if (!json_object_object_get_ex(env, "iv", &val) ||
        (iv_hex = json_object_get_string(val)) == NULL ||
        from_hex(iv_hex, iv, sizeof(iv)) != sizeof(iv)) {
        fprintf(stderr, "mqc: malformed 'iv' field\n");
        return 1;
    }
    if (!json_object_object_get_ex(env, "tag", &val) ||
        (tag_hex = json_object_get_string(val)) == NULL ||
        from_hex(tag_hex, tag, sizeof(tag)) != sizeof(tag)) {
        fprintf(stderr, "mqc: malformed 'tag' field\n");
        return 1;
    }
    if (!json_object_object_get_ex(env, "ct", &val) ||
        (ct_hex = json_object_get_string(val)) == NULL) {
        fprintf(stderr, "mqc: missing 'ct' field\n");
        return 1;
    }

    ct_sz = (int)strlen(ct_hex) / 2;
    if (ct_sz < 0 || (ct_sz > 0 && (ct = malloc(ct_sz)) == NULL)) {
        fprintf(stderr, "mqc: out of memory\n");
        return 1;
    }
    if (ct_sz > 0 && from_hex(ct_hex, ct, ct_sz) != ct_sz) {
        fprintf(stderr, "mqc: malformed 'ct' field\n");
        goto done;
    }

    if (derive_key(password, salt, sizeof(salt), key) != 0) {
        fprintf(stderr, "mqc: scrypt key derivation failed\n");
        goto done;
    }

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "mqc: AES init failed\n");
        goto done;
    }
    aes_ok = 1;
    if (wc_AesGcmSetKey(&aes, key, MQC_AES_KEY_SZ) != 0) {
        fprintf(stderr, "mqc: AES SetKey failed\n");
        goto done;
    }

    if (ct_sz > 0) {
        pt = malloc(ct_sz);
        if (!pt) {
            fprintf(stderr, "mqc: out of memory\n");
            goto done;
        }
    }
    ret = wc_AesGcmDecrypt(&aes, pt, ct, (word32)ct_sz,
                           iv, sizeof(iv),
                           tag, sizeof(tag),
                           NULL, 0);
    if (ret != 0) {
        fprintf(stderr, "mqc: authentication tag mismatch — wrong "
                "password or corrupted ciphertext\n");
        goto done;
    }

    if (ct_sz > 0 && fwrite(pt, 1, (size_t)ct_sz, stdout) != (size_t)ct_sz) {
        fprintf(stderr, "mqc: write error\n");
        goto done;
    }
    rc = 0;

done:
    if (aes_ok) wc_AesFree(&aes);
    memset(key, 0, sizeof(key));
    if (pt) { memset(pt, 0, ct_sz); free(pt); }
    free(ct);
    return rc;
}

/* ------------------------------------------------------------------ */
/* domain + cache                                                     */
/* ------------------------------------------------------------------ */

static int resolve_domain(const char *arg, char *out, size_t sz)
{
    const char *home;
    char default_path[PATH_MAX];
    char resolved[PATH_MAX];
    ssize_t rl;

    if (arg && arg[0]) {
        snprintf(out, sz, "%s", arg);
        return 0;
    }

    home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(default_path, sizeof(default_path), "%s/.TPM/default", home);
    rl = readlink(default_path, resolved, sizeof(resolved) - 1);
    if (rl > 0) {
        resolved[rl] = '\0';
        const char *base = strrchr(resolved, '/');
        base = base ? base + 1 : resolved;
        size_t blen = strlen(base);
        if (blen >= sz) blen = sz - 1;
        memcpy(out, base, blen);
        out[blen] = '\0';
        return 0;
    }
    fprintf(stderr, "mqc: no --domain passed and ~/.TPM/default does not "
            "resolve; pass --domain explicitly\n");
    return -1;
}

static int read_cache(const char *domain, char *pw_out, size_t sz)
{
    const char *home = getenv("HOME");
    char path[PATH_MAX];
    FILE *f;
    size_t got;

    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%s/.TPM/%s/mqc-password.pw", home, domain);
    f = fopen(path, "r");
    if (!f) return (errno == ENOENT) ? -1 : -2;
    got = fread(pw_out, 1, sz - 1, f);
    fclose(f);
    if (got == 0) return -2;
    pw_out[got] = '\0';
    /* strip trailing newline(s) */
    while (got > 0 && (pw_out[got - 1] == '\n' || pw_out[got - 1] == '\r')) {
        pw_out[--got] = '\0';
    }
    return 0;
}

static int write_cache(const char *domain, const char *pw)
{
    const char *home = getenv("HOME");
    char tpm_dir[PATH_MAX];
    char dom_dir[PATH_MAX];
    char path[PATH_MAX];
    FILE *f;

    if (!home) home = "/tmp";
    snprintf(tpm_dir, sizeof(tpm_dir), "%s/.TPM", home);
    snprintf(dom_dir, sizeof(dom_dir), "%s/.TPM/%s", home, domain);
    snprintf(path,    sizeof(path),    "%s/.TPM/%s/mqc-password.pw",
             home, domain);

    (void)mkdir(tpm_dir, 0700);
    (void)mkdir(dom_dir, 0700);
    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "mqc: cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        /* non-fatal */
    }
    fputs(pw, f);
    fputc('\n', f);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ~/.env master-password lookup                                      */
/* ------------------------------------------------------------------ */

/* Read ~/.env, find a line matching
 *   MQC_MASTER_PASSWORD=<value>
 *   MQC_MASTER_PASSWORD="value"
 *   MQC_MASTER_PASSWORD='value'
 * (whitespace tolerated around =, leading/trailing ws trimmed on the
 * unquoted form).  Lines beginning with # are ignored.  First match
 * wins.  Returns 0 on success, -1 on any miss.
 */
static int read_env_password(char *pw_out, size_t sz)
{
    const char *home = getenv("HOME");
    char path[PATH_MAX];
    FILE *f;
    char line[MQC_PW_MAX + 128];
    const char *KEY = "MQC_MASTER_PASSWORD";
    size_t KEYLEN = strlen(KEY);
    int found = 0;

    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%s/.env", home);
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "mqc: --env: cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        /* optional `export ` prefix */
        if (strncmp(p, "export", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
            p += 7;
            while (*p == ' ' || *p == '\t') p++;
        }
        if (strncmp(p, KEY, KEYLEN) != 0) continue;
        p += KEYLEN;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '=') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;

        /* Strip trailing newline */
        size_t llen = strlen(p);
        while (llen > 0 && (p[llen - 1] == '\n' || p[llen - 1] == '\r')) {
            p[--llen] = '\0';
        }
        /* Unquote if wrapped in matching '...' or "..." */
        if (llen >= 2 && ((p[0] == '"'  && p[llen - 1] == '"') ||
                          (p[0] == '\'' && p[llen - 1] == '\''))) {
            p[llen - 1] = '\0';
            p++;
            llen -= 2;
        } else {
            /* Unquoted: trim trailing whitespace */
            while (llen > 0 && (p[llen - 1] == ' ' || p[llen - 1] == '\t')) {
                p[--llen] = '\0';
            }
        }
        if (llen == 0) {
            fprintf(stderr, "mqc: --env: %s is empty in %s\n", KEY, path);
            fclose(f);
            return -1;
        }
        if (llen >= sz) {
            fprintf(stderr, "mqc: --env: %s too long (max %zu)\n",
                    KEY, sz - 1);
            fclose(f);
            return -1;
        }
        memcpy(pw_out, p, llen);
        pw_out[llen] = '\0';
        found = 1;
        break;
    }
    fclose(f);

    if (!found) {
        fprintf(stderr, "mqc: --env: %s not set in %s\n", KEY, path);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* complex-password + tty prompt                                      */
/* ------------------------------------------------------------------ */

static int generate_complex_password(char *buf, int len)
{
    WC_RNG rng;
    uint8_t raw[MQC_COMPLEX_LEN * 2];  /* over-generate, reject-sample */
    int i, outpos = 0;

    if (wc_InitRng(&rng) != 0) return -1;
    if (wc_RNG_GenerateBlock(&rng, raw, sizeof(raw)) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    wc_FreeRng(&rng);
    /* Rejection sampling: floor(256/68)*68 = 252.  Bytes < 252 are
     * unbiased; discard 252..255.  With 32 raw bytes we expect to
     * need ~16.2 of them — vanishingly small chance of exhaustion,
     * but handle it by just re-tapping RNG if we run out. */
    for (i = 0; i < (int)sizeof(raw) && outpos < len; i++) {
        if (raw[i] < 252) {
            buf[outpos++] = MQC_PW_ALPHABET[raw[i] % MQC_PW_ALPHABET_LEN];
        }
    }
    while (outpos < len) {
        uint8_t b;
        if (wc_InitRng(&rng) != 0) return -1;
        if (wc_RNG_GenerateBlock(&rng, &b, 1) != 0) {
            wc_FreeRng(&rng); return -1;
        }
        wc_FreeRng(&rng);
        if (b < 252) buf[outpos++] = MQC_PW_ALPHABET[b % MQC_PW_ALPHABET_LEN];
    }
    buf[len] = '\0';
    memset(raw, 0, sizeof(raw));
    return 0;
}

/* Prompt for a password from /dev/tty (so it works even when stdin
 * is consumed by a pipe).  Echo off during read. */
static int prompt_password(char *buf, size_t sz)
{
    FILE *tty_in, *tty_out;
    struct termios old_t, new_t;
    size_t len;

    tty_in  = fopen("/dev/tty", "r");
    tty_out = fopen("/dev/tty", "w");
    if (!tty_in || !tty_out) {
        fprintf(stderr, "mqc: no /dev/tty for password prompt "
                "(and no --password / no cache)\n");
        if (tty_in)  fclose(tty_in);
        if (tty_out) fclose(tty_out);
        return -1;
    }

    fputs("Password: ", tty_out);
    fflush(tty_out);

    if (tcgetattr(fileno(tty_in), &old_t) == 0) {
        new_t = old_t;
        new_t.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fileno(tty_in), TCSANOW, &new_t);
    }

    if (!fgets(buf, (int)sz, tty_in)) {
        tcsetattr(fileno(tty_in), TCSANOW, &old_t);
        fputc('\n', tty_out);
        fclose(tty_in); fclose(tty_out);
        return -1;
    }

    tcsetattr(fileno(tty_in), TCSANOW, &old_t);
    fputc('\n', tty_out);
    fclose(tty_in); fclose(tty_out);

    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    if (len == 0) {
        fprintf(stderr, "mqc: empty password rejected\n");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* --file autodetect                                                  */
/* ------------------------------------------------------------------ */

/* Returns 1 if the buffer looks like an mqc-1 JSON envelope, 0 else. */
static int buffer_is_mqc_envelope(const char *buf, size_t sz)
{
    struct json_object *env, *v;
    const char *s;
    int match = 0;

    if (sz == 0) return 0;
    env = json_tokener_parse(buf);
    if (!env) return 0;
    if (json_object_get_type(env) == json_type_object &&
        json_object_object_get_ex(env, "v", &v) &&
        (s = json_object_get_string(v)) != NULL &&
        strcmp(s, MQC_VERSION) == 0) {
        match = 1;
    }
    json_object_put(env);
    return match;
}

/* ------------------------------------------------------------------ */
/* usage + main                                                       */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Symmetric encrypt/decrypt pipe.  Derives an AES-256 key from a\n"
        "password via scrypt; seals with AES-256-GCM; emits JSON on encode.\n"
        "\n"
        "Usage:\n"
        "  cat file   | %s --encode [--password P | --complex-password]\n"
        "  cat cipher | %s --decode [--password P]\n"
        "               %s --file PATH [--password P]      (autodetect mode)\n"
        "\n"
        "  --encode              Encrypt stdin (or --file) to JSON envelope\n"
        "  --decode              Decrypt JSON envelope (stdin or --file)\n"
        "  --file PATH           Read from file; no --encode/--decode →\n"
        "                         autodetect (JSON envelope → decode, else encode)\n"
        "  --out PATH            Write output to PATH (mode 0600, truncates\n"
        "                         if exists) instead of stdout\n"
        "  --password PW         Password string.  Caches to\n"
        "                         ~/.TPM/<domain>/mqc-password.pw (mode 0600)\n"
        "  --complex-password    Generate a 16-char shell-safe password\n"
        "                         [A-Za-z0-9_-.+=@], print to stderr, cache, use\n"
        "  --env                 Read MQC_MASTER_PASSWORD from ~/.env and use\n"
        "                         it (does not read or write the cache)\n"
        "  --domain D            Domain for cache path (default: resolve\n"
        "                         ~/.TPM/default symlink)\n"
        "  --no-cache            Don't read or write the cache file\n"
        "  -h, --help            This help\n"
        "\n"
        "Password resolution order:\n"
        "  1. --password PW\n"
        "  2. --env (MQC_MASTER_PASSWORD in ~/.env)\n"
        "  3. cache at ~/.TPM/<domain>/mqc-password.pw (unless --no-cache)\n"
        "  4. interactive prompt via /dev/tty\n"
        "  5. error\n",
        prog, prog, prog);
}

int main(int argc, char **argv)
{
    int mode_encode = 0, mode_decode = 0;
    const char *password_arg = NULL;
    int complex_pw = 0;
    int use_env = 0;
    const char *domain_arg = NULL;
    const char *file_arg = NULL;
    const char *out_arg = NULL;
    int no_cache = 0;
    int i, rc = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        } else if (strcmp(argv[i], "--encode") == 0) {
            mode_encode = 1;
        } else if (strcmp(argv[i], "--decode") == 0) {
            mode_decode = 1;
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            password_arg = argv[++i];
        } else if (strcmp(argv[i], "--complex-password") == 0) {
            complex_pw = 1;
        } else if (strcmp(argv[i], "--env") == 0) {
            use_env = 1;
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            domain_arg = argv[++i];
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            file_arg = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_arg = argv[++i];
        } else if (strcmp(argv[i], "--no-cache") == 0) {
            no_cache = 1;
        } else {
            fprintf(stderr, "mqc: unknown argument '%s'\n", argv[i]);
            usage(argv[0]); return 2;
        }
    }

    if (mode_encode && mode_decode) {
        fprintf(stderr, "mqc: --encode and --decode are mutually exclusive\n");
        return 2;
    }
    if (complex_pw && mode_decode) {
        fprintf(stderr, "mqc: --complex-password is encode-only\n");
        return 2;
    }
    if (complex_pw && password_arg) {
        fprintf(stderr, "mqc: --complex-password and --password are "
                "mutually exclusive\n");
        return 2;
    }
    if (use_env && (complex_pw || password_arg)) {
        fprintf(stderr, "mqc: --env is mutually exclusive with "
                "--password and --complex-password\n");
        return 2;
    }

    /* --- Read input --- */
    char *input_buf = NULL;
    size_t input_sz = 0;
    if (file_arg) {
        int fd = open(file_arg, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "mqc: cannot open %s: %s\n",
                    file_arg, strerror(errno));
            return 1;
        }
        input_buf = read_all_fd(fd, &input_sz);
        close(fd);
        if (!input_buf) {
            fprintf(stderr, "mqc: read error on %s\n", file_arg);
            return 1;
        }
        /* Autodetect mode if the operator didn't force one */
        if (!mode_encode && !mode_decode) {
            if (buffer_is_mqc_envelope(input_buf, input_sz)) {
                mode_decode = 1;
            } else {
                mode_encode = 1;
            }
        }
    } else {
        /* Must have explicit mode when reading stdin */
        if (!mode_encode && !mode_decode) {
            fprintf(stderr, "mqc: pass --encode or --decode (or use "
                    "--file PATH for autodetect)\n");
            usage(argv[0]); return 2;
        }
        input_buf = read_all_fd(0, &input_sz);
        if (!input_buf) {
            fprintf(stderr, "mqc: read error on stdin\n");
            return 1;
        }
    }

    /* --- Pre-parse envelope (decode only) to recover domain --- */
    char embedded_domain[256] = {0};
    struct json_object *env = NULL;
    if (mode_decode) {
        env = json_tokener_parse(input_buf);
        if (!env) {
            fprintf(stderr, "mqc: input is not valid JSON\n");
            free(input_buf); return 1;
        }
        {
            struct json_object *v;
            if (json_object_object_get_ex(env, "domain", &v)) {
                const char *s = json_object_get_string(v);
                if (s) snprintf(embedded_domain, sizeof(embedded_domain),
                                "%s", s);
            }
        }
    }

    /* --- Resolve domain --- */
    char domain[256];
    if (domain_arg) {
        snprintf(domain, sizeof(domain), "%s", domain_arg);
    } else if (mode_decode && embedded_domain[0]) {
        snprintf(domain, sizeof(domain), "%s", embedded_domain);
    } else if (resolve_domain(NULL, domain, sizeof(domain)) != 0) {
        if (env) json_object_put(env);
        free(input_buf); return 1;
    }

    /* --- Resolve password --- */
    char password[MQC_PW_MAX];
    password[0] = '\0';
    int pw_from_arg = 0;
    int pw_generated = 0;

    if (complex_pw) {
        if (generate_complex_password(password, MQC_COMPLEX_LEN) != 0) {
            fprintf(stderr, "mqc: complex-password generation failed\n");
            goto cleanup;
        }
        fprintf(stderr, "Generated password: %s\n", password);
        fprintf(stderr, "(cached at ~/.TPM/%s/mqc-password.pw; save this "
                "for offline backup)\n", domain);
        pw_generated = 1;
    } else if (password_arg) {
        snprintf(password, sizeof(password), "%s", password_arg);
        pw_from_arg = 1;
    } else if (use_env) {
        if (read_env_password(password, sizeof(password)) != 0) {
            goto cleanup;
        }
    } else if (!no_cache && read_cache(domain, password, sizeof(password)) == 0) {
        /* cache hit */
    } else {
        if (prompt_password(password, sizeof(password)) != 0) {
            goto cleanup;
        }
    }

    if (password[0] == '\0') {
        fprintf(stderr, "mqc: no password available\n");
        goto cleanup;
    }

    /* --- Cache write (encode side, or when operator supplied one) --- */
    if (!no_cache && (pw_from_arg || pw_generated)) {
        (void)write_cache(domain, password);
    }

    /* --- Redirect stdout to --out file if requested --- */
    if (out_arg) {
        int outfd = open(out_arg, O_WRONLY | O_CREAT | O_TRUNC,
                         S_IRUSR | S_IWUSR);
        if (outfd < 0) {
            fprintf(stderr, "mqc: cannot open %s for writing: %s\n",
                    out_arg, strerror(errno));
            goto cleanup;
        }
        fflush(stdout);
        if (dup2(outfd, STDOUT_FILENO) < 0) {
            fprintf(stderr, "mqc: dup2 onto stdout failed: %s\n",
                    strerror(errno));
            close(outfd);
            goto cleanup;
        }
        close(outfd);
    }

    /* --- Dispatch --- */
    if (mode_encode) {
        rc = encode_blob(domain, password,
                         (const uint8_t *)input_buf, input_sz);
    } else {
        rc = decode_blob(password, env, NULL, 0);
    }
    fflush(stdout);

cleanup:
    memset(password, 0, sizeof(password));
    if (env) json_object_put(env);
    free(input_buf);
    return rc;
}
