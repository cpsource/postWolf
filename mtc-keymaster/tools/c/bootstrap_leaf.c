/******************************************************************************
 * File:        bootstrap_leaf.c
 * Purpose:     Client-side DH bootstrap tool for leaf enrollment.
 *
 * Description:
 *   Connects to the CA server's DH bootstrap port, performs X25519 key
 *   exchange, sends an encrypted enrollment request, receives the
 *   certificate, and stores it in ~/.TPM/<subject>/.
 *
 *   Usage:
 *     bootstrap_leaf --server HOST:PORT --domain DOMAIN \
 *                    --public-key FILE --private-key FILE \
 *                    --nonce NONCE [--tpm-dir DIR] [--dry-run]
 *
 * Dependencies:
 *   mtc_crypt.h / mtc_crypt.c       (AES encryption)
 *   wolfssl/wolfcrypt/curve25519.h   (X25519 key exchange)
 *   wolfssl/wolfcrypt/hmac.h         (HKDF key derivation)
 *   wolfssl/wolfcrypt/random.h       (RNG)
 *   json-c/json.h                    (JSON parsing)
 *
 * Created:     2026-04-14
 ******************************************************************************/

#include "mtc_crypt.h"
#include "mtc_domain.h"
#include "../../read-config/read-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/dilithium.h>     /* P0 #9b: ML-DSA-87 verify */
#include <wolfssl/wolfcrypt/asn_public.h>    /* P0 #9b: wc_PubKeyPemToDer */
#include <wolfssl/wolfcrypt/sha256.h>        /* P0 #9b: wc_Sha256Hash */

#include <json-c/json.h>

/* P0 / TODO #9b leaf branch — must match the server-side label
 * in mtc_bootstrap.c.  The cosigner signs the canonical JSON of
 * the bootstrap response (with ca_cosigner_pem set, ca_response_sig
 * absent) under this ctx.  Any divergence between client and
 * server here breaks every fresh enrollment — handle as a
 * single-deployment flag-day per CLAUDE.md. */
#define MTC_BOOTSTRAP_LABEL      "mtc-bootstrap/v1\n\x00"
#define MTC_BOOTSTRAP_LABEL_LEN  16

/* P0 / TODO #63 — DH-transcript signature label.  Must match
 * server-side MTC_BOOTSTRAP_DH_LABEL in mtc_bootstrap.c. */
#define MTC_BOOTSTRAP_DH_LABEL      "mtc-boot-dh/v1\n\x00"
#define MTC_BOOTSTRAP_DH_LABEL_LEN  16

#define HKDF_INFO        "mtc-dh-bootstrap"
/* TODO #62: AES-256-GCM AEAD; HKDF produces 64 bytes (c2s||s2c). */
#define SALT_SZ          16
#define AES_KEY_SZ       32                  /* AES-256 */
#define AES_KEYS_TOTAL   (AES_KEY_SZ * 2)    /* c2s||s2c   */
#define MAX_MSG          65536
#define DEFAULT_TPM_DIR  ".TPM"

static int g_trial_run = 0;
static int g_verbose   = 0;

/******************************************************************************
 * Logging helpers
 ******************************************************************************/
#define LOG(fmt, ...) \
    fprintf(stdout, "[bootstrap] " fmt "\n", ##__VA_ARGS__)

#define LOG_V(fmt, ...) \
    do { if (g_verbose) fprintf(stdout, "[bootstrap] " fmt "\n", ##__VA_ARGS__); } while(0)

/******************************************************************************
 * Function:    secure_zero  (static)
 ******************************************************************************/
static void secure_zero(void *buf, unsigned int len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    unsigned int i;
    for (i = 0; i < len; i++)
        p[i] = 0;
}

/******************************************************************************
 * Function:    to_hex  (static)
 ******************************************************************************/
static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

/******************************************************************************
 * Function:    hex_to_bytes  (static)
 ******************************************************************************/
static int hex_to_bytes(const char *hex, uint8_t *out, int out_sz)
{
    int len = (int)strlen(hex);
    int i;
    if (len % 2 != 0 || len / 2 > out_sz)
        return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1)
            return -1;
        out[i] = (uint8_t)b;
    }
    return len / 2;
}

/******************************************************************************
 * Function:    read_file  (static)
 *
 * Description:
 *   Read an entire file into a malloc'd buffer.  Returns length or -1.
 ******************************************************************************/
static int read_file(const char *path, char **out)
{
    FILE *fp;
    long sz;
    char *buf;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[sz] = '\0';
    fclose(fp);

    *out = buf;
    return (int)sz;
}

/******************************************************************************
 * Function:    write_all  (static)
 ******************************************************************************/
static int write_all(int fd, const unsigned char *buf, unsigned int len)
{
    unsigned int sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += (unsigned int)n;
    }
    return 0;
}

/******************************************************************************
 * Function:    read_all  (static)
 ******************************************************************************/
static int read_all(int fd, unsigned char *buf, unsigned int len)
{
    unsigned int got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0)
            return -1;
        got += (unsigned int)n;
    }
    return 0;
}

/******************************************************************************
 * Function:    read_plaintext_json  (static)
 ******************************************************************************/
static int read_plaintext_json(int fd, char *buf, int bufsz)
{
    int pos = 0, depth = 0, started = 0;

    while (pos < bufsz - 1) {
        ssize_t n = read(fd, buf + pos, 1);
        if (n <= 0)
            return -1;
        if (buf[pos] == '{') { depth++; started = 1; }
        else if (buf[pos] == '}') { depth--; }
        pos++;
        if (started && depth == 0) {
            buf[pos] = '\0';
            return pos;
        }
    }
    return -1;
}

/******************************************************************************
 * Function:    send_length_prefixed  (static)
 ******************************************************************************/
static int send_length_prefixed(int fd, const unsigned char *data,
                                unsigned int len)
{
    uint32_t net_len = htonl(len);
    if (write_all(fd, (unsigned char *)&net_len, 4) != 0)
        return -1;
    return write_all(fd, data, len);
}

/******************************************************************************
 * Function:    recv_length_prefixed  (static)
 ******************************************************************************/
static int recv_length_prefixed(int fd, unsigned char *buf, int bufsz)
{
    uint32_t net_len, len;
    if (read_all(fd, (unsigned char *)&net_len, 4) != 0)
        return -1;
    len = ntohl(net_len);
    if (len > (uint32_t)bufsz)
        return -1;
    if (read_all(fd, buf, len) != 0)
        return -1;
    return (int)len;
}

/******************************************************************************
 * Function:    save_to_tpm  (static)
 *
 * Description:
 *   Save the enrollment result to ~/.TPM/<subject>/.
 *   Creates the directory if needed.  Writes certificate.json,
 *   index, public_key.pem, and copies private_key.pem.
 ******************************************************************************/
#define MTC_LABEL_MAX 64
/* Client-side label validator; see plan TODO #26.  Charset
 * [A-Za-z0-9._-], 1..64 chars.  Empty and NULL are invalid. */
static int sanitize_label(const char *in)
{
    size_t len, i;
    if (!in) return -1;
    len = strlen(in);
    if (len < 1 || len > MTC_LABEL_MAX) return -1;
    for (i = 0; i < len; i++) {
        char c = in[i];
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) return -1;
    }
    return 0;
}

static int save_to_tpm(const char *tpm_dir, const char *subject,
                       const char *label, int make_default,
                       const char *cert_json, int cert_index,
                       const char *pub_key_path, const char *priv_key_path,
                       const char *ca_cosigner_pem)
{
    char dir_path[256];
    char file_path[256 + 32];  /* dir_path + longest filename */
    char *subj_safe;
    FILE *fp;
    char *key_data;
    int key_len, n;
    unsigned int i;

    /* Convert subject to filesystem-safe name: replace ':' with '_' */
    subj_safe = strdup(subject);
    for (i = 0; i < strlen(subj_safe); i++) {
        if (subj_safe[i] == ':')
            subj_safe[i] = '_';
    }

    /* Label is already sanitized by the caller (see handle_cert_resp).
     * Format the dir as <subject>-<label> when label is set, else just
     * <subject> (legacy behavior). */
    if (label && label[0])
        n = snprintf(dir_path, sizeof(dir_path), "%s/%s-%s",
                     tpm_dir, subj_safe, label);
    else
        n = snprintf(dir_path, sizeof(dir_path), "%s/%s",
                     tpm_dir, subj_safe);
    if (n < 0 || n >= (int)sizeof(dir_path)) {
        LOG("ERROR: TPM path too long");
        free(subj_safe);
        return -1;
    }

    /* Create directory */
    if (mkdir(dir_path, 0700) < 0 && errno != EEXIST) {
        LOG("ERROR: cannot create %s: %s", dir_path, strerror(errno));
        free(subj_safe);
        return -1;
    }

    /* Write certificate.json */
    snprintf(file_path, sizeof(file_path), "%s/certificate.json", dir_path);
    fp = fopen(file_path, "w");
    if (!fp) {
        LOG("ERROR: cannot write %s: %s", file_path, strerror(errno));
        free(subj_safe);
        return -1;
    }
    fprintf(fp, "%s\n", cert_json);
    fclose(fp);
    LOG("  wrote %s", file_path);

    /* Write index */
    snprintf(file_path, sizeof(file_path), "%s/index", dir_path);
    fp = fopen(file_path, "w");
    if (fp) {
        fprintf(fp, "%d\n", cert_index);
        fclose(fp);
        LOG("  wrote %s", file_path);
    }

    /* Copy public key */
    key_len = read_file(pub_key_path, &key_data);
    if (key_len > 0) {
        snprintf(file_path, sizeof(file_path), "%s/public_key.pem", dir_path);
        fp = fopen(file_path, "w");
        if (fp) {
            fwrite(key_data, 1, (size_t)key_len, fp);
            fclose(fp);
            LOG("  wrote %s", file_path);
        }
        free(key_data);
    }

    /* Copy private key (restricted permissions) */
    key_len = read_file(priv_key_path, &key_data);
    if (key_len > 0) {
        snprintf(file_path, sizeof(file_path), "%s/private_key.pem", dir_path);
        fp = fopen(file_path, "w");
        if (fp) {
            fchmod(fileno(fp), 0600);
            fwrite(key_data, 1, (size_t)key_len, fp);
            fclose(fp);
            LOG("  wrote %s", file_path);
        }
        secure_zero(key_data, (unsigned int)key_len);
        free(key_data);
    }

    /* P0 / TODO #9b leaf branch — pin the now-authenticated CA
     * cosigner PEM into this leaf's TPM dir so future MQC handshakes
     * (mqc_load_ca_pubkey) take this per-leaf path instead of TOFUing
     * over port 8445.  Verification of fingerprint + signature happens
     * before save_to_tpm is called; by the time the PEM lands here
     * we've already proven (a) sha256(DER(SPKI)) matches the operator-
     * pasted fingerprint and (b) the bootstrap response was signed
     * under this PEM's private key. */
    if (ca_cosigner_pem && ca_cosigner_pem[0]) {
        snprintf(file_path, sizeof(file_path),
                 "%s/ca-cosigner.pem", dir_path);
        fp = fopen(file_path, "w");
        if (fp) {
            fputs(ca_cosigner_pem, fp);
            /* Ensure trailing newline so readers that strstr for
             * "-----END" tolerate either form. */
            size_t pem_len = strlen(ca_cosigner_pem);
            if (pem_len == 0 || ca_cosigner_pem[pem_len - 1] != '\n')
                fputc('\n', fp);
            fclose(fp);
            LOG("  wrote %s", file_path);
        } else {
            LOG("WARN: could not write %s: %s", file_path,
                strerror(errno));
        }
    }

    /* ~/.TPM/default symlink policy (plan TODO #26 Phases D + G):
     *   default missing → always create it pointing at this identity
     *   default present + !make_default → leave alone (operator's pin)
     *   default present +  make_default → atomic re-point via
     *     rename-over-symlink so concurrent readers never see a torn
     *     state.  Relative target so the whole ~/.TPM tree is movable.
     *   Failure is a warning, not fatal. */
    {
        char default_path[PATH_MAX];
        char rel_target[256];
        struct stat st;
        int default_exists;
        if (label && label[0])
            snprintf(rel_target, sizeof(rel_target), "%s-%s",
                     subj_safe, label);
        else
            snprintf(rel_target, sizeof(rel_target), "%s", subj_safe);
        snprintf(default_path, sizeof(default_path), "%s/default", tpm_dir);
        default_exists = (lstat(default_path, &st) == 0);

        if (!default_exists) {
            if (symlink(rel_target, default_path) != 0)
                LOG("WARN: could not create %s: %s",
                    default_path, strerror(errno));
            else
                LOG("  set default -> %s", rel_target);
        } else if (make_default) {
            char tmp_path[PATH_MAX];
            snprintf(tmp_path, sizeof(tmp_path), "%s/.default.tmp.%d",
                     tpm_dir, (int)getpid());
            unlink(tmp_path);  /* harmless if absent */
            if (symlink(rel_target, tmp_path) != 0) {
                LOG("WARN: could not stage new default: %s",
                    strerror(errno));
            } else if (rename(tmp_path, default_path) != 0) {
                LOG("WARN: could not atomically re-point default: %s",
                    strerror(errno));
                unlink(tmp_path);
            } else {
                LOG("  re-pointed default -> %s (was pinned)", rel_target);
            }
        }
    }

    free(subj_safe);
    return 0;
}

/******************************************************************************
 * Function:    usage
 ******************************************************************************/
static void usage(const char *prog)
{
    printf("DH Bootstrap Leaf Enrollment Tool\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --server HOST:PORT   CA server DH bootstrap endpoint\n");
    printf("  --domain DOMAIN      Domain/subject (must match issue_leaf_nonce --domain)\n");
    printf("  --public-key FILE    Path to leaf public key PEM\n");
    printf("  --private-key FILE   Path to leaf private key PEM\n");
    printf("  --nonce NONCE        Enrollment nonce (64-char hex)\n");
    printf("  --cosigner-fp FP     SHA-256 of DER(SPKI) of the CA's cosigner\n");
    printf("                       pubkey (sha256:<hex> or raw 64-char hex).\n");
    printf("                       Required.  Issued by the CA operator\n");
    printf("                       alongside --nonce; printed by\n");
    printf("                       issue_leaf_nonce as 'Cosigner-fp:'.\n");
    printf("                       The bootstrap response is rejected if its\n");
    printf("                       embedded ca_cosigner_pem doesn't match.\n");
    printf("  --key-algorithm ALG  Key algorithm (default: ML-DSA-87)\n");
    printf("  --validity-days N    Certificate validity (default: 90)\n");
    printf("  --tpm-dir DIR        TPM storage directory (default: ~/.TPM)\n");
    printf("  --make-default       Re-point ~/.TPM/default at this identity\n");
    printf("                       even if it already exists (default: create\n");
    printf("                       only if missing, preserve existing pin).\n");
    printf("  --dry-run            Do everything but don't save to TPM\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help\n");
}

/******************************************************************************
 * Function:    main
 ******************************************************************************/
int main(int argc, char *argv[])
{
    /* Command-line arguments */
    const char *server_arg = NULL;
    const char *subject = NULL;
    const char *pub_key_path = NULL;
    const char *priv_key_path = NULL;
    const char *nonce = NULL;
    const char *cosigner_fp_arg = NULL;   /* P0 #9b */
    const char *key_algo = "ML-DSA-87";
    int validity_days = 90;
    const char *tpm_dir_arg = NULL;
    int make_default = 0;

    /* Parsed server host:port */
    char server_host[256];
    int server_port = 0;

    /* TPM directory */
    char tpm_dir[512];

    /* DH exchange state */
    curve25519_key my_key, server_key;
    WC_RNG rng;
    uint8_t shared_secret[CURVE25519_KEYSIZE];
    word32 shared_sz = CURVE25519_KEYSIZE;
    uint8_t my_pub[CURVE25519_KEYSIZE];
    word32 my_pub_sz = CURVE25519_KEYSIZE;
    uint8_t server_pub[CURVE25519_KEYSIZE];
    uint8_t salt[SALT_SZ];
    uint8_t aes_keys[AES_KEYS_TOTAL];   /* c2s||s2c */

    /* I/O */
    int sock_fd = -1;
    char json_buf[MAX_MSG];
    unsigned char enc_buf[MAX_MSG];
    unsigned char dec_buf[MAX_MSG];
    unsigned int enc_len, dec_len;

    /* Public key PEM content */
    char *pub_key_pem = NULL;

    MtcCryptCtx *crypt_ctx = NULL;
    int i, ret;
    int rng_ok = 0, my_key_ok = 0, server_key_ok = 0;
    int exit_code = 1;

    /* --- Parse arguments --- */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc)
            server_arg = argv[++i];
        else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
            subject = argv[++i];
        else if (strcmp(argv[i], "--public-key") == 0 && i + 1 < argc)
            pub_key_path = argv[++i];
        else if (strcmp(argv[i], "--private-key") == 0 && i + 1 < argc)
            priv_key_path = argv[++i];
        else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc)
            nonce = argv[++i];
        else if (strcmp(argv[i], "--cosigner-fp") == 0 && i + 1 < argc)
            cosigner_fp_arg = argv[++i];
        else if (strcmp(argv[i], "--key-algorithm") == 0 && i + 1 < argc)
            key_algo = argv[++i];
        else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc)
            validity_days = atoi(argv[++i]);
        else if (strcmp(argv[i], "--tpm-dir") == 0 && i + 1 < argc)
            tpm_dir_arg = argv[++i];
        else if (strcmp(argv[i], "--make-default") == 0)
            make_default = 1;
        else if (strcmp(argv[i], "--dry-run") == 0)
            g_trial_run = 1;
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!subject) {
        fprintf(stderr, "Error: --domain is required\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Canonicalize early — same gate the server applies, just
     * before the network round-trip.  README-issues.md issue #6. */
    {
        static char domain_canon[256];
        if (mtc_canonicalize_domain(subject, domain_canon,
                                    sizeof(domain_canon)) != 0) {
            fprintf(stderr,
                "Error: --domain '%s' is not a valid lowercase ASCII "
                "LDH name (no wildcards, no underscore-prefixed labels, "
                "no IDN — punycode to xn--... yourself).\n", subject);
            return 1;
        }
        subject = domain_canon;
    }

    /* Default --server: CLI > [global] url-bootstrap > factsorlie.com:8445. */
    if (!server_arg) {
        char *cfg = read_config_url("global/url-bootstrap");
        server_arg = cfg ? cfg : "factsorlie.com:8445";
    }

    /* Default paths from ~/.mtc-ca-data/<domain>/ if not specified */
    {
        static char def_pub[512], def_priv[512], def_nonce_path[512];
        static char nonce_buf[256];
        const char *home = getenv("HOME");
        if (!home) home = ".";

        if (!pub_key_path) {
            snprintf(def_pub, sizeof(def_pub),
                     "%s/.mtc-ca-data/%s/public_key.pem", home, subject);
            pub_key_path = def_pub;
        }
        if (!priv_key_path) {
            snprintf(def_priv, sizeof(def_priv),
                     "%s/.mtc-ca-data/%s/private_key.pem", home, subject);
            priv_key_path = def_priv;
        }
        /* Persistent buffer for cosigner_fp parsed from nonce.txt
         * (visible to the verify block far below).  Sized to hold a
         * "sha256:" prefix + 64 hex chars + NUL with comfortable
         * margin; the further-down --cosigner-fp canonicalizer
         * length-checks before use. */
        static char nonce_txt_cosigner_fp[256];
        nonce_txt_cosigner_fp[0] = '\0';

        if (!nonce || !cosigner_fp_arg) {
            FILE *nf;
            snprintf(def_nonce_path, sizeof(def_nonce_path),
                     "%s/.mtc-ca-data/%s/nonce.txt", home, subject);
            nf = fopen(def_nonce_path, "r");
            if (nf) {
                char line[256];
                int line_no = 0;
                while (fgets(line, sizeof(line), nf)) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    line_no++;
                    /* First line is the nonce hex (matches the file
                     * format issue_leaf_nonce writes). */
                    if (line_no == 1 && !nonce && line[0]) {
                        snprintf(nonce_buf, sizeof(nonce_buf), "%s", line);
                        nonce = nonce_buf;
                        continue;
                    }
                    /* P0 #9b: cosigner_fp=sha256:<hex> on a later
                     * line (issue_leaf_nonce emits this when the
                     * server returns ca_cosigner_fp). */
                    if (!cosigner_fp_arg &&
                        strncmp(line, "cosigner_fp=", 12) == 0) {
                        snprintf(nonce_txt_cosigner_fp,
                                 sizeof(nonce_txt_cosigner_fp),
                                 "%s", line + 12);
                        cosigner_fp_arg = nonce_txt_cosigner_fp;
                    }
                }
                fclose(nf);
            }
            if (!nonce) {
                fprintf(stderr, "Error: no --nonce given and no nonce.txt "
                        "found at %s\n"
                        "Run issue_leaf_nonce --domain %s first\n",
                        def_nonce_path, subject);
                return 1;
            }
        }
    }

    /* P0 / TODO #9b leaf branch — require --cosigner-fp.  No
     * --no-pin escape hatch: pin or fail.  Accept either bare
     * 64-char hex or "sha256:<hex>"; canonicalize to bare hex
     * for the comparison further down. */
    {
        static char cosigner_fp_canon[65];
        const char *p = cosigner_fp_arg;
        if (!p) {
            fprintf(stderr,
                    "Error: --cosigner-fp is required (issued by the\n"
                    "       CA operator alongside --nonce; printed by\n"
                    "       issue_leaf_nonce as 'Cosigner-fp:' and\n"
                    "       persisted as cosigner_fp=... in nonce.txt).\n"
                    "       This pin closes the first-contact MitM hole\n"
                    "       on port 8445; there is no --no-pin override.\n");
            return 1;
        }
        if (strncmp(p, "sha256:", 7) == 0) p += 7;
        if (strlen(p) != 64) {
            fprintf(stderr,
                    "Error: --cosigner-fp must be 64 hex chars "
                    "(optionally prefixed with 'sha256:').  Got %zu chars.\n",
                    strlen(p));
            return 1;
        }
        for (int hi = 0; hi < 64; hi++) {
            char c = p[hi];
            char lc = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
            if (!((lc >= '0' && lc <= '9') || (lc >= 'a' && lc <= 'f'))) {
                fprintf(stderr, "Error: --cosigner-fp contains a "
                                "non-hex character at position %d ('%c')\n",
                                hi, c);
                return 1;
            }
            cosigner_fp_canon[hi] = lc;
        }
        cosigner_fp_canon[64] = '\0';
        cosigner_fp_arg = cosigner_fp_canon;
    }

    /* Parse host:port */
    {
        char *colon = strrchr(server_arg, ':');
        if (!colon) {
            fprintf(stderr, "Error: --server must be HOST:PORT\n");
            return 1;
        }
        memset(server_host, 0, sizeof(server_host));
        memcpy(server_host, server_arg,
               (size_t)(colon - server_arg) < sizeof(server_host) - 1
                   ? (size_t)(colon - server_arg) : sizeof(server_host) - 1);
        server_port = atoi(colon + 1);
        if (server_port <= 0) {
            fprintf(stderr, "Error: invalid port in --server\n");
            return 1;
        }
    }

    /* Set TPM directory */
    if (tpm_dir_arg) {
        snprintf(tpm_dir, sizeof(tpm_dir), "%s", tpm_dir_arg);
    } else {
        const char *home = getenv("HOME");
        if (!home) home = ".";
        snprintf(tpm_dir, sizeof(tpm_dir), "%s/%s", home, DEFAULT_TPM_DIR);
    }

    /* Read public key PEM */
    if (read_file(pub_key_path, &pub_key_pem) <= 0) {
        fprintf(stderr, "Error: cannot read public key file: %s\n", pub_key_path);
        return 1;
    }

    if (g_trial_run)
        LOG("*** DRY RUN — will not save to TPM ***");

    LOG("server:      %s:%d", server_host, server_port);
    LOG("subject:     %s", subject);
    LOG("public key:  %s", pub_key_path);
    LOG("nonce:       %.16s...", nonce);
    LOG("algorithm:   %s", key_algo);
    LOG("validity:    %d days", validity_days);
    LOG("TPM dir:     %s", tpm_dir);

    /* --- Initialize wolfSSL RNG --- */
    wolfSSL_Init();

    if (wc_InitRng(&rng) != 0) {
        LOG("ERROR: RNG init failed");
        goto done;
    }
    rng_ok = 1;

    /* --- Step 3: Connect to DH port --- */
    LOG("connecting to %s:%d ...", server_host, server_port);
    {
        struct addrinfo hints, *res, *rp;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", server_port);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(server_host, port_str, &hints, &res) != 0) {
            LOG("ERROR: cannot resolve %s", server_host);
            goto done;
        }

        sock_fd = -1;
        for (rp = res; rp != NULL; rp = rp->ai_next) {
            sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sock_fd < 0) continue;
            if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(sock_fd);
            sock_fd = -1;
        }
        freeaddrinfo(res);

        if (sock_fd < 0) {
            LOG("ERROR: cannot connect to %s:%d", server_host, server_port);
            goto done;
        }
    }
    LOG("connected");

    /* --- Generate X25519 ephemeral keypair --- */
    if (wc_curve25519_init(&my_key) != 0) {
        LOG("ERROR: X25519 key init failed");
        goto done;
    }
    my_key_ok = 1;

    if (wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &my_key) != 0) {
        LOG("ERROR: X25519 key generation failed");
        goto done;
    }

    if (wc_curve25519_export_public(&my_key, my_pub, &my_pub_sz) != 0) {
        LOG("ERROR: X25519 export public failed");
        goto done;
    }

    /* --- Send DH public key (plaintext JSON) --- */
    {
        char pub_hex[CURVE25519_KEYSIZE * 2 + 1];
        int json_len;
        to_hex(my_pub, CURVE25519_KEYSIZE, pub_hex);
        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"dh_public_key\":\"%s\"}", pub_hex);
        LOG_V("sending DH public key (%d bytes)", json_len);
        if (write_all(sock_fd, (unsigned char *)json_buf,
                      (unsigned int)json_len) != 0) {
            LOG("ERROR: failed to send DH request");
            goto done;
        }
    }
    LOG("DH public key sent");

    /* --- Receive server DH response (plaintext JSON) --- */
    ret = read_plaintext_json(sock_fd, json_buf, sizeof(json_buf));
    if (ret <= 0) {
        LOG("ERROR: failed to receive DH response");
        goto done;
    }
    LOG_V("received DH response (%d bytes)", ret);

    {
        struct json_object *resp, *val;
        const char *hex_str;
        uint8_t pop_nonce[32];
        int     have_pop_nonce = 0;
        const char *resp_cosigner_pem = NULL;
        const char *resp_transcript_sig_hex = NULL;
        int  resp_proto_version = 0;

        resp = json_tokener_parse(json_buf);
        if (!resp) {
            LOG("ERROR: invalid DH response JSON");
            goto done;
        }

        if (!json_object_object_get_ex(resp, "dh_public_key", &val)) {
            LOG("ERROR: missing dh_public_key in response");
            json_object_put(resp);
            goto done;
        }
        hex_str = json_object_get_string(val);
        if (hex_to_bytes(hex_str, server_pub, CURVE25519_KEYSIZE)
                != CURVE25519_KEYSIZE) {
            LOG("ERROR: invalid server DH public key");
            json_object_put(resp);
            goto done;
        }

        if (!json_object_object_get_ex(resp, "salt", &val)) {
            LOG("ERROR: missing salt in response");
            json_object_put(resp);
            goto done;
        }
        hex_str = json_object_get_string(val);
        if (hex_to_bytes(hex_str, salt, SALT_SZ) != SALT_SZ) {
            LOG("ERROR: invalid salt");
            json_object_put(resp);
            goto done;
        }

        /* P0 / TODO #63 — DH-transcript signature.  Required fields:
         * pop_nonce (32 bytes), protocol_version (1), ca_cosigner_pem,
         * transcript_sig (ML-DSA-87, hex).  Refuse to derive any AEAD
         * keys until both the fingerprint and the signature verify. */
        if (json_object_object_get_ex(resp, "pop_nonce", &val)) {
            hex_str = json_object_get_string(val);
            if (hex_to_bytes(hex_str, pop_nonce, sizeof(pop_nonce))
                    == (int)sizeof(pop_nonce))
                have_pop_nonce = 1;
        }
        if (!have_pop_nonce) {
            LOG("ERROR: step-2 missing pop_nonce — server is older "
                "than the P0 #63 cutover; rebuild + redeploy");
            json_object_put(resp);
            goto done;
        }
        if (json_object_object_get_ex(resp, "protocol_version", &val))
            resp_proto_version = json_object_get_int(val);
        if (resp_proto_version != 1) {
            LOG("ERROR: step-2 protocol_version=%d, expected 1 — "
                "incompatible peer", resp_proto_version);
            json_object_put(resp);
            goto done;
        }
        if (!json_object_object_get_ex(resp, "ca_cosigner_pem", &val)) {
            LOG("ERROR: step-2 missing ca_cosigner_pem (P0 #63)");
            json_object_put(resp);
            goto done;
        }
        resp_cosigner_pem = json_object_get_string(val);
        if (!json_object_object_get_ex(resp, "transcript_sig", &val)) {
            LOG("ERROR: step-2 missing transcript_sig (P0 #63)");
            json_object_put(resp);
            goto done;
        }
        resp_transcript_sig_hex = json_object_get_string(val);

        /* (1) Fingerprint check: SHA-256(DER(SPKI(pem))) ==
         *     cosigner_fp_canon (operator-pasted via
         *     issue_leaf_nonce). */
        {
            unsigned char spki_der[4096];
            int spki_sz = wc_PubKeyPemToDer(
                (const unsigned char *)resp_cosigner_pem,
                (int)strlen(resp_cosigner_pem),
                spki_der, (int)sizeof(spki_der));
            if (spki_sz <= 0) {
                LOG("ERROR: step-2 ca_cosigner_pem rejected by "
                    "wc_PubKeyPemToDer (rc=%d)", spki_sz);
                json_object_put(resp);
                goto done;
            }
            unsigned char digest[WC_SHA256_DIGEST_SIZE];
            if (wc_Sha256Hash(spki_der, (word32)spki_sz, digest) != 0) {
                LOG("ERROR: SHA-256 over step-2 cosigner SPKI failed");
                json_object_put(resp);
                goto done;
            }
            char got_fp[WC_SHA256_DIGEST_SIZE * 2 + 1];
            {
                static const char hex[] = "0123456789abcdef";
                int hi;
                for (hi = 0; hi < (int)sizeof(digest); hi++) {
                    got_fp[hi * 2]     = hex[(digest[hi] >> 4) & 0xf];
                    got_fp[hi * 2 + 1] = hex[digest[hi] & 0xf];
                }
                got_fp[64] = '\0';
            }
            int diff = 0, hi;
            for (hi = 0; hi < 64; hi++)
                diff |= got_fp[hi] ^ cosigner_fp_arg[hi];
            if (diff != 0) {
                LOG("ERROR: step-2 COSIGNER_FP_MISMATCH — possible "
                    "MitM on port 8445.\n"
                    "       expected: sha256:%s\n"
                    "       got:      sha256:%s",
                    cosigner_fp_arg, got_fp);
                json_object_put(resp);
                goto done;
            }

            /* (2) Reconstruct the 113-byte signed message and
             *     ML-DSA-87 verify under the now-fingerprint-trusted
             *     PEM.  Catches MitM substituting either DH key. */
            unsigned char sig_msg[CURVE25519_KEYSIZE * 2 + SALT_SZ +
                                  32 + 1];
            unsigned int  sig_msg_len = 0;
            memcpy(sig_msg + sig_msg_len, my_pub, CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, server_pub, CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, salt, SALT_SZ);
            sig_msg_len += SALT_SZ;
            memcpy(sig_msg + sig_msg_len, pop_nonce, sizeof(pop_nonce));
            sig_msg_len += (unsigned int)sizeof(pop_nonce);
            sig_msg[sig_msg_len++] = (unsigned char)resp_proto_version;

            int sig_hex_len = (int)strlen(resp_transcript_sig_hex);
            if (sig_hex_len <= 0 || (sig_hex_len & 1) != 0) {
                LOG("ERROR: transcript_sig odd-length hex (%d)",
                    sig_hex_len);
                json_object_put(resp);
                goto done;
            }
            int sig_bin_len = sig_hex_len / 2;
            unsigned char *sig_bin =
                (unsigned char *)malloc((size_t)sig_bin_len);
            if (!sig_bin || hex_to_bytes(resp_transcript_sig_hex,
                                          sig_bin, sig_bin_len)
                            != sig_bin_len) {
                LOG("ERROR: transcript_sig hex decode failed");
                free(sig_bin);
                json_object_put(resp);
                goto done;
            }
            dilithium_key dil;
            int verify_rc = -1, verified = 0;
            if (wc_dilithium_init(&dil) == 0) {
                if (wc_dilithium_set_level(&dil, WC_ML_DSA_87) == 0) {
                    word32 idx = 0;
                    if (wc_Dilithium_PublicKeyDecode(
                            spki_der, &idx, &dil,
                            (word32)spki_sz) == 0) {
                        verify_rc = wc_dilithium_verify_ctx_msg(
                            sig_bin, (word32)sig_bin_len,
                            (const byte *)MTC_BOOTSTRAP_DH_LABEL,
                            MTC_BOOTSTRAP_DH_LABEL_LEN,
                            sig_msg, sig_msg_len,
                            &verified, &dil);
                    }
                }
                wc_dilithium_free(&dil);
            }
            free(sig_bin);
            if (verify_rc != 0 || !verified) {
                LOG("ERROR: BOOTSTRAP_DH_TRANSCRIPT_INVALID — "
                    "step-2 signature does not verify under the "
                    "cosigner PEM whose fingerprint matched the pin "
                    "(rc=%d, verified=%d).  Aborting before any AEAD "
                    "keys are derived.", verify_rc, verified);
                json_object_put(resp);
                goto done;
            }
            LOG("  DH transcript signature verified (P0 #63)");
        }

        json_object_put(resp);
    }
    LOG("server DH public key + salt + pop_nonce received");

    /* --- Compute shared secret --- */
    if (wc_curve25519_init(&server_key) != 0) {
        LOG("ERROR: server key init failed");
        goto done;
    }
    server_key_ok = 1;

    if (wc_curve25519_import_public(server_pub, CURVE25519_KEYSIZE,
                                     &server_key) != 0) {
        LOG("ERROR: import server public key failed");
        goto done;
    }

    if (wc_curve25519_shared_secret(&my_key, &server_key,
                                     shared_secret, &shared_sz) != 0) {
        LOG("ERROR: shared secret computation failed");
        goto done;
    }
    LOG("shared secret computed (%u bytes)", shared_sz);

    /* --- Derive AES-256-GCM keys (TODO #62 AEAD): 64 bytes total,
     *     first 32 = c2s_key, last 32 = s2c_key. --- */
    if (wc_HKDF(WC_SHA256, shared_secret, shared_sz,
                 salt, SALT_SZ,
                 (const byte *)HKDF_INFO, (word32)strlen(HKDF_INFO),
                 aes_keys, AES_KEYS_TOTAL) != 0) {
        LOG("ERROR: HKDF key derivation failed");
        goto done;
    }
    LOG("AES-256-GCM keys derived via HKDF");

    /* --- Init AEAD encryption --- */
    crypt_ctx = mtc_crypt_init(aes_keys,                   /* c2s */
                               aes_keys + AES_KEY_SZ);     /* s2c */
    if (!crypt_ctx) {
        LOG("ERROR: mtc_crypt_init failed");
        goto done;
    }

    /* --- Step 4: Send encrypted enrollment request --- */
    {
        struct json_object *enroll = json_object_new_object();
        const char *enroll_str;

        json_object_object_add(enroll, "subject",
            json_object_new_string(subject));
        json_object_object_add(enroll, "public_key_pem",
            json_object_new_string(pub_key_pem));
        json_object_object_add(enroll, "key_algorithm",
            json_object_new_string(key_algo));
        json_object_object_add(enroll, "validity_days",
            json_object_new_int(validity_days));
        json_object_object_add(enroll, "enrollment_nonce",
            json_object_new_string(nonce));

        enroll_str = json_object_to_json_string(enroll);
        LOG_V("enrollment JSON: %s", enroll_str);

        enc_len = sizeof(enc_buf);
        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_C2S, (unsigned char *)enroll_str,
                (unsigned int)strlen(enroll_str), enc_buf, &enc_len) != 0) {
            LOG("ERROR: failed to encrypt enrollment request");
            json_object_put(enroll);
            goto done;
        }
        json_object_put(enroll);

        LOG("sending encrypted enrollment (%u bytes)", enc_len);
        if (send_length_prefixed(sock_fd, enc_buf, enc_len) != 0) {
            LOG("ERROR: failed to send enrollment request");
            goto done;
        }
    }
    LOG("enrollment request sent");

    /* --- Receive encrypted certificate response --- */
    ret = recv_length_prefixed(sock_fd, enc_buf, sizeof(enc_buf));
    if (ret <= 0) {
        LOG("ERROR: failed to receive certificate response");
        goto done;
    }
    LOG("received encrypted response (%d bytes)", ret);

    dec_len = sizeof(dec_buf);
    if (mtc_crypt_decode(crypt_ctx, MTC_DIR_S2C, enc_buf, (unsigned int)ret,
                         dec_buf, &dec_len) != 0) {
        LOG("ERROR: failed to decrypt certificate response");
        goto done;
    }
    dec_buf[dec_len] = '\0';

    LOG("decrypted response (%u bytes)", dec_len);
    LOG_V("response: %s", (char *)dec_buf);

    /* --- Parse response --- */
    {
        struct json_object *resp, *val;
        const char *status;
        const char *ca_cosigner_pem = NULL;

        resp = json_tokener_parse((const char *)dec_buf);
        if (!resp) {
            LOG("ERROR: invalid certificate response JSON");
            goto done;
        }

        if (json_object_object_get_ex(resp, "status", &val)) {
            status = json_object_get_string(val);
            if (strcmp(status, "ok") != 0) {
                const char *msg = "";
                if (json_object_object_get_ex(resp, "message", &val))
                    msg = json_object_get_string(val);
                LOG("ERROR: server returned: %s — %s", status, msg);
                json_object_put(resp);
                goto done;
            }
        }

        /* P0 / TODO #9b leaf branch — verify the bootstrap response
         * before trusting any of its other fields.  Steps:
         *   1. Extract ca_cosigner_pem + ca_response_sig.  Both
         *      missing  ⇒ legacy server, refuse (operator must
         *      upgrade the CA before fresh enrollments will land).
         *   2. SHA-256(DER(SPKI(pem))) must match cosigner_fp_arg.
         *      This is the operator-pasted pin; it's the link that
         *      defeats an on-path attacker on port 8445.
         *   3. wc_dilithium_verify_ctx_msg the response signature
         *      under the (now-fingerprint-authenticated) PEM, with
         *      ctx=MTC_BOOTSTRAP_LABEL, over the canonical JSON of
         *      the response with ca_response_sig removed.  This
         *      proves the bootstrap response was actually produced
         *      by the holder of the cosigner private key.
         *   4. On success, ca_cosigner_pem becomes safe to pin into
         *      the per-leaf TPM dir (handled in save_to_tpm). */
        {
            struct json_object *pem_val, *sig_val;
            const char *response_sig_hex = NULL;
            int  have_pem = json_object_object_get_ex(
                                resp, "ca_cosigner_pem", &pem_val);
            int  have_sig = json_object_object_get_ex(
                                resp, "ca_response_sig", &sig_val);

            if (!have_pem || !have_sig) {
                LOG("ERROR: bootstrap response is missing P0 #9b "
                    "fields (ca_cosigner_pem / ca_response_sig).  "
                    "The CA server hasn't been upgraded to the "
                    "post-#9b protocol; refusing to enroll.");
                json_object_put(resp);
                goto done;
            }
            ca_cosigner_pem    = json_object_get_string(pem_val);
            response_sig_hex   = json_object_get_string(sig_val);
            if (!ca_cosigner_pem || !response_sig_hex) {
                LOG("ERROR: ca_cosigner_pem or ca_response_sig is "
                    "not a string in the bootstrap response.");
                json_object_put(resp);
                goto done;
            }
            /* Copy the sig hex out before json_object_object_del
             * frees the value below — the const char* returned by
             * json_object_get_string is borrowed from the json_object
             * and goes dangling on delete.  ML-DSA-87 hex sig is
             * 9254 chars + NUL; 16 KB stack buffer is comfortable. */
            char  response_sig_hex_buf[16384];
            int   response_sig_hex_len = (int)strlen(response_sig_hex);
            if (response_sig_hex_len <= 0 ||
                response_sig_hex_len >= (int)sizeof(response_sig_hex_buf)) {
                LOG("ERROR: ca_response_sig length %d out of range",
                    response_sig_hex_len);
                json_object_put(resp);
                goto done;
            }
            memcpy(response_sig_hex_buf, response_sig_hex,
                   (size_t)response_sig_hex_len + 1);
            response_sig_hex = response_sig_hex_buf;

            /* Step 2: fingerprint check. */
            unsigned char spki_der[4096];
            int spki_der_sz = wc_PubKeyPemToDer(
                (const unsigned char *)ca_cosigner_pem,
                (int)strlen(ca_cosigner_pem),
                spki_der, (int)sizeof(spki_der));
            if (spki_der_sz <= 0) {
                LOG("ERROR: ca_cosigner_pem is not a valid PEM-encoded "
                    "public key (wc_PubKeyPemToDer rc=%d)", spki_der_sz);
                json_object_put(resp);
                goto done;
            }
            unsigned char digest[WC_SHA256_DIGEST_SIZE];
            if (wc_Sha256Hash(spki_der, (word32)spki_der_sz,
                              digest) != 0) {
                LOG("ERROR: SHA-256 over cosigner SPKI DER failed");
                json_object_put(resp);
                goto done;
            }
            char got_fp[WC_SHA256_DIGEST_SIZE * 2 + 1];
            {
                static const char hexdigits[] = "0123456789abcdef";
                int hi;
                for (hi = 0; hi < (int)sizeof(digest); hi++) {
                    got_fp[hi * 2]     = hexdigits[(digest[hi] >> 4) & 0xf];
                    got_fp[hi * 2 + 1] = hexdigits[digest[hi] & 0xf];
                }
                got_fp[sizeof(digest) * 2] = '\0';
            }
            /* cosigner_fp_arg is already canonicalized to bare 64-char
             * lowercase hex; constant-time-equal compare. */
            {
                int diff = 0, hi;
                for (hi = 0; hi < 64; hi++)
                    diff |= got_fp[hi] ^ cosigner_fp_arg[hi];
                if (diff != 0) {
                    LOG("ERROR: COSIGNER_FP_MISMATCH — possible MitM "
                        "on port 8445.\n"
                        "       expected: sha256:%s\n"
                        "       got:      sha256:%s\n"
                        "       (the CA-operator-pasted --cosigner-fp "
                        "does NOT match the response's ca_cosigner_pem)",
                        cosigner_fp_arg, got_fp);
                    json_object_put(resp);
                    goto done;
                }
            }
            LOG("  cosigner fingerprint matches (sha256:%s)", got_fp);

            /* Step 3: signature verify.
             * The signed bytes are the canonical JSON of the response
             * with ca_response_sig REMOVED.  Strip the field, re-
             * serialize with JSON_C_TO_STRING_PLAIN, and verify. */
            json_object_object_del(resp, "ca_response_sig");
            const char *to_verify = json_object_to_json_string_ext(
                resp, JSON_C_TO_STRING_PLAIN);
            int  to_verify_len = (int)strlen(to_verify);

            int sig_hex_len = (int)strlen(response_sig_hex);
            if (sig_hex_len <= 0 || (sig_hex_len & 1) != 0) {
                LOG("ERROR: ca_response_sig is not even-length hex "
                    "(len=%d)", sig_hex_len);
                json_object_put(resp);
                goto done;
            }
            int sig_bin_len = sig_hex_len / 2;
            unsigned char *sig_bin =
                (unsigned char *)malloc((size_t)sig_bin_len);
            if (!sig_bin) {
                LOG("ERROR: out of memory for response signature");
                json_object_put(resp);
                goto done;
            }
            {
                int hi;
                for (hi = 0; hi < sig_bin_len; hi++) {
                    int hv, lv;
                    char hc = response_sig_hex[hi * 2];
                    char lc = response_sig_hex[hi * 2 + 1];
                    if      (hc >= '0' && hc <= '9') hv = hc - '0';
                    else if (hc >= 'a' && hc <= 'f') hv = 10 + hc - 'a';
                    else if (hc >= 'A' && hc <= 'F') hv = 10 + hc - 'A';
                    else { free(sig_bin); LOG("ERROR: ca_response_sig "
                        "contains non-hex char"); json_object_put(resp);
                        goto done; }
                    if      (lc >= '0' && lc <= '9') lv = lc - '0';
                    else if (lc >= 'a' && lc <= 'f') lv = 10 + lc - 'a';
                    else if (lc >= 'A' && lc <= 'F') lv = 10 + lc - 'A';
                    else { free(sig_bin); LOG("ERROR: ca_response_sig "
                        "contains non-hex char"); json_object_put(resp);
                        goto done; }
                    sig_bin[hi] = (unsigned char)((hv << 4) | lv);
                }
            }

            dilithium_key dil;
            int verify_rc = -1, verified = 0;
            if (wc_dilithium_init(&dil) == 0) {
                if (wc_dilithium_set_level(&dil, WC_ML_DSA_87) == 0) {
                    word32 idx = 0;
                    if (wc_Dilithium_PublicKeyDecode(spki_der, &idx,
                            &dil, (word32)spki_der_sz) == 0) {
                        verify_rc = wc_dilithium_verify_ctx_msg(
                            sig_bin, (word32)sig_bin_len,
                            (const byte *)MTC_BOOTSTRAP_LABEL,
                            MTC_BOOTSTRAP_LABEL_LEN,
                            (const byte *)to_verify,
                            (word32)to_verify_len,
                            &verified, &dil);
                    }
                }
                wc_dilithium_free(&dil);
            }
            free(sig_bin);
            if (verify_rc != 0 || !verified) {
                LOG("ERROR: BOOTSTRAP_RESPONSE_SIG_INVALID — "
                    "signature does not verify under the cosigner "
                    "PEM whose fingerprint matched the operator pin "
                    "(rc=%d, verified=%d).  Refusing to enroll.",
                    verify_rc, verified);
                json_object_put(resp);
                goto done;
            }
            LOG("  bootstrap response signature verified under cosigner PEM");
        }

        if (json_object_object_get_ex(resp, "index", &val)) {
            int cert_index = json_object_get_int(val);
            const char *label_from_server = NULL;
            struct json_object *lval;

            LOG("certificate issued at index %d", cert_index);

            /* Optional label echoed by the server (present when the
             * CA operator ran issue_leaf_nonce --label ...).  The
             * server MUST NOT bake this into the cert; it's purely a
             * hint for where to write on disk.  Absent field =
             * legacy behavior (write to ~/.TPM/<subject>/). */
            if (json_object_object_get_ex(resp, "label", &lval)) {
                const char *s = json_object_get_string(lval);
                if (s && s[0]) {
                    if (sanitize_label(s) != 0) {
                        LOG("ERROR: server-supplied label '%s' fails "
                            "sanitization — refusing to write to disk", s);
                        json_object_put(resp);
                        goto done;
                    }
                    label_from_server = s;
                    LOG("  server-assigned label: %s", s);
                }
            }

            /* --- Step 6: Save to TPM --- */
            if (g_trial_run) {
                if (label_from_server)
                    LOG("DRY RUN: would save to %s/<subject>-%s/",
                        tpm_dir, label_from_server);
                else
                    LOG("DRY RUN: would save to %s/<subject>/", tpm_dir);
                LOG("DRY RUN: certificate JSON:\n%s",
                    json_object_to_json_string_ext(resp,
                        JSON_C_TO_STRING_PRETTY));
            } else {
                if (save_to_tpm(tpm_dir, subject, label_from_server,
                        make_default,
                        json_object_to_json_string_ext(resp,
                            JSON_C_TO_STRING_PRETTY),
                        cert_index, pub_key_path, priv_key_path,
                        ca_cosigner_pem) == 0) {
                    LOG("certificate saved to %s/", tpm_dir);
                } else {
                    LOG("ERROR: failed to save to TPM");
                    json_object_put(resp);
                    goto done;
                }
            }
        }

        json_object_put(resp);
    }

    /* Server-side enrollment already wrote the leaf pubkey to Neon
     * (mtc_bootstrap.c:1367 mtc_db_save_public_key) — the client
     * doesn't (and shouldn't) have Neon credentials, so the prior
     * client-side mtc_store_public_key() call was vestigial and just
     * produced a noisy "MERKLE_NEON not found, skipping key store"
     * message on every leaf-side enrollment.  Removed. */

    LOG("enrollment complete!");
    exit_code = 0;

done:
    if (pub_key_pem) free(pub_key_pem);
    if (crypt_ctx) mtc_crypt_fin(crypt_ctx);
    if (sock_fd >= 0) close(sock_fd);
    if (server_key_ok) wc_curve25519_free(&server_key);
    if (my_key_ok) wc_curve25519_free(&my_key);
    if (rng_ok) wc_FreeRng(&rng);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_keys, sizeof(aes_keys));
    secure_zero(salt, sizeof(salt));
    wolfSSL_Cleanup();
    return exit_code;
}
