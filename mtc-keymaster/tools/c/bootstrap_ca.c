/******************************************************************************
 * File:        bootstrap_ca.c
 * Purpose:     Client-side DH bootstrap tool for CA enrollment.
 *
 * Description:
 *   Connects to the CA server's DH bootstrap port, performs X25519 key
 *   exchange, sends an encrypted CA enrollment request (with the X.509
 *   CA certificate in extensions), receives the MTC certificate, and
 *   stores it in ~/.TPM/<subject>/.
 *
 *   The server performs DNSSEC-validated TXT validation at
 *   _mqc-ca.<domain> for every CA enrollment (no root bypass);
 *   the published TXT must contain
 *   `v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<HEX>` where
 *   <HEX> is SHA3-256 of the cert's SPKI DER.  Generate the
 *   record with `ca_dns_txt.py --cert <PATH> --domain <DOMAIN>`.
 *
 *   Usage:
 *     bootstrap_ca --server HOST:PORT --domain DOMAIN \
 *                  --public-key FILE --private-key FILE \
 *                  --ca-cert FILE [--tpm-dir DIR] [--dry-run]
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
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/types.h>

#include "../../server2/c/mtc_dnssec_pin.h"   /* P0 #9b CA branch */
#include "../../server2/c/mtc_bootstrap_transcript.h"  /* TODO #11 */

/* P0 / TODO #63 — DH-transcript signature label.  Must match
 * server-side MTC_BOOTSTRAP_DH_LABEL in mtc_bootstrap.c. */
#define MTC_BOOTSTRAP_DH_LABEL      "mtc-boot-dh/v1\n\x00"
#define MTC_BOOTSTRAP_DH_LABEL_LEN  16

/* Proof-of-possession constants — MUST match the server's
 * mtc-keymaster/server2/c/mtc_bootstrap.c.  See
 * mtc-keymaster/server2/c/README-issues.md issue #5 for the
 * design.  No header is shared because client and server live
 * in separate compilation units that don't otherwise depend on
 * each other; both sides assert this label is exactly 16 bytes. */
#define BOOTSTRAP_POP_NONCE_SZ 32
#define MTC_CA_POP_LABEL       "mtc-ca-pop/v1\n\x00"
#define MTC_CA_POP_LABEL_LEN   16
#define MTC_CA_POP_PREFIX      "MQC-CA-REGISTER"

#include <json-c/json.h>

#define HKDF_INFO        "mtc-dh-bootstrap"
#define SALT_SZ          16
#define AES_KEY_SZ       32                  /* AES-256 — TODO #62 */
#define AES_KEYS_TOTAL   (AES_KEY_SZ * 2)    /* c2s||s2c           */
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

/* CA subject is always "<domain>-ca" (established by the server).  The
 * optional label slots in BEFORE "-ca", giving "<domain>-<label>-ca"
 * on disk — mirrors the leaf convention of "<domain>-<label>". */
static int save_to_tpm(const char *tpm_dir, const char *subject,
                       const char *label, int make_default,
                       const char *cert_json, int cert_index,
                       const char *pub_key_path, const char *priv_key_path,
                       const char *ca_cert_path_arg,
                       const char *ca_cosigner_pem)
{
    char dir_path[256];
    char file_path[256 + 32];  /* dir_path + longest filename */
    char *subj_safe;
    char leaf_part[256];       /* subject minus trailing "-ca", if any */
    FILE *fp;
    char *key_data;
    int key_len, n;
    unsigned int i;
    size_t sl;

    /* Convert subject to filesystem-safe name: replace ':' with '_' */
    subj_safe = strdup(subject);
    for (i = 0; i < strlen(subj_safe); i++) {
        if (subj_safe[i] == ':')
            subj_safe[i] = '_';
    }

    /* If a label is set, interleave it before the "-ca" suffix:
     *     foo.com-ca  +  label=prod   →   foo.com-prod-ca
     * Falls back to the legacy subject-only path when label is NULL. */
    if (label && label[0]) {
        sl = strlen(subj_safe);
        if (sl > 3 && strcmp(subj_safe + sl - 3, "-ca") == 0) {
            int ll = (int)(sl - 3);
            if (ll >= (int)sizeof(leaf_part)) ll = (int)sizeof(leaf_part) - 1;
            memcpy(leaf_part, subj_safe, (size_t)ll);
            leaf_part[ll] = '\0';
            n = snprintf(dir_path, sizeof(dir_path), "%s/%s-%s-ca",
                         tpm_dir, leaf_part, label);
        } else {
            /* Subject doesn't end in -ca — keep the label as a plain
             * suffix (shouldn't happen in practice but safe fallback). */
            n = snprintf(dir_path, sizeof(dir_path), "%s/%s-%s",
                         tpm_dir, subj_safe, label);
        }
    } else {
        n = snprintf(dir_path, sizeof(dir_path), "%s/%s", tpm_dir, subj_safe);
    }
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

    /* Copy CA certificate */
    if (ca_cert_path_arg) {
        key_len = read_file(ca_cert_path_arg, &key_data);
        if (key_len > 0) {
            snprintf(file_path, sizeof(file_path), "%s/ca_cert.pem", dir_path);
            fp = fopen(file_path, "w");
            if (fp) {
                fwrite(key_data, 1, (size_t)key_len, fp);
                fclose(fp);
                LOG("  wrote %s", file_path);
            }
            free(key_data);
        }
    }

    /* P0 / TODO #9b CA branch — pin the now-authenticated parent
     * cosigner PEM into this CA's TPM dir.  Verification of
     * fingerprint (DNSSEC-fetched) + signature happens before
     * save_to_tpm is called; by the time the PEM lands here we've
     * already proven it was signed under the cosigner private key
     * whose SHA3-256(SPKI DER) matches the parent's DNSSEC pin. */
    if (ca_cosigner_pem && ca_cosigner_pem[0]) {
        snprintf(file_path, sizeof(file_path),
                 "%s/ca-cosigner.pem", dir_path);
        fp = fopen(file_path, "w");
        if (fp) {
            fputs(ca_cosigner_pem, fp);
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
     * mirrors the bootstrap_leaf logic exactly.  See comments there. */
    {
        char default_path[PATH_MAX];
        char rel_target[256];
        struct stat st;
        int default_exists;
        const char *base = strrchr(dir_path, '/');
        base = base ? base + 1 : dir_path;
        snprintf(rel_target, sizeof(rel_target), "%s", base);
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
            unlink(tmp_path);
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
    printf("DH Bootstrap CA Enrollment Tool\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  --server HOST:PORT   CA server DH bootstrap endpoint\n");
    printf("  --domain DOMAIN      CA domain (e.g., factsorlie.com)\n");
    printf("  --public-key FILE    Path to CA public key PEM\n");
    printf("  --private-key FILE   Path to CA private key PEM\n");
    printf("  --ca-cert FILE       Path to X.509 CA certificate PEM\n");
    printf("  --cosigner-fp FP     SHA3-256 of DER(SPKI) of the parent log's\n");
    printf("                       cosigner pubkey (sha3-256:<hex> or 64-char\n");
    printf("                       hex).  Skip to fetch automatically via\n");
    printf("                       DNSSEC at _mqc-cosigner.<server-host>.\n");
    printf("                       Refuses to enroll on fp-mismatch.\n");
    printf("  --no-pin             Skip cosigner-fp verification entirely.\n");
    printf("                       ONLY for self-bootstrap on the same box\n");
    printf("                       as mtc_server (--server localhost:...);\n");
    printf("                       cross-host enrollment must verify.\n");
    printf("  --key-algorithm ALG  Key algorithm (default: ML-DSA-87)\n");
    printf("  --validity-days N    Certificate validity (default: 365)\n");
    printf("  --tpm-dir DIR        TPM storage directory (default: ~/.TPM)\n");
    printf("  --label LABEL        Optional local disambiguator: CA identity\n");
    printf("                       is stored under ~/.TPM/<domain>-<label>-ca/\n");
    printf("                       Charset [A-Za-z0-9._-], length 1..64.\n");
    printf("                       Never embedded in the cert.\n");
    printf("  --make-default       Re-point ~/.TPM/default at this identity\n");
    printf("                       even if it already exists (default: create\n");
    printf("                       only if missing).\n");
    printf("  --dry-run            Do everything but don't save to TPM\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help\n");
    printf("\nNote: CA enrollment requires a DNSSEC-signed DNS TXT\n");
    printf("  record at _mqc-ca.<domain> with format:\n");
    printf("  v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<fingerprint>\n");
    printf("  where <fingerprint> is SHA3-256 over the CA cert's SPKI DER.\n");
    printf("  Generate the record with:\n");
    printf("    ca_dns_txt.py --domain <DOMAIN> --cert <PATH-TO-CA-CERT>\n");
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
    const char *ca_cert_path = NULL;
    const char *cosigner_fp_arg = NULL;   /* P0 #9b CA branch */
    int  no_pin = 0;                      /* self-bootstrap escape */
    const char *key_algo = "ML-DSA-87";
    int validity_days = 365;
    const char *tpm_dir_arg = NULL;
    const char *label_arg = NULL;
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
    uint8_t aes_keys[AES_KEYS_TOTAL];   /* c2s||s2c — TODO #62 */
    char    pop_nonce_hex[BOOTSTRAP_POP_NONCE_SZ * 2 + 1] = {0};

    /* I/O */
    int sock_fd = -1;
    char json_buf[MAX_MSG];
    unsigned char enc_buf[MAX_MSG];
    unsigned char dec_buf[MAX_MSG];
    unsigned int enc_len, dec_len;

    /* Public key PEM content */
    char *pub_key_pem = NULL;
    char *ca_cert_pem = NULL;

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
        else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc)
            ca_cert_path = argv[++i];
        else if (strcmp(argv[i], "--cosigner-fp") == 0 && i + 1 < argc)
            cosigner_fp_arg = argv[++i];
        else if (strcmp(argv[i], "--no-pin") == 0)
            no_pin = 1;
        else if (strcmp(argv[i], "--key-algorithm") == 0 && i + 1 < argc)
            key_algo = argv[++i];
        else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc)
            validity_days = atoi(argv[++i]);
        else if (strcmp(argv[i], "--tpm-dir") == 0 && i + 1 < argc)
            tpm_dir_arg = argv[++i];
        else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc)
            label_arg = argv[++i];
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

    if (label_arg && sanitize_label(label_arg) != 0) {
        fprintf(stderr,
            "Error: --label must be 1..%d chars, [A-Za-z0-9._-] only\n",
            MTC_LABEL_MAX);
        return 1;
    }

    /* Default --server: CLI > [global] url-bootstrap > factsorlie.com:8445. */
    if (!server_arg) {
        char *cfg = read_config_url("global/url-bootstrap");
        server_arg = cfg ? cfg : "factsorlie.com:8445";
    }

    /* Default paths from ~/.mtc-ca-data/<domain>-ca/ if not specified.
     *
     * The `-ca` suffix matches the CA's actual TBS subject (the wire
     * subject is `<domain>-ca`, not bare `<domain>`).  Without the
     * suffix, the same directory was being used by both create_ca_cert.py
     * (writing) and create_leaf_keypair.py / register-leaf.sh (reading
     * for a same-domain leaf) — collision: register-leaf.sh on the
     * same box would find the CA's keypair and try to register the
     * CA's public key as a leaf with subject == bare domain. */
    {
        static char def_pub[512], def_priv[512], def_cert[512];
        const char *home = getenv("HOME");
        if (!home) home = ".";

        if (!pub_key_path) {
            snprintf(def_pub, sizeof(def_pub),
                     "%s/.mtc-ca-data/%s-ca/public_key.pem", home, subject);
            pub_key_path = def_pub;
        }
        if (!priv_key_path) {
            snprintf(def_priv, sizeof(def_priv),
                     "%s/.mtc-ca-data/%s-ca/private_key.pem", home, subject);
            priv_key_path = def_priv;
        }
        if (!ca_cert_path) {
            snprintf(def_cert, sizeof(def_cert),
                     "%s/.mtc-ca-data/%s-ca/ca_cert.pem", home, subject);
            ca_cert_path = def_cert;
        }
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

    /* P0 / TODO #9b CA branch — resolve the expected cosigner
     * fingerprint BEFORE opening the TCP connection.  Order of
     * precedence:
     *   1. --cosigner-fp <hex>   (operator-pasted, like the leaf
     *                              branch)
     *   2. DNSSEC TXT at _mqc-cosigner.<server-host>
     *   3. --no-pin              (allowed only for localhost /
     *                              127.0.0.1 self-bootstrap)
     *
     * The cosigner_fp_canon buffer below holds the canonical
     * 64-char lowercase hex; it stays empty if --no-pin (in which
     * case the verify block at the bottom skips the comparison
     * but still verifies the response signature against the
     * embedded PEM — i.e., the response is still tamper-evident,
     * just not key-authenticated).  The "embedded PEM" in
     * --no-pin mode is tautologically the one signing itself, so
     * --no-pin is genuinely no-trust; restricted to local. */
    char cosigner_fp_canon[65];
    cosigner_fp_canon[0] = '\0';

    if (cosigner_fp_arg) {
        const char *p = cosigner_fp_arg;
        if (strncmp(p, "sha3-256:", 9) == 0)      p += 9;
        else if (strncmp(p, "sha256:", 7) == 0)   p += 7;
        if (strlen(p) != 64) {
            fprintf(stderr,
                    "Error: --cosigner-fp must be 64 hex chars "
                    "(optionally prefixed sha3-256:).  Got %zu chars.\n",
                    strlen(p));
            free(pub_key_pem); free(ca_cert_pem);
            return 1;
        }
        for (int hi = 0; hi < 64; hi++) {
            char c = p[hi];
            char lc = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
            if (!((lc >= '0' && lc <= '9') || (lc >= 'a' && lc <= 'f'))) {
                fprintf(stderr, "Error: --cosigner-fp contains non-hex "
                                "char at position %d ('%c')\n", hi, c);
                free(pub_key_pem); free(ca_cert_pem);
                return 1;
            }
            cosigner_fp_canon[hi] = lc;
        }
        cosigner_fp_canon[64] = '\0';
        LOG("cosigner-fp source: --cosigner-fp (operator-pasted)");
    } else if (no_pin) {
        int is_local =
            (strcmp(server_host, "localhost") == 0) ||
            (strcmp(server_host, "127.0.0.1") == 0) ||
            (strcmp(server_host, "::1") == 0);
        if (!is_local) {
            fprintf(stderr,
                    "Error: --no-pin is only allowed when --server is\n"
                    "       localhost / 127.0.0.1 / ::1.  Cross-host\n"
                    "       enrollment must verify the parent cosigner\n"
                    "       (use --cosigner-fp <hex> or publish a\n"
                    "       DNSSEC TXT at _mqc-cosigner.<host>).\n");
            free(pub_key_pem); free(ca_cert_pem);
            return 1;
        }
        LOG("cosigner-fp source: --no-pin (self-bootstrap on %s)",
            server_host);
    } else {
        /* DNSSEC fetch.  Fail closed on any non-OK status. */
        mqc_dnssec_status_t st =
            mqc_dnssec_fetch_cosigner_kh(server_host, cosigner_fp_canon);
        if (st != MQC_DNSSEC_OK) {
            fprintf(stderr,
                "Error: DNSSEC lookup of _mqc-cosigner.%s failed: %s\n"
                "       Operator must publish a DNSSEC-signed TXT record\n"
                "       (mtc_server prints the value to publish in its\n"
                "       startup banner — pull it from journalctl on the\n"
                "       parent CA).  Or pass --cosigner-fp <hex> to skip\n"
                "       DNSSEC; or --no-pin for localhost self-bootstrap.\n",
                server_host, mqc_dnssec_status_string(st));
            free(pub_key_pem); free(ca_cert_pem);
            return 1;
        }
        LOG("cosigner-fp source: DNSSEC _mqc-cosigner.%s -> sha3-256:%s",
            server_host, cosigner_fp_canon);
    }

    /* Read public key PEM */
    if (read_file(pub_key_path, &pub_key_pem) <= 0) {
        fprintf(stderr, "Error: cannot read public key file: %s\n", pub_key_path);
        return 1;
    }

    /* Read CA certificate PEM */
    if (read_file(ca_cert_path, &ca_cert_pem) <= 0) {
        fprintf(stderr, "Error: cannot read CA cert file: %s\n", ca_cert_path);
        free(pub_key_pem);
        return 1;
    }

    if (g_trial_run)
        LOG("*** DRY RUN — will not save to TPM ***");

    LOG("server:      %s:%d", server_host, server_port);
    LOG("subject:     %s", subject);
    LOG("public key:  %s", pub_key_path);
    LOG("CA cert:     %s", ca_cert_path);
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

        /* PoP nonce (issue #5).  Server includes 32 random bytes
         * here that the client must sign with the CA private key
         * to prove possession.  A server that doesn't ship the
         * issue-#5 fix will omit this field; we treat the
         * absence as a hard error rather than silently falling
         * back, because the absence of PoP is exactly the bug
         * issue #5 closes. */
        if (!json_object_object_get_ex(resp, "pop_nonce", &val)) {
            LOG("ERROR: server response is missing pop_nonce — "
                "the server is older than the README-issues.md "
                "issue #5 fix; upgrade the server before "
                "enrolling a CA.");
            json_object_put(resp);
            goto done;
        }
        hex_str = json_object_get_string(val);
        if (!hex_str ||
            strlen(hex_str) != BOOTSTRAP_POP_NONCE_SZ * 2) {
            LOG("ERROR: pop_nonce must be exactly %d hex chars",
                BOOTSTRAP_POP_NONCE_SZ * 2);
            json_object_put(resp);
            goto done;
        }
        snprintf(pop_nonce_hex, sizeof(pop_nonce_hex), "%s", hex_str);

        /* P0 / TODO #63 — DH-transcript signature.  Verify before
         * deriving any AEAD keys.  Skip under --no-pin (localhost
         * self-bootstrap, no MitM surface). */
        if (cosigner_fp_canon[0]) {
            int  resp_proto_version = 0;
            const char *resp_cosigner_pem = NULL;
            const char *resp_transcript_sig_hex = NULL;

            if (!json_object_object_get_ex(resp, "protocol_version", &val) ||
                (resp_proto_version = json_object_get_int(val)) != 1) {
                LOG("ERROR: step-2 protocol_version missing or != 1 — "
                    "incompatible peer (P0 #63)");
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

            /* SHA3-256 fingerprint check against DNSSEC pin (or
             * operator-pasted --cosigner-fp). */
            unsigned char digest[32];
            wc_Sha3 sha;
            wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
            wc_Sha3_256_Update(&sha, spki_der, (word32)spki_sz);
            wc_Sha3_256_Final(&sha, digest);
            wc_Sha3_256_Free(&sha);
            char got_fp[65];
            {
                static const char hex[] = "0123456789abcdef";
                int hi;
                for (hi = 0; hi < 32; hi++) {
                    got_fp[hi * 2]     = hex[(digest[hi] >> 4) & 0xf];
                    got_fp[hi * 2 + 1] = hex[digest[hi] & 0xf];
                }
                got_fp[64] = '\0';
            }
            int diff = 0, hi;
            for (hi = 0; hi < 64; hi++)
                diff |= got_fp[hi] ^ cosigner_fp_canon[hi];
            if (diff != 0) {
                LOG("ERROR: step-2 COSIGNER_FP_MISMATCH — possible "
                    "MitM on port 8445.\n"
                    "       expected: sha3-256:%s\n"
                    "       got:      sha3-256:%s",
                    cosigner_fp_canon, got_fp);
                json_object_put(resp);
                goto done;
            }

            /* Reconstruct the 113-byte signed message and ML-DSA-87
             * verify under the now-fingerprint-trusted PEM. */
            unsigned char sig_msg[CURVE25519_KEYSIZE * 2 + SALT_SZ +
                                  BOOTSTRAP_POP_NONCE_SZ + 1];
            unsigned int  sig_msg_len = 0;
            unsigned char pop_nonce_bin[BOOTSTRAP_POP_NONCE_SZ];
            if (hex_to_bytes(pop_nonce_hex, pop_nonce_bin,
                             BOOTSTRAP_POP_NONCE_SZ)
                != BOOTSTRAP_POP_NONCE_SZ) {
                LOG("ERROR: pop_nonce hex decode failed");
                json_object_put(resp);
                goto done;
            }
            memcpy(sig_msg + sig_msg_len, my_pub, CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, server_pub, CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, salt, SALT_SZ);
            sig_msg_len += SALT_SZ;
            memcpy(sig_msg + sig_msg_len, pop_nonce_bin,
                   BOOTSTRAP_POP_NONCE_SZ);
            sig_msg_len += BOOTSTRAP_POP_NONCE_SZ;
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
        } else {
            LOG("  DH transcript verification SKIPPED (--no-pin)");
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
        char ca_subject[512];

        /* CA subject convention: <domain>-ca */
        snprintf(ca_subject, sizeof(ca_subject), "%s-ca", subject);
        json_object_object_add(enroll, "subject",
            json_object_new_string(ca_subject));
        json_object_object_add(enroll, "public_key_pem",
            json_object_new_string(pub_key_pem));
        json_object_object_add(enroll, "key_algorithm",
            json_object_new_string(key_algo));
        json_object_object_add(enroll, "validity_days",
            json_object_new_int(validity_days));
        /* CA enrollment does not use an enrollment nonce — DNS TXT
         * is the proof of domain control, and the PoP signature
         * below proves possession of the CA private key. */

        /* CA-specific: add ca_certificate_pem in extensions */
        {
            struct json_object *ext = json_object_new_object();
            json_object_object_add(ext, "ca_certificate_pem",
                json_object_new_string(ca_cert_pem));
            json_object_object_add(ext, "is_ca",
                json_object_new_boolean(1));
            json_object_object_add(enroll, "extensions", ext);
        }

        /* Proof-of-possession (issue #5).  Compute SHA3-256 of
         * the SPKI DER from the local CA cert (same canonical
         * value the server will recompute), build the canonical
         * signed string, sign it under the CA private key with
         * ML-DSA-87/ctx=MTC_CA_POP_LABEL, and embed the hex
         * signature as `pop_signature`. */
        {
            unsigned char  cert_der[16384];
            int            cert_der_sz;
            unsigned char  spki_der[4096];
            word32         spki_sz = sizeof(spki_der);
            wc_Sha3        sha3;
            unsigned char  spki_h[WC_SHA3_256_DIGEST_SIZE];
            char           spki_hex[WC_SHA3_256_DIGEST_SIZE * 2 + 1];
            char           pop_msg[1024];
            int            pop_msg_len;
            char           *priv_pem = NULL;
            int            priv_pem_len = 0;
            unsigned char  priv_der[16384];
            int            priv_der_sz;
            dilithium_key  dil_priv;
            int            dil_priv_init = 0;
            unsigned char  pop_sig[DILITHIUM_LEVEL5_SIG_SIZE];
            word32         pop_sig_len = sizeof(pop_sig);
            char           pop_sig_hex[DILITHIUM_LEVEL5_SIG_SIZE * 2 + 1];
            int            pop_ok = 0;
            unsigned int   pi;

            cert_der_sz = wc_CertPemToDer(
                (const unsigned char *)ca_cert_pem,
                (int)strlen(ca_cert_pem),
                cert_der, (int)sizeof(cert_der), CERT_TYPE);
            if (cert_der_sz <= 0) {
                LOG("ERROR: PoP cert PEM->DER failed (%d)", cert_der_sz);
                goto pop_done;
            }
            if (wc_GetSubjectPubKeyInfoDerFromCert(
                    cert_der, (word32)cert_der_sz,
                    spki_der, &spki_sz) != 0) {
                LOG("ERROR: PoP SPKI extract failed");
                goto pop_done;
            }
            wc_InitSha3_256(&sha3, NULL, INVALID_DEVID);
            wc_Sha3_256_Update(&sha3, spki_der, spki_sz);
            wc_Sha3_256_Final(&sha3, spki_h);
            wc_Sha3_256_Free(&sha3);
            for (pi = 0; pi < WC_SHA3_256_DIGEST_SIZE; pi++)
                snprintf(spki_hex + pi * 2, 3, "%02x", spki_h[pi]);
            spki_hex[WC_SHA3_256_DIGEST_SIZE * 2] = '\0';

            pop_msg_len = snprintf(pop_msg, sizeof(pop_msg),
                "%s|%s|%s|%s|%s",
                MTC_CA_POP_PREFIX, subject, ca_subject,
                spki_hex, pop_nonce_hex);
            if (pop_msg_len <= 0 ||
                pop_msg_len >= (int)sizeof(pop_msg)) {
                LOG("ERROR: PoP msg too large");
                goto pop_done;
            }

            priv_pem_len = read_file(priv_key_path, &priv_pem);
            if (priv_pem_len <= 0 || !priv_pem) {
                LOG("ERROR: cannot read private key %s", priv_key_path);
                goto pop_done;
            }
            priv_der_sz = wc_KeyPemToDer(
                (const unsigned char *)priv_pem, priv_pem_len,
                priv_der, (int)sizeof(priv_der), NULL);
            if (priv_der_sz <= 0) {
                LOG("ERROR: PoP priv PEM->DER failed (%d)", priv_der_sz);
                goto pop_done;
            }
            wc_dilithium_init(&dil_priv);
            dil_priv_init = 1;
            wc_dilithium_set_level(&dil_priv, WC_ML_DSA_87);
            {
                word32 idx = 0;
                if (wc_Dilithium_PrivateKeyDecode(priv_der, &idx,
                        &dil_priv, (word32)priv_der_sz) != 0) {
                    LOG("ERROR: ML-DSA-87 priv decode failed");
                    goto pop_done;
                }
            }

            if (wc_dilithium_sign_ctx_msg(
                    (const byte *)MTC_CA_POP_LABEL,
                    MTC_CA_POP_LABEL_LEN,
                    (const byte *)pop_msg, (word32)pop_msg_len,
                    pop_sig, &pop_sig_len,
                    &dil_priv, &rng) != 0) {
                LOG("ERROR: PoP signature failed");
                goto pop_done;
            }
            for (pi = 0; pi < pop_sig_len; pi++)
                snprintf(pop_sig_hex + pi * 2, 3, "%02x", pop_sig[pi]);
            pop_sig_hex[pop_sig_len * 2] = '\0';

            json_object_object_add(enroll, "pop_signature",
                json_object_new_string(pop_sig_hex));
            LOG("PoP signature attached (%u bytes)", pop_sig_len);
            pop_ok = 1;

        pop_done:
            if (dil_priv_init) wc_dilithium_free(&dil_priv);
            if (priv_pem) {
                secure_zero((void *)priv_pem,
                            (unsigned int)priv_pem_len);
                free(priv_pem);
            }
            secure_zero(priv_der, sizeof(priv_der));
            if (!pop_ok) {
                json_object_put(enroll);
                goto done;
            }
        }

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

        /* P0 / TODO #9b CA branch — verify the bootstrap response
         * before trusting any of its other fields.  Same shape as
         * bootstrap_leaf's verify, but the operator-pasted
         * fingerprint is replaced by a DNSSEC-fetched one (or
         * skipped under --no-pin for localhost self-bootstrap).
         * Algo difference vs leaf: leaf compares SHA-256 against
         * an operator paste; CA compares SHA3-256 against the
         * DNS TXT (matching the existing _mqc-ca. convention).
         * Signature verification is identical — same ML-DSA-87
         * verify under MTC_BOOTSTRAP_LABEL ctx. */
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
            /* Stack copy of sig hex (json_object_object_del below
             * frees the original).  ML-DSA-87 hex sig is 9254
             * chars + NUL; 16 KB is comfortable. */
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

            /* Convert PEM → SPKI DER once; reuse for both the
             * fingerprint check and the signature verify. */
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

            /* Fingerprint check (skipped under --no-pin). */
            if (cosigner_fp_canon[0]) {
                unsigned char digest[32];
                wc_Sha3 sha;
                wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
                wc_Sha3_256_Update(&sha, spki_der, (word32)spki_der_sz);
                wc_Sha3_256_Final(&sha, digest);
                wc_Sha3_256_Free(&sha);
                char got_fp[65];
                {
                    static const char hexdigits[] = "0123456789abcdef";
                    int hi;
                    for (hi = 0; hi < 32; hi++) {
                        got_fp[hi * 2]     = hexdigits[(digest[hi] >> 4) & 0xf];
                        got_fp[hi * 2 + 1] = hexdigits[digest[hi] & 0xf];
                    }
                    got_fp[64] = '\0';
                }
                int diff = 0, hi;
                for (hi = 0; hi < 64; hi++)
                    diff |= got_fp[hi] ^ cosigner_fp_canon[hi];
                if (diff != 0) {
                    LOG("ERROR: COSIGNER_FP_MISMATCH — possible MitM "
                        "on port 8445.\n"
                        "       expected: sha3-256:%s\n"
                        "       got:      sha3-256:%s\n"
                        "       (the DNSSEC-pinned _mqc-cosigner.%s pin "
                        "does NOT match the response's ca_cosigner_pem)",
                        cosigner_fp_canon, got_fp, server_host);
                    json_object_put(resp);
                    goto done;
                }
                LOG("  cosigner fingerprint matches (sha3-256:%s)", got_fp);
            } else {
                LOG("  cosigner fingerprint check SKIPPED (--no-pin)");
            }

            /* Signature verify.  TODO #11 — the signed bytes are a
             * fixed binary transcript built by
             * mtc_bootstrap_response_transcript from the response's
             * structured fields.  No canonical-JSON contract
             * between signer and verifier. */
            unsigned char to_verify[MTC_BOOTSTRAP_TRANSCRIPT_MAX];
            size_t        to_verify_len = 0;
            if (mtc_bootstrap_response_transcript(resp,
                    to_verify, sizeof(to_verify),
                    &to_verify_len) != 0) {
                LOG("ERROR: failed to build response transcript "
                    "for verification");
                json_object_put(resp);
                goto done;
            }

            if ((response_sig_hex_len & 1) != 0) {
                LOG("ERROR: ca_response_sig is not even-length hex "
                    "(len=%d)", response_sig_hex_len);
                json_object_put(resp);
                goto done;
            }
            int sig_bin_len = response_sig_hex_len / 2;
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
                            to_verify,
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
                    "PEM whose fingerprint matched the parent's "
                    "DNSSEC pin (rc=%d, verified=%d).  Refusing "
                    "to enroll.", verify_rc, verified);
                json_object_put(resp);
                goto done;
            }
            LOG("  bootstrap response signature verified under cosigner PEM");
        }

        if (json_object_object_get_ex(resp, "index", &val)) {
            int cert_index = json_object_get_int(val);
            LOG("certificate issued at index %d", cert_index);

            /* --- Step 6: Save to TPM --- */
            if (g_trial_run) {
                LOG("DRY RUN: would save to %s/<subject>/", tpm_dir);
                LOG("DRY RUN: certificate JSON:\n%s",
                    json_object_to_json_string_ext(resp,
                        JSON_C_TO_STRING_PRETTY));
            } else {
                char ca_subj_save[512];
                snprintf(ca_subj_save, sizeof(ca_subj_save), "%s-ca", subject);
                if (save_to_tpm(tpm_dir, ca_subj_save, label_arg,
                        make_default,
                        json_object_to_json_string_ext(resp,
                            JSON_C_TO_STRING_PRETTY),
                        cert_index, pub_key_path, priv_key_path,
                        ca_cert_path, ca_cosigner_pem) == 0) {
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

    /* Server-side enrollment already wrote the CA pubkey to Neon
     * (mtc_bootstrap.c:1367 mtc_db_save_public_key) — the client
     * doesn't (and shouldn't) have Neon credentials, so the prior
     * client-side mtc_store_public_key() call was vestigial and just
     * produced a noisy "MERKLE_NEON not found, skipping key store"
     * message on every CA-side enrollment.  Removed. */

    LOG("enrollment complete!");
    exit_code = 0;

done:
    if (pub_key_pem) free(pub_key_pem);
    if (ca_cert_pem) free(ca_cert_pem);
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
