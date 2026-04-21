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
#include "mtc_pubkey_db.h"

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

#include <json-c/json.h>

#define HKDF_INFO        "mtc-dh-bootstrap"
#define SALT_SZ          16
#define AES_KEY_SZ       16
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
                       const char *pub_key_path, const char *priv_key_path)
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
    uint8_t aes_key[AES_KEY_SZ];

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

    /* Default --server to factsorlie.com:8445 */
    if (!server_arg)
        server_arg = "factsorlie.com:8445";

    /* Default paths from ~/.mtc-ca-data/<domain>/ if not specified */
    {
        static char def_pub[512], def_priv[512], def_nonce_path[512];
        static char nonce_buf[128];
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
        if (!nonce) {
            FILE *nf;
            snprintf(def_nonce_path, sizeof(def_nonce_path),
                     "%s/.mtc-ca-data/%s/nonce.txt", home, subject);
            nf = fopen(def_nonce_path, "r");
            if (nf) {
                if (fgets(nonce_buf, sizeof(nonce_buf), nf)) {
                    /* Strip trailing newline */
                    char *nl = strchr(nonce_buf, '\n');
                    if (nl) *nl = '\0';
                    nonce = nonce_buf;
                }
                fclose(nf);
            }
            if (!nonce) {
                fprintf(stderr, "Error: no --nonce given and no nonce.txt "
                        "found at %s\n"
                        "Run issue_leaf_nonce.py --domain %s first\n",
                        def_nonce_path, subject);
                return 1;
            }
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

        json_object_put(resp);
    }
    LOG("server DH public key + salt received");

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

    /* --- Derive AES key via HKDF --- */
    if (wc_HKDF(WC_SHA256, shared_secret, shared_sz,
                 salt, SALT_SZ,
                 (const byte *)HKDF_INFO, (word32)strlen(HKDF_INFO),
                 aes_key, AES_KEY_SZ) != 0) {
        LOG("ERROR: HKDF key derivation failed");
        goto done;
    }
    LOG("AES key derived via HKDF");

    /* --- Init encryption --- */
    crypt_ctx = mtc_crypt_init(aes_key, AES_KEY_SZ);
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
        if (mtc_crypt_encode(crypt_ctx, (unsigned char *)enroll_str,
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
    if (mtc_crypt_decode(crypt_ctx, enc_buf, (unsigned int)ret,
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
                        cert_index, pub_key_path, priv_key_path) == 0) {
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

    /* Store public key in Neon mtc_public_keys table */
    if (!g_trial_run && pub_key_pem)
        mtc_store_public_key(subject, pub_key_pem);

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
    secure_zero(aes_key, sizeof(aes_key));
    secure_zero(salt, sizeof(salt));
    wolfSSL_Cleanup();
    return exit_code;
}
