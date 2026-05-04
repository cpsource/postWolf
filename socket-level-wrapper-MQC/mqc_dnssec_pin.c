/*
 * mqc_dnssec_pin.c
 *
 * DNSSEC TXT lookup + MQC CA key hash pinning.
 *
 * Requires:
 *   sudo apt install libunbound-dev libssl-dev
 *
 * Build:
 *   gcc -Wall -Wextra -O2 mqc_dnssec_pin.c -lunbound -lcrypto -o mqc_dnssec_pin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include <unbound.h>
#include <openssl/evp.h>

#define MQC_MAX_TXT_LEN 4096
#define MQC_HASH_HEX_LEN 64

typedef enum {
    MQC_DNSSEC_OK = 0,
    MQC_DNSSEC_NO_DATA,
    MQC_DNSSEC_BOGUS,
    MQC_DNSSEC_INSECURE,
    MQC_DNSSEC_RESOLVE_ERROR,
    MQC_DNSSEC_PARSE_ERROR,
    MQC_DNSSEC_HASH_MISMATCH
} mqc_dnssec_status_t;

static int hex_encode(const unsigned char *in, size_t in_len,
                      char *out, size_t out_len)
{
    static const char hexdigits[] = "0123456789abcdef";

    if (out_len < (in_len * 2 + 1))
        return -1;

    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hexdigits[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hexdigits[in[i] & 0x0f];
    }

    out[in_len * 2] = '\0';
    return 0;
}

static int sha3_256_file_hex(const char *path, char out_hex[MQC_HASH_HEX_LEN + 1])
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    unsigned char buf[8192];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(fp);

    if (digest_len != 32)
        return -1;

    return hex_encode(digest, digest_len, out_hex, MQC_HASH_HEX_LEN + 1);
}

/*
 * DNS TXT RDATA format:
 *   one TXT RR can contain one or more length-prefixed character strings.
 *
 * This joins those strings into one C string.
 */
static int join_txt_rdata(const unsigned char *rdata, int len,
                          char *out, size_t out_len)
{
    size_t pos = 0;
    int i = 0;

    if (!rdata || len <= 0 || !out || out_len == 0)
        return -1;

    while (i < len) {
        unsigned int chunk_len = rdata[i++];

        if (i + (int)chunk_len > len)
            return -1;

        if (pos + chunk_len >= out_len)
            return -1;

        memcpy(out + pos, rdata + i, chunk_len);
        pos += chunk_len;
        i += chunk_len;
    }

    out[pos] = '\0';
    return 0;
}

static char *trim_left(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

static void trim_right(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[n - 1] = '\0';
        n--;
    }
}

/*
 * Extract kh=sha3-256:<hex> from:
 *
 *   v=MQC1; role=ca; alg=ML-DSA-87;
 *   kh=sha3-256:<HEX>; nonce=...; exp=...; sigalg=...; sig=...
 */
static int extract_kh_sha3_256(const char *txt,
                               char out_hex[MQC_HASH_HEX_LEN + 1])
{
    char tmp[MQC_MAX_TXT_LEN];

    if (!txt || strlen(txt) >= sizeof(tmp))
        return -1;

    strncpy(tmp, txt, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(tmp, ";", &saveptr);

    while (tok) {
        tok = trim_left(tok);
        trim_right(tok);

        const char *prefix = "kh=sha3-256:";
        size_t prefix_len = strlen(prefix);

        if (strncmp(tok, prefix, prefix_len) == 0) {
            const char *hex = tok + prefix_len;

            if (strlen(hex) != MQC_HASH_HEX_LEN)
                return -1;

            for (size_t i = 0; i < MQC_HASH_HEX_LEN; i++) {
                if (!isxdigit((unsigned char)hex[i]))
                    return -1;

                out_hex[i] = (char)tolower((unsigned char)hex[i]);
            }

            out_hex[MQC_HASH_HEX_LEN] = '\0';
            return 0;
        }

        tok = strtok_r(NULL, ";", &saveptr);
    }

    return -1;
}

/*
 * Fetch DNSSEC-validated TXT from _mqc-ca.<domain>.
 *
 * Important policy:
 *   result->secure must be true.
 *   result->bogus is fatal.
 *   secure=false && bogus=false means insecure/unsigned DNS, reject.
 */
static mqc_dnssec_status_t mqc_dnssec_fetch_ca_txt(const char *domain,
                                                   char *out_txt,
                                                   size_t out_txt_len)
{
    struct ub_ctx *ctx = NULL;
    struct ub_result *result = NULL;
    int rc;
    char qname[512];

    if (!domain || !out_txt || out_txt_len == 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (snprintf(qname, sizeof(qname), "_mqc-ca.%s", domain) >= (int)sizeof(qname))
        return MQC_DNSSEC_PARSE_ERROR;

    ctx = ub_ctx_create();
    if (!ctx)
        return MQC_DNSSEC_RESOLVE_ERROR;

    /*
     * Do NOT call ub_ctx_resolvconf(ctx, "/etc/resolv.conf") for MQC
     * bootstrap unless you intentionally trust your local resolver path.
     *
     * Without resolvconf, libunbound can act recursively itself.
     * NLnet Labs notes this is useful when you do not trust resolv.conf
     * servers or need DNSSEC validation.
     */

    rc = ub_ctx_add_ta_file(ctx, "/var/lib/unbound/root.key");
    if (rc != 0) {
        /*
         * Common alternatives:
         *   /usr/share/dns/root.key
         *   /etc/unbound/root.key
         */
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_RESOLVE_ERROR;
    }

    rc = ub_resolve(ctx, qname, 16 /* TXT */, 1 /* IN */, &result);
    if (rc != 0 || !result) {
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_RESOLVE_ERROR;
    }

    if (result->bogus) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_BOGUS;
    }

    if (!result->secure) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_INSECURE;
    }

    if (!result->havedata || !result->data || !result->data[0]) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_NO_DATA;
    }

    if (join_txt_rdata((const unsigned char *)result->data[0],
                       result->len[0],
                       out_txt,
                       out_txt_len) != 0) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_PARSE_ERROR;
    }

    ub_resolve_free(result);
    ub_ctx_delete(ctx);

    return MQC_DNSSEC_OK;
}

/*
 * Main drop-in function:
 *
 *   domain:            "foobar.com"
 *   ca_pubkey_path:    path to fetched/staged CA public key
 *
 * Returns MQC_DNSSEC_OK only if:
 *   - DNSSEC validation succeeds
 *   - TXT record exists
 *   - kh=sha3-256:<hash> is present
 *   - hash(public-key-file) matches DNS TXT hash
 */
mqc_dnssec_status_t mqc_pin_ca_key_from_dnssec(const char *domain,
                                               const char *ca_pubkey_path)
{
    char txt[MQC_MAX_TXT_LEN];
    char dns_hash[MQC_HASH_HEX_LEN + 1];
    char file_hash[MQC_HASH_HEX_LEN + 1];

    mqc_dnssec_status_t st =
        mqc_dnssec_fetch_ca_txt(domain, txt, sizeof(txt));

    if (st != MQC_DNSSEC_OK)
        return st;

    if (extract_kh_sha3_256(txt, dns_hash) != 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (sha3_256_file_hex(ca_pubkey_path, file_hash) != 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (strcmp(dns_hash, file_hash) != 0)
        return MQC_DNSSEC_HASH_MISMATCH;

    return MQC_DNSSEC_OK;
}

const char *mqc_dnssec_status_string(mqc_dnssec_status_t st)
{
    switch (st) {
    case MQC_DNSSEC_OK:
        return "OK";
    case MQC_DNSSEC_NO_DATA:
        return "No TXT data";
    case MQC_DNSSEC_BOGUS:
        return "DNSSEC bogus/tampered";
    case MQC_DNSSEC_INSECURE:
        return "DNSSEC insecure or unsigned";
    case MQC_DNSSEC_RESOLVE_ERROR:
        return "DNS resolution error";
    case MQC_DNSSEC_PARSE_ERROR:
        return "Parse/hash error";
    case MQC_DNSSEC_HASH_MISMATCH:
        return "CA public key hash mismatch";
    default:
        return "Unknown error";
    }
}

#ifdef MQC_DNSSEC_PIN_TEST
int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <domain> <ca_pubkey_file>\n", argv[0]);
        return 2;
    }

    mqc_dnssec_status_t st =
        mqc_pin_ca_key_from_dnssec(argv[1], argv[2]);

    printf("%s\n", mqc_dnssec_status_string(st));

    return st == MQC_DNSSEC_OK ? 0 : 1;
}
#endif
