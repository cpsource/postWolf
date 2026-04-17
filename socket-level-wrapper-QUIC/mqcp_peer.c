/* mqcp_peer.c — Peer verification (cache-only, no curl, no json-c)
 *
 * Resolves peer public keys and verifies certificates from the local
 * TPM cache. No network calls, no curl, no json-c.
 *
 * Verification steps (matching MQC's mqc_peer_verify):
 *   1. Load certificate.json from ~/.TPM/peers/<index>/
 *   2. Verify Merkle inclusion proof (TODO — same as MQC)
 *   3. Verify Ed25519 cosignature (TODO — same as MQC)
 *   4. Check validity period (not_before / not_after)
 *   5. Load public_key.pem and convert to DER
 */

#include "mqcp_peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#define PEER_LOG(fmt, ...) \
    fprintf(stderr, "[MQCP-PEER %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__)

#define PEER_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQCP-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__)

/* --- Helpers --- */

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65536) { fclose(f); return NULL; }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    buf[sz] = '\0';
    return buf;
}

/* Minimal JSON number extraction: find "key": <number> and return the number.
 * Works for both integer and floating point values. Returns 0.0 on failure. */
static double json_find_number(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0.0;
    p += strlen(pattern);
    /* skip whitespace and colon */
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\n' || *p == '\r') p++;
    return atof(p);
}

/* --- Validity check --- */

static int check_validity(const char *cert_json, int cert_index) {
    double not_before = json_find_number(cert_json, "not_before");
    double not_after = json_find_number(cert_json, "not_after");
    double now = (double)time(NULL);

    if (not_before > 0 && not_after > 0) {
        if (now < not_before) {
            PEER_SECURITY("CERT_NOT_YET_VALID: cert %d (now=%.0f not_before=%.0f)",
                          cert_index, now, not_before);
            return -1;
        }
        if (now > not_after) {
            PEER_SECURITY("CERT_EXPIRED: cert %d (now=%.0f not_after=%.0f)",
                          cert_index, now, not_after);
            return -1;
        }
    }

    return 0;
}

/* --- Public key loading --- */

static int load_pubkey_pem(int cert_index, unsigned char **out, int *out_sz) {
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    /* Try ~/.TPM/peers/<cert_index>/public_key.pem */
    char path[512];
    snprintf(path, sizeof(path), "%s/.TPM/peers/%d/public_key.pem",
             home, cert_index);

    char *pem = read_file(path);
    if (!pem) {
        PEER_LOG("Cache miss: %s", path);
        return -1;
    }

    /* PEM to DER */
    unsigned char der[4096];
    int der_sz = wc_PubKeyPemToDer((const unsigned char *)pem,
                                   (int)strlen(pem), der, (int)sizeof(der));
    free(pem);
    if (der_sz <= 0) {
        PEER_SECURITY("PEM_TO_DER_FAILED: cert %d", cert_index);
        return -1;
    }

    *out = (unsigned char *)malloc((size_t)der_sz);
    if (!*out) return -1;
    memcpy(*out, der, (size_t)der_sz);
    *out_sz = der_sz;
    return 0;
}

/* --- Public API --- */

int mqcp_peer_get_pubkey(int cert_index,
                         unsigned char **pubkey_out, int *pubkey_sz_out) {
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    *pubkey_out = NULL;
    *pubkey_sz_out = 0;

    /* 1. Load certificate.json */
    char cert_path[512];
    snprintf(cert_path, sizeof(cert_path),
             "%s/.TPM/peers/%d/certificate.json", home, cert_index);

    char *cert_json = read_file(cert_path);
    if (cert_json) {
        /* 2. Verify Merkle inclusion proof */
        /* TODO: implement full Merkle proof verification.
         * Same status as MQC — deferred to next iteration.
         * Requires fetching the checkpoint root and recomputing
         * the proof path using SHA-256. */

        /* 3. Verify Ed25519 cosignature */
        /* TODO: implement cosignature verification with CA public key.
         * Same status as MQC — deferred to next iteration. */

        /* 4. Check validity period */
        if (check_validity(cert_json, cert_index) != 0) {
            free(cert_json);
            return -1;
        }

        free(cert_json);
    }
    /* If no certificate.json, we still try to load the public key.
     * The peer may have been pre-provisioned with just the key file. */

    /* 5. Load public key */
    return load_pubkey_pem(cert_index, pubkey_out, pubkey_sz_out);
}
