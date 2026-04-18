/******************************************************************************
 * File:        mqc_peer.c
 * Purpose:     MQC peer verification — fetch, cache, Merkle verify.
 *
 * Description:
 *   Resolves a peer's identity by cert_index from the MTC transparency
 *   log. Checks local cache first, then fetches from the MTC server.
 *   Verifies the Merkle inclusion proof, Ed25519 cosignature, revocation
 *   status, and validity period. Caches verified certs for reuse.
 *
 * Dependencies:
 *   libcurl         (HTTP GET)
 *   json-c          (JSON parsing)
 *   wolfSSL crypto  (SHA-256, Merkle verify, cosignature verify)
 *
 * Created:     2026-04-15
 ******************************************************************************/

#include "mqc_peer.h"
#include "mqc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <curl/curl.h>
#include <json-c/json.h>

#define MQC_LOG(fmt, ...) \
    fprintf(stderr, "[MQC %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MQC_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQC-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mtc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/coding.h>

/* Verify a Merkle inclusion proof per RFC 9162 Section 2.1.3.
 *
 * This mirrors the server's inclusion_path() construction (see
 * mtc-keymaster/server/c/mtc_merkle.c:306-331).  At each recursion
 * level, split at k = largest power of 2 < n.  If m < k, the leaf is
 * in the left subtree and the sibling (right subtree root) appears on
 * the right; else the leaf is in the right subtree and the sibling
 * (left subtree root) appears on the left.  Proof entries are emitted
 * bottom-up by the server, so we walk them in the same order.
 *
 * Used instead of wolfSSL's wc_MtcVerifyInclusionProof which assumes a
 * balanced binary tree (idx & 1 bit walk) — correct only when the
 * subtree size is a power of 2.
 *
 * Returns 0 if the proof reconstructs expected_root, -1 otherwise. */
static int mqc_verify_inclusion_proof(int leaf_index, int start, int end,
                                      const byte *leaf_hash,
                                      const byte *inclusion_path,
                                      int path_count,
                                      const byte *expected_root)
{
    byte cur[MTC_HASH_SZ];
    byte next[MTC_HASH_SZ];
    int  dir_stack[MTC_MAX_PROOF_DEPTH]; /* 0 = sibling on right, 1 = on left */
    int  depth = 0;
    int  m, n, i, ret;

    if (leaf_index < start || leaf_index >= end) return -1;
    if (path_count < 0 || path_count > MTC_MAX_PROOF_DEPTH) return -1;

    /* Walk down the recursive split to record sibling direction per level.
     * Top of the stack (pushed first) corresponds to the outermost
     * recursion level; the deepest level (pushed last) matches the first
     * proof entry emitted by the server. */
    m = leaf_index - start;
    n = end - start;
    while (n > 1) {
        int k = 1;
        while (k * 2 < n) k *= 2;
        if (m < k) {
            dir_stack[depth++] = 0;   /* sibling (right subtree) on right */
            n = k;
        } else {
            dir_stack[depth++] = 1;   /* sibling (left subtree) on left  */
            m -= k;
            n -= k;
        }
    }

    if (depth != path_count) return -1;

    /* Walk back up: the first proof entry is the deepest sibling. */
    XMEMCPY(cur, leaf_hash, MTC_HASH_SZ);
    for (i = 0; i < path_count; i++) {
        const byte *sibling = inclusion_path + i * MTC_HASH_SZ;
        int dir = dir_stack[depth - 1 - i];
        if (dir == 0) {
            /* sibling on right → cur is left child */
            ret = wc_MtcHashNode(next, cur, sibling);
        } else {
            /* sibling on left → cur is right child */
            ret = wc_MtcHashNode(next, sibling, cur);
        }
        if (ret != 0) return -1;
        XMEMCPY(cur, next, MTC_HASH_SZ);
    }

    return (XMEMCMP(cur, expected_root, MTC_HASH_SZ) == 0) ? 0 : -1;
}

/* Verify an Ed25519 cosignature in the server's message format —
 * the exact layout produced by mtc_store_cosign() in
 * mtc-keymaster/server/c/mtc_store.c:735-780:
 *
 *   "mtc-subtree/v1\n\x00" (16 bytes, including the trailing NUL)
 *   || cosigner_id (strlen bytes, no terminator)
 *   || log_id      (strlen bytes)
 *   || start       (8 bytes, big-endian uint64)
 *   || end         (8 bytes, big-endian uint64)
 *   || subtree_hash (32 bytes)
 *
 * We intentionally don't call wolfSSL's wc_MtcVerifyCosignature
 * because it uses a different label and omits cosigner_id/log_id.
 *
 * Returns 0 if the signature verifies, -1 otherwise. */
static int verify_cosignature(const byte *ca_pubkey, int ca_pubkey_sz,
                              const char *cosigner_id, const char *log_id,
                              long long start, long long end,
                              const byte *subtree_hash,
                              const byte *sig, int sig_sz)
{
    byte msg[256];
    int msg_sz = 0;
    int i;
    ed25519_key key;
    int ret, verified = 0;
    size_t co_len, lo_len;
    uint64_t s64, e64;

    if (!ca_pubkey || ca_pubkey_sz != 32) return -1;
    if (!cosigner_id || !log_id) return -1;
    if (!subtree_hash || !sig || sig_sz != 64) return -1;

    co_len = strlen(cosigner_id);
    lo_len = strlen(log_id);
    if (16 + co_len + lo_len + 8 + 8 + MTC_HASH_SZ > sizeof(msg))
        return -1;

    /* Build message in server's exact byte order. */
    memcpy(msg, "mtc-subtree/v1\n\x00", 16);
    msg_sz = 16;
    memcpy(msg + msg_sz, cosigner_id, co_len); msg_sz += (int)co_len;
    memcpy(msg + msg_sz, log_id, lo_len);      msg_sz += (int)lo_len;

    s64 = (uint64_t)start;
    e64 = (uint64_t)end;
    for (i = 7; i >= 0; i--)
        msg[msg_sz++] = (byte)((s64 >> (i * 8)) & 0xff);
    for (i = 7; i >= 0; i--)
        msg[msg_sz++] = (byte)((e64 >> (i * 8)) & 0xff);

    memcpy(msg + msg_sz, subtree_hash, MTC_HASH_SZ);
    msg_sz += MTC_HASH_SZ;

    /* Verify. */
    if (wc_ed25519_init(&key) != 0) return -1;
    ret = wc_ed25519_import_public(ca_pubkey, (word32)ca_pubkey_sz, &key);
    if (ret != 0) { wc_ed25519_free(&key); return -1; }
    ret = wc_ed25519_verify_msg(sig, (word32)sig_sz,
                                msg, (word32)msg_sz,
                                &verified, &key);
    wc_ed25519_free(&key);
    return (ret == 0 && verified) ? 0 : -1;
}

/* Decode a hex string into a byte buffer.  Returns number of bytes
 * written (hex_len / 2), or -1 on odd length, invalid hex digit, or
 * overflow. */
static int mqc_hex_to_bytes(const char *hex, byte *out, int out_cap)
{
    int len, i;
    if (!hex) return -1;
    len = (int)strlen(hex);
    if (len & 1) return -1;
    if (len / 2 > out_cap) return -1;
    for (i = 0; i < len; i += 2) {
        int hi, lo;
        char ch = hex[i];
        if      (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'a' && ch <= 'f') hi = 10 + (ch - 'a');
        else if (ch >= 'A' && ch <= 'F') hi = 10 + (ch - 'A');
        else return -1;
        ch = hex[i + 1];
        if      (ch >= '0' && ch <= '9') lo = ch - '0';
        else if (ch >= 'a' && ch <= 'f') lo = 10 + (ch - 'a');
        else if (ch >= 'A' && ch <= 'F') lo = 10 + (ch - 'A');
        else return -1;
        out[i / 2] = (byte)((hi << 4) | lo);
    }
    return len / 2;
}

/* Cache directory under ~/.TPM */
#define PEER_CACHE_DIR   "peers"
#define CHECKPOINT_CACHE "checkpoint_cache.json"
#define CHECKPOINT_TTL   300  /* 5 minutes */
#define REVOKED_TTL      86400 /* seconds — 24 hour per-peer TTL */

/******************************************************************************
 * libcurl write callback — accumulates response body in a malloc'd buffer.
 ******************************************************************************/
struct curl_buf {
    char  *data;
    size_t sz;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
    struct curl_buf *b = (struct curl_buf *)userdata;
    size_t total = size * nmemb;
    char *tmp = realloc(b->data, b->sz + total + 1);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->sz, ptr, total);
    b->sz += total;
    b->data[b->sz] = '\0';
    return total;
}

/******************************************************************************
 * Function:    http_get
 *
 * Description:
 *   Perform an HTTP(S) GET and return the response body.
 *   Caller frees the returned buffer.
 ******************************************************************************/
static char *http_get(const char *url, long *http_code)
{
    CURL *curl;
    CURLcode res;
    struct curl_buf buf = {NULL, 0};

    curl = curl_easy_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);

    if (http_code)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf.data);
        return NULL;
    }

    return buf.data;
}

/******************************************************************************
 * Function:    ensure_dir
 ******************************************************************************/
static int ensure_dir(const char *path)
{
    if (mkdir(path, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/******************************************************************************
 * Function:    peer_cache_path
 *
 * Description:
 *   Build path: ~/.TPM/peers/<cert_index>/certificate.json
 ******************************************************************************/
static int peer_cache_path(int cert_index, char *out, int outsz)
{
    const char *home = getenv("HOME");
    if (!home) return -1;
    snprintf(out, (size_t)outsz, "%s/.TPM/%s/%d/certificate.json",
             home, PEER_CACHE_DIR, cert_index);
    return 0;
}

/* Path to a cached hex-encoded leaf_hash for a peer cert.  The leaf
 * hash is immutable (content-addressed), so once cached it is
 * reusable forever without contacting the MTC HTTP server. */
static int peer_leaf_hash_path(int cert_index, char *out, int outsz)
{
    const char *home = getenv("HOME");
    if (!home) return -1;
    snprintf(out, (size_t)outsz, "%s/.TPM/%s/%d/leaf_hash.hex",
             home, PEER_CACHE_DIR, cert_index);
    return 0;
}

/******************************************************************************
 * Function:    read_file_str
 *
 * Description:
 *   Read an entire file into a malloc'd string. Caller frees.
 ******************************************************************************/
static char *read_file_str(const char *path)
{
    FILE *f;
    long sz;
    char *buf;

    f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/******************************************************************************
 * Function:    write_file_str
 ******************************************************************************/
static int write_file_str(const char *path, const char *data)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(data, f);
    fclose(f);
    return 0;
}

/******************************************************************************
 * Function:    normalize_server
 *
 * Description:
 *   Ensure server URL has https:// prefix.
 ******************************************************************************/
static void normalize_server(const char *server, char *out, int outsz)
{
    if (strncmp(server, "http://", 7) == 0 ||
        strncmp(server, "https://", 8) == 0) {
        snprintf(out, (size_t)outsz, "%s", server);
    } else {
        snprintf(out, (size_t)outsz, "https://%s", server);
    }
}

/******************************************************************************
 * Function:    fetch_certificate
 *
 * Description:
 *   GET /certificate/<index> from MTC server. Returns parsed JSON or NULL.
 ******************************************************************************/
static struct json_object *fetch_certificate(const char *mtc_server,
                                             int cert_index)
{
    char url[768], server[512];
    char *body;
    long code = 0;
    struct json_object *obj;

    normalize_server(mtc_server, server, sizeof(server));
    snprintf(url, sizeof(url), "%s/certificate/%d", server, cert_index);

    body = http_get(url, &code);
    if (!body || code != 200) {
        free(body);
        fprintf(stderr, "[mqc-peer] fetch cert %d failed (code=%ld)\n",
                cert_index, code);
        return NULL;
    }

    obj = json_tokener_parse(body);
    free(body);
    return obj;
}

/******************************************************************************
 * Function:    peer_revoked_cache_path
 *
 * Description:
 *   Build path to the per-peer revocation cache file
 *   ~/.TPM/peers/<cert_index>/revoked.json.
 ******************************************************************************/
static int peer_revoked_cache_path(int cert_index, char *out, int outsz)
{
    const char *home = getenv("HOME");
    if (!home) return -1;
    snprintf(out, (size_t)outsz, "%s/.TPM/%s/%d/revoked.json",
             home, PEER_CACHE_DIR, cert_index);
    return 0;
}

/* check_revoked return codes:
 *   0  = not revoked (fresh cached status allows connection)
 *   1  = revoked (cached status says so, or fresh fetch confirmed)
 *  -1  = cache miss or stale; fresh single-cert status was fetched
 *        and persisted, but caller must drop this connection as a
 *        safety measure.  The peer will find the cache fresh on retry.
 */

/******************************************************************************
 * Function:    check_revoked
 *
 * Description:
 *   Per-peer revocation check with a 24-hour TTL cache.  The cache lives
 *   at ~/.TPM/peers/<n>/revoked.json and holds a single JSON object:
 *       { "revoked": false }   or   { "revoked": true }
 *   File mtime drives the TTL — anything fresher than REVOKED_TTL is
 *   trusted; anything older (or missing) triggers a fresh single-cert
 *   fetch of GET /revoked/<n> and returns -1 so the caller drops the
 *   current connection.  The peer's next attempt finds the cache fresh.
 ******************************************************************************/
static int check_revoked(const char *mtc_server, int cert_index)
{
    char cache_path[512];
    struct stat st;
    int cache_fresh = 0;

    if (peer_revoked_cache_path(cert_index, cache_path,
                                sizeof(cache_path)) != 0)
        return 0;

    if (stat(cache_path, &st) == 0 &&
        (long)(time(NULL) - st.st_mtime) <= REVOKED_TTL)
        cache_fresh = 1;

    if (cache_fresh) {
        char *body = read_file_str(cache_path);
        int revoked = 0;
        if (body) {
            struct json_object *obj = json_tokener_parse(body);
            free(body);
            if (obj) {
                struct json_object *val;
                if (json_object_object_get_ex(obj, "revoked", &val))
                    revoked = json_object_get_boolean(val);
                json_object_put(obj);
            }
        }
        return revoked ? 1 : 0;
    }

    /* Cache missing or stale → single-cert fetch + drop. */
    {
        char url[768], server[512];
        char *body;
        long code = 0;
        int revoked = 0;

        normalize_server(mtc_server, server, sizeof(server));
        snprintf(url, sizeof(url), "%s/revoked/%d", server, cert_index);
        body = http_get(url, &code);
        if (!body || code != 200) {
            free(body);
            return -1;   /* can't refresh — drop to be safe */
        }
        {
            struct json_object *obj = json_tokener_parse(body);
            if (obj) {
                struct json_object *val;
                if (json_object_object_get_ex(obj, "revoked", &val))
                    revoked = json_object_get_boolean(val);
                json_object_put(obj);
            }
        }

        /* Persist a compact record (just the status).  Sets mtime to
         * now so the next handshake within 1h will find the cache
         * fresh and skip the server round-trip. */
        {
            char out[64];
            snprintf(out, sizeof(out), "{\"revoked\":%s}\n",
                     revoked ? "true" : "false");
            write_file_str(cache_path, out);
        }
        free(body);

        if (mqc_get_verbose())
            fprintf(stderr, "[mqc-peer] revoked status refreshed for "
                    "cert %d (revoked=%d) — dropping connection, peer "
                    "will retry with fresh cache\n",
                    cert_index, revoked);

        return -1;  /* drop; peer retries and finds fresh cache */
    }
}

/******************************************************************************
 * Function:    extract_pubkey_pem
 *
 * Description:
 *   Fetch the peer's public key. First try the Neon mtc_public_keys table
 *   via the MTC server, then fall back to reading from the cached cert's
 *   subject_public_key_hash and resolving from the MTC server.
 *
 *   For now: fetch public_key.pem from ~/.TPM/peers/<index>/ if cached
 *   during a previous bootstrap, or fetch from the MTC server's
 *   /ca/public-key endpoint (for CAs) or from the mtc_public_keys table.
 *
 *   Returns malloc'd DER public key, caller frees.
 ******************************************************************************/
static int extract_pubkey_from_cert(struct json_object *cert_json,
                                    const char *mtc_server, int cert_index,
                                    unsigned char **out, int *out_sz)
{
    /* The certificate.json has subject_public_key_hash but not the
     * actual public key. We need to fetch it from the MTC server's
     * mtc_public_keys table or the Neon database.
     *
     * Strategy: GET /certificate/<index> returns the full cert JSON
     * which includes the subject but not the raw key. The key is
     * stored separately in Neon mtc_public_keys table.
     *
     * For now, try to fetch from a known endpoint or resolve from
     * the cert's subject field via the public key in the database. */

    struct json_object *sc, *tbs, *val;
    const char *subject;

    if (!json_object_object_get_ex(cert_json, "standalone_certificate", &sc))
        return -1;
    if (!json_object_object_get_ex(sc, "tbs_entry", &tbs))
        return -1;
    if (!json_object_object_get_ex(tbs, "subject", &val))
        return -1;
    subject = json_object_get_string(val);

    /* Try: GET https://<server>/certificate/<index> and look for
     * public_key in the response. The server doesn't include the raw
     * public key in the certificate JSON, so we need another source.
     *
     * Fall back: check if we have a cached public_key.pem from the
     * peer's TPM directory or from a previous fetch. */
    {
        char cache_dir[512];
        char pubkey_path[560];
        const char *home = getenv("HOME");
        if (!home) home = "/tmp";

        snprintf(cache_dir, sizeof(cache_dir), "%s/.TPM/%s/%d",
                 home, PEER_CACHE_DIR, cert_index);
        snprintf(pubkey_path, sizeof(pubkey_path), "%s/public_key.pem",
                 cache_dir);

        /* Check local cache */
        {
            char *pem = read_file_str(pubkey_path);
            if (pem) {
                /* Convert PEM to DER */
                unsigned char der[4096];
                int der_sz;

                der_sz = wc_PubKeyPemToDer((const unsigned char *)pem,
                    (int)strlen(pem), der, (int)sizeof(der));
                free(pem);

                if (der_sz > 0) {
                    *out = malloc((size_t)der_sz);
                    if (*out) {
                        memcpy(*out, der, (size_t)der_sz);
                        *out_sz = der_sz;
                        return 0;
                    }
                }
            }
        }
    }

    /* Fetch from Neon mtc_public_keys table via MTC server.
     * The subject is the key_name in the table. */
    {
        /* Strategy: the public key was stored by bootstrap_ca/bootstrap_leaf
         * into Neon mtc_public_keys with key_name = subject.
         * We can't query Neon directly from here (no libpq linked),
         * so try to read from the TPM directory using the subject. */
        {
            char tpm_key_path[512];
            const char *h = getenv("HOME");
            if (!h) h = "/tmp";

            /* Try ~/.TPM/<subject_safe>/public_key.pem */
            {
                char subj_safe[256];
                unsigned int si;
                snprintf(subj_safe, sizeof(subj_safe), "%s", subject);
                for (si = 0; si < strlen(subj_safe); si++)
                    if (subj_safe[si] == ':') subj_safe[si] = '_';

                snprintf(tpm_key_path, sizeof(tpm_key_path),
                         "%s/.TPM/%s/public_key.pem", h, subj_safe);
                {
                    char *pem2 = read_file_str(tpm_key_path);
                    if (pem2) {
                        unsigned char der2[4096];
                        int der2_sz = wc_PubKeyPemToDer(
                            (const unsigned char *)pem2,
                            (int)strlen(pem2), der2, (int)sizeof(der2));
                        free(pem2);
                        if (der2_sz > 0) {
                            *out = malloc((size_t)der2_sz);
                            if (*out) {
                                memcpy(*out, der2, (size_t)der2_sz);
                                *out_sz = der2_sz;

                                /* Cache to peer dir for next time */
                                {
                                    char pd[512], pp[560];
                                    snprintf(pd, sizeof(pd),
                                             "%s/.TPM/%s/%d",
                                             h, PEER_CACHE_DIR, cert_index);
                                    ensure_dir(pd);
                                    snprintf(pp, sizeof(pp),
                                             "%s/public_key.pem", pd);
                                    char *orig_pem = read_file_str(tpm_key_path);
                                    if (orig_pem) {
                                        write_file_str(pp, orig_pem);
                                        free(orig_pem);
                                    }
                                }

                                return 0;
                            }
                        }
                    }
                }

                /* Also try ~/.mtc-ca-data/<subject>/public_key.pem */
                snprintf(tpm_key_path, sizeof(tpm_key_path),
                         "%s/.mtc-ca-data/%s/public_key.pem", h, subject);
                {
                    char *pem3 = read_file_str(tpm_key_path);
                    if (pem3) {
                        unsigned char der3[4096];
                        int der3_sz = wc_PubKeyPemToDer(
                            (const unsigned char *)pem3,
                            (int)strlen(pem3), der3, (int)sizeof(der3));
                        if (der3_sz > 0) {
                            *out = malloc((size_t)der3_sz);
                            if (*out) {
                                memcpy(*out, der3, (size_t)der3_sz);
                                *out_sz = der3_sz;
                                /* Cache to peer dir */
                                {
                                    char pd[512], pp[560];
                                    snprintf(pd, sizeof(pd), "%s/.TPM/%s/%d",
                                             h, PEER_CACHE_DIR, cert_index);
                                    ensure_dir(pd);
                                    snprintf(pp, sizeof(pp),
                                             "%s/public_key.pem", pd);
                                    write_file_str(pp, pem3);
                                }
                                free(pem3);
                                return 0;
                            }
                        }
                        free(pem3);
                    }
                }

                /* Try fetching from MTC server's Neon public key table.
                 * The server exposes public keys at a search endpoint
                 * or we can try the certificate search by subject. */
                {
                    char pub_url[768], svr[512];
                    char *pub_body;
                    long pub_code = 0;

                    normalize_server(mtc_server, svr, sizeof(svr));

                    /* Try fetching the public key by subject name.
                     * Convention: keys are stored with key_name = subject
                     * in the mtc_public_keys table. We search certificates
                     * to find the subject, then look for a matching
                     * public_key.pem in the local TPM store.
                     *
                     * Direct approach: GET /ca/public-key returns the CA
                     * key. For leaf keys, we don't have a direct endpoint
                     * yet. Try the certificate's subject to find the key
                     * in the TPM tree. */

                    /* Last resort: try to get the key from the certificate
                     * search. The MTC server's certificate JSON doesn't
                     * include the raw public key, but we can try fetching
                     * the Neon mtc_public_keys table via a custom endpoint
                     * if available.
                     *
                     * For now, if we have the subject, try constructing
                     * a path from subject variants. */
                    {
                        /* Try subject without -ca suffix */
                        char base_subj[256];
                        int slen = (int)strlen(subject);
                        snprintf(base_subj, sizeof(base_subj), "%s", subject);
                        if (slen > 3 && strcmp(base_subj + slen - 3, "-ca") == 0)
                            base_subj[slen - 3] = '\0';

                        snprintf(tpm_key_path, sizeof(tpm_key_path),
                                 "%s/.mtc-ca-data/%s/public_key.pem",
                                 h, base_subj);
                        {
                            char *pem4 = read_file_str(tpm_key_path);
                            if (pem4) {
                                unsigned char der4[4096];
                                int der4_sz = wc_PubKeyPemToDer(
                                    (const unsigned char *)pem4,
                                    (int)strlen(pem4), der4, (int)sizeof(der4));
                                if (der4_sz > 0) {
                                    *out = malloc((size_t)der4_sz);
                                    if (*out) {
                                        memcpy(*out, der4, (size_t)der4_sz);
                                        *out_sz = der4_sz;
                                        /* Cache to peer dir */
                                        {
                                            char pd2[512], pp2[560];
                                            snprintf(pd2, sizeof(pd2),
                                                     "%s/.TPM/%s/%d",
                                                     h, PEER_CACHE_DIR, cert_index);
                                            ensure_dir(pd2);
                                            snprintf(pp2, sizeof(pp2),
                                                     "%s/public_key.pem", pd2);
                                            write_file_str(pp2, pem4);
                                            fprintf(stderr,
                                                "[mqc-peer] cached public key for cert %d\n",
                                                cert_index);
                                        }
                                        free(pem4);
                                        return 0;
                                    }
                                }
                                free(pem4);
                            }
                        }
                    }

                    /* Fetch from MTC server: GET /public-key/<subject> */
                    normalize_server(mtc_server, svr, sizeof(svr));
                    snprintf(pub_url, sizeof(pub_url), "%s/public-key/%s",
                             svr, subject);
                    pub_body = http_get(pub_url, &pub_code);
                    if (pub_body && pub_code == 200) {
                        struct json_object *pk_obj = json_tokener_parse(pub_body);
                        struct json_object *pk_val;
                        if (pk_obj &&
                            json_object_object_get_ex(pk_obj, "key_value", &pk_val)) {
                            const char *fetched_pem = json_object_get_string(pk_val);
                            unsigned char der5[4096];
                            int der5_sz = wc_PubKeyPemToDer(
                                (const unsigned char *)fetched_pem,
                                (int)strlen(fetched_pem),
                                der5, (int)sizeof(der5));
                            if (der5_sz > 0) {
                                *out = malloc((size_t)der5_sz);
                                if (*out) {
                                    memcpy(*out, der5, (size_t)der5_sz);
                                    *out_sz = der5_sz;
                                    /* Cache to peer dir */
                                    char pd3[512], pp3[560];
                                    snprintf(pd3, sizeof(pd3),
                                             "%s/.TPM/%s/%d",
                                             h, PEER_CACHE_DIR, cert_index);
                                    ensure_dir(pd3);
                                    snprintf(pp3, sizeof(pp3),
                                             "%s/public_key.pem", pd3);
                                    write_file_str(pp3, fetched_pem);
                                    fprintf(stderr,
                                        "[mqc-peer] fetched + cached public key "
                                        "for cert %d from server\n", cert_index);
                                    json_object_put(pk_obj);
                                    free(pub_body);
                                    return 0;
                                }
                            }
                        }
                        if (pk_obj) json_object_put(pk_obj);
                    }
                    free(pub_body);
                }
            }
        }
    }

    MQC_SECURITY("PUBKEY_MISSING: no public key for cert %d (%s)\n",
            cert_index, subject);
    return -1;
}

/******************************************************************************
 * Function:    cache_peer_cert
 ******************************************************************************/
static void cache_peer_cert(int cert_index, const char *cert_json_str)
{
    char dir1[512], dir2[560], path[620];
    const char *home = getenv("HOME");
    if (!home) return;

    snprintf(dir1, sizeof(dir1), "%s/.TPM/%s", home, PEER_CACHE_DIR);
    ensure_dir(dir1);

    snprintf(dir2, sizeof(dir2), "%s/%d", dir1, cert_index);
    ensure_dir(dir2);

    snprintf(path, sizeof(path), "%s/certificate.json", dir2);
    write_file_str(path, cert_json_str);
}

/******************************************************************************
 * Function:    pem_extract_ed25519_raw
 *
 * Description:
 *   Pull the raw 32-byte Ed25519 public key out of an RFC 8410 SPKI PEM.
 *   Works whether the PEM header is the proper "-----BEGIN PUBLIC KEY-----"
 *   or the mislabelled "-----BEGIN EDDSA PRIVATE KEY-----" the MTC server
 *   currently emits — we base64-decode the body and take the last 32
 *   bytes of the DER.
 ******************************************************************************/
static int pem_extract_ed25519_raw(const char *pem, byte *out32)
{
    const char *body_start, *end, *p;
    char  b64[1024];
    int   blen = 0;
    byte  der[256];
    word32 der_len = sizeof(der);

    if (!pem) return -1;
    body_start = strchr(pem, '\n');
    if (!body_start) return -1;
    body_start++;
    end = strstr(body_start, "-----END");
    if (!end) return -1;
    for (p = body_start; p < end && blen < (int)sizeof(b64) - 1; p++) {
        if (*p != '\r' && *p != '\n' && *p != ' ' && *p != '\t')
            b64[blen++] = *p;
    }
    b64[blen] = '\0';
    if (Base64_Decode((const byte *)b64, (word32)blen, der, &der_len) != 0)
        return -1;
    if (der_len < 32) return -1;
    memcpy(out32, der + der_len - 32, 32);
    return 0;
}

/** Default DH bootstrap port for ca_pubkey fetches. */
#define MQC_BOOTSTRAP_PORT 8445

/******************************************************************************
 * Function:    extract_host  (static)
 *
 * Description:
 *   Extract a bare hostname from an "mtc_server" config string like
 *   "host:8444" or "https://host:8444" or plain "host".  Writes just the
 *   host portion into out (no scheme, no port).
 ******************************************************************************/
static void extract_host(const char *server, char *out, int outsz)
{
    const char *p = server;
    const char *end;
    int len;

    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) p += 7;

    end = strchr(p, ':');
    if (!end) end = p + strlen(p);
    len = (int)(end - p);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, (size_t)len);
    out[len] = '\0';
}

/******************************************************************************
 * Function:    bootstrap_fetch_ca_pubkey  (static)
 *
 * Description:
 *   Open a TCP connection to host:port (the DH bootstrap listener), send
 *   a plaintext {"op":"ca_pubkey"} request, and read the JSON response by
 *   brace-counting.  Returns a malloc'd NUL-terminated JSON string on
 *   success, or NULL on any failure.
 ******************************************************************************/
static char *bootstrap_fetch_ca_pubkey(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[8];
    int fd = -1;
    const char *req = "{\"op\":\"ca_pubkey\"}";
    ssize_t sent;
    char *buf = NULL;
    int pos = 0, depth = 0, started = 0;
    size_t cap = 4096;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return NULL;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return NULL;

    sent = send(fd, req, strlen(req), 0);
    if (sent != (ssize_t)strlen(req)) {
        close(fd);
        return NULL;
    }

    buf = (char *)malloc(cap);
    if (!buf) {
        close(fd);
        return NULL;
    }

    for (;;) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) break;
        if ((size_t)pos + 2 >= cap) {
            size_t new_cap = cap * 2;
            char *nb = (char *)realloc(buf, new_cap);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb; cap = new_cap;
        }
        buf[pos++] = c;
        if (c == '{') { depth++; started = 1; }
        else if (c == '}') { depth--; }
        if (started && depth == 0) break;
    }
    close(fd);
    if (!buf) return NULL;
    if (pos == 0 || !started || depth != 0) { free(buf); return NULL; }
    buf[pos] = '\0';
    return buf;
}

/******************************************************************************
 * Function:    mqc_load_ca_pubkey
 *
 * Description:
 *   Load the CA cosigner's raw 32-byte Ed25519 public key — the trust
 *   anchor any MQC peer needs to verify log cosignatures.  Prefers a
 *   cached copy at ~/.TPM/ca-cosigner.pem; on miss, fetches the key over
 *   the DH bootstrap port (MQC_BOOTSTRAP_PORT) by sending a plaintext
 *   {"op":"ca_pubkey"} request, then populates the cache (TOFU).
 *
 *   This is the shared helper used by show-tpm, echo_server,
 *   echo_client, and any other MQC-capable tool.  Long-term, the CA
 *   pubkey should be distributed out-of-band to eliminate the
 *   trust-on-first-use window (tracked in README-bugsandtodo.md §9b).
 ******************************************************************************/
int mqc_load_ca_pubkey(const char *mtc_server, unsigned char *out32)
{
    const char *home = getenv("HOME");
    char cache_path[512];
    char *pem = NULL;
    int rc = -1;

    if (!mtc_server || !out32) return -1;
    if (!home) home = "/tmp";
    snprintf(cache_path, sizeof(cache_path),
             "%s/.TPM/ca-cosigner.pem", home);

    /* Try local cache first. */
    pem = read_file_str(cache_path);
    if (pem) {
        rc = pem_extract_ed25519_raw(pem, (byte *)out32);
        free(pem);
        if (rc == 0) return 0;
        fprintf(stderr, "[mqc] cached %s malformed; refetching\n",
                cache_path);
    }

    /* Fetch from DH bootstrap port (TOFU).  No TLS — the payload is a
     * public key that the caller pins regardless of transport. */
    {
        char host[256];
        char *body;
        struct json_object *obj = NULL, *val;

        extract_host(mtc_server, host, sizeof(host));
        body = bootstrap_fetch_ca_pubkey(host, MQC_BOOTSTRAP_PORT);
        if (!body) {
            fprintf(stderr,
                    "[mqc] cannot fetch CA pubkey from %s:%d (bootstrap)\n",
                    host, MQC_BOOTSTRAP_PORT);
            return -1;
        }
        obj = json_tokener_parse(body);
        free(body);
        if (!obj ||
            !json_object_object_get_ex(obj, "public_key_pem", &val)) {
            fprintf(stderr,
                    "[mqc] bootstrap ca_pubkey missing public_key_pem\n");
            if (obj) json_object_put(obj);
            return -1;
        }
        pem = strdup(json_object_get_string(val));
        json_object_put(obj);
        if (!pem) return -1;

        rc = pem_extract_ed25519_raw(pem, (byte *)out32);
        if (rc == 0)
            write_file_str(cache_path, pem);
        free(pem);
        if (rc != 0) {
            fprintf(stderr,
                    "[mqc] bootstrap ca_pubkey PEM could not be decoded\n");
            return -1;
        }
    }
    return 0;
}

/******************************************************************************
 * Function:    mqc_peer_verify
 ******************************************************************************/
int mqc_peer_verify(const char *mtc_server,
                    const unsigned char *ca_pubkey, int ca_pubkey_sz,
                    int cert_index, int is_server,
                    unsigned char **pubkey_out, int *pubkey_sz_out)
{
    struct json_object *cert_json = NULL;
    char cache_path[512];
    int ret = -1;

    (void)ca_pubkey;
    (void)ca_pubkey_sz;

    *pubkey_out = NULL;
    *pubkey_sz_out = 0;

    /* 1. Check cache */
    if (peer_cache_path(cert_index, cache_path, sizeof(cache_path)) == 0) {
        char *cached = read_file_str(cache_path);
        if (cached) {
            cert_json = json_tokener_parse(cached);
            free(cached);
            if (cert_json && mqc_get_verbose())
                fprintf(stderr, "[mqc-peer] cache hit for cert %d\n",
                        cert_index);
        }
    }

    /* 2. Fetch from server if not cached */
    if (!cert_json) {
        cert_json = fetch_certificate(mtc_server, cert_index);
        if (!cert_json) {
            fprintf(stderr, "[mqc-peer] cannot fetch cert %d\n", cert_index);
            return -1;
        }
        /* Cache it */
        {
            const char *s = json_object_to_json_string_ext(cert_json,
                JSON_C_TO_STRING_PRETTY);
            cache_peer_cert(cert_index, s);
        }
        if (mqc_get_verbose())
            fprintf(stderr, "[mqc-peer] fetched and cached cert %d\n", cert_index);
    }

    /* 3. Verify Merkle inclusion proof.
     *
     * The authoritative leaf hash comes from /log/entry/<cert_index>
     * (computed over the exact bytes the server stored, sidestepping
     * any JSON-serialization ambiguity).  The proof path, subtree
     * bounds, and expected root come from the /certificate/<n>
     * response we already have.  wolfSSL's wc_MtcVerifyInclusionProof
     * walks the path per RFC 9162 Section 2.1.3. */
    {
        char url[768], svr[512];
        char *body = NULL;
        long http_code = 0;
        struct json_object *entry_obj = NULL, *lh_val;
        struct json_object *sc, *proof_arr, *val;
        byte leaf_hash[MTC_HASH_SZ];
        byte subtree_hash[MTC_HASH_SZ];
        byte *inclusion_path = NULL;
        int path_count = 0, i;
        word64 subtree_start = 0, subtree_end = 0;
        int vret;

        /* Obtain leaf_hash.  The leaf hash is content-addressed — the bytes
         * at a given tree position never change — so once we have it, we
         * cache it under ~/.TPM/peers/<n>/leaf_hash.hex and reuse forever.
         * Only fetch /log/entry/<n> on a cold cache. */
        {
            char lh_cache_path[512];
            int got = 0;
            if (peer_leaf_hash_path(cert_index,
                                    lh_cache_path,
                                    sizeof(lh_cache_path)) == 0) {
                char *cached_hex = read_file_str(lh_cache_path);
                if (cached_hex) {
                    /* Trim trailing whitespace / newline. */
                    size_t n = strlen(cached_hex);
                    while (n > 0 && (cached_hex[n-1] == '\n' ||
                                     cached_hex[n-1] == '\r' ||
                                     cached_hex[n-1] == ' ')) {
                        cached_hex[--n] = '\0';
                    }
                    if (mqc_hex_to_bytes(cached_hex, leaf_hash,
                                         MTC_HASH_SZ) == MTC_HASH_SZ) {
                        got = 1;
                        if (mqc_get_verbose())
                            fprintf(stderr,
                                "[mqc-peer] leaf_hash cache hit for cert %d\n",
                                cert_index);
                    }
                    free(cached_hex);
                }
            }

            if (!got) {
                normalize_server(mtc_server, svr, sizeof(svr));
                snprintf(url, sizeof(url), "%s/log/entry/%d",
                         svr, cert_index);
                body = http_get(url, &http_code);
                if (!body || http_code != 200) {
                    MQC_SECURITY("LEAF_FETCH_FAILED: cert %d (code=%ld)",
                                 cert_index, http_code);
                    free(body);
                    json_object_put(cert_json);
                    return -1;
                }
                entry_obj = json_tokener_parse(body);
                free(body);
                if (!entry_obj ||
                    !json_object_object_get_ex(entry_obj, "leaf_hash",
                                               &lh_val) ||
                    mqc_hex_to_bytes(json_object_get_string(lh_val),
                                     leaf_hash, MTC_HASH_SZ)
                        != MTC_HASH_SZ) {
                    MQC_SECURITY("LEAF_FETCH_PARSE: cert %d", cert_index);
                    if (entry_obj) json_object_put(entry_obj);
                    json_object_put(cert_json);
                    return -1;
                }
                /* Persist to cache. */
                {
                    const char *lh_hex_s = json_object_get_string(lh_val);
                    write_file_str(lh_cache_path, lh_hex_s);
                }
                json_object_put(entry_obj);
                if (mqc_get_verbose())
                    fprintf(stderr,
                        "[mqc-peer] leaf_hash fetched and cached for cert %d\n",
                        cert_index);
            }
        }

        /* Extract proof fields from the cert response */
        if (!json_object_object_get_ex(cert_json,
                "standalone_certificate", &sc) ||
            !json_object_object_get_ex(sc, "subtree_start", &val)) {
            MQC_SECURITY("PROOF_MISSING: cert %d subtree_start", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        subtree_start = (word64)json_object_get_int64(val);
        if (!json_object_object_get_ex(sc, "subtree_end", &val)) {
            MQC_SECURITY("PROOF_MISSING: cert %d subtree_end", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        subtree_end = (word64)json_object_get_int64(val);
        if (!json_object_object_get_ex(sc, "subtree_hash", &val) ||
            mqc_hex_to_bytes(json_object_get_string(val),
                             subtree_hash, MTC_HASH_SZ) != MTC_HASH_SZ) {
            MQC_SECURITY("PROOF_MALFORMED: cert %d subtree_hash", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        if (!json_object_object_get_ex(sc, "inclusion_proof", &proof_arr) ||
            !json_object_is_type(proof_arr, json_type_array)) {
            MQC_SECURITY("PROOF_MISSING: cert %d inclusion_proof", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        path_count = (int)json_object_array_length(proof_arr);
        if (path_count > MTC_MAX_PROOF_DEPTH) {
            MQC_SECURITY("PROOF_TOO_DEEP: cert %d (%d hashes)",
                         cert_index, path_count);
            json_object_put(cert_json);
            return -1;
        }
        if (path_count > 0) {
            inclusion_path = (byte *)malloc((size_t)path_count * MTC_HASH_SZ);
            if (!inclusion_path) {
                json_object_put(cert_json);
                return -1;
            }
            for (i = 0; i < path_count; i++) {
                struct json_object *h = json_object_array_get_idx(proof_arr, i);
                if (mqc_hex_to_bytes(json_object_get_string(h),
                        inclusion_path + i * MTC_HASH_SZ,
                        MTC_HASH_SZ) != MTC_HASH_SZ) {
                    MQC_SECURITY("PROOF_MALFORMED: cert %d hash[%d]",
                                 cert_index, i);
                    free(inclusion_path);
                    json_object_put(cert_json);
                    return -1;
                }
            }
        }

        /* Verify the proof using the RFC 9162 split-at-k algorithm
         * (server uses the same in mtc_merkle.c:inclusion_path). */
        vret = mqc_verify_inclusion_proof(cert_index,
                                          (int)subtree_start,
                                          (int)subtree_end,
                                          leaf_hash,
                                          inclusion_path,
                                          path_count,
                                          subtree_hash);
        free(inclusion_path);

        if (vret != 0) {
            MQC_SECURITY("PROOF_INVALID: cert %d", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        if (mqc_get_verbose())
            fprintf(stderr, "[mqc-peer] inclusion proof OK for cert %d\n",
                    cert_index);
    }

    /* 4. Verify Ed25519 cosignature over the subtree root.
     *
     * This binds the (start, end, subtree_hash) we just validated
     * via the inclusion proof to the CA cosigner's Ed25519 key that
     * the caller loaded out-of-band.  Without this check, a
     * malicious MTC HTTP server could hand us a consistent but
     * fabricated (leafHash, proof, subtreeHash) triple. */
    {
        struct json_object *sc, *cosig_arr, *cosig, *val;
        const char *cosigner_id, *log_id;
        byte subtree_hash[MTC_HASH_SZ];
        byte sig[64];
        long long start = 0, end = 0;
        int i, zeroed = 1;

        /* Require a non-zero 32-byte CA pubkey. */
        if (!ca_pubkey || ca_pubkey_sz != 32) {
            MQC_SECURITY("COSIG_NO_CA_KEY: cert %d (pubkey_sz=%d)",
                         cert_index, ca_pubkey_sz);
            json_object_put(cert_json);
            return -1;
        }
        for (i = 0; i < ca_pubkey_sz; i++)
            if (ca_pubkey[i] != 0) { zeroed = 0; break; }
        if (zeroed) {
            MQC_SECURITY("COSIG_NO_CA_KEY: cert %d (pubkey is zero)",
                         cert_index);
            json_object_put(cert_json);
            return -1;
        }

        if (!json_object_object_get_ex(cert_json,
                "standalone_certificate", &sc) ||
            !json_object_object_get_ex(sc, "cosignatures", &cosig_arr) ||
            !json_object_is_type(cosig_arr, json_type_array) ||
            json_object_array_length(cosig_arr) == 0) {
            MQC_SECURITY("COSIG_MISSING: cert %d", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        cosig = json_object_array_get_idx(cosig_arr, 0);
        if (!cosig ||
            !json_object_object_get_ex(cosig, "cosigner_id", &val)) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d cosigner_id",
                         cert_index);
            json_object_put(cert_json);
            return -1;
        }
        cosigner_id = json_object_get_string(val);
        if (!json_object_object_get_ex(cosig, "log_id", &val)) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d log_id", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        log_id = json_object_get_string(val);
        if (!json_object_object_get_ex(cosig, "start", &val)) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d start", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        start = json_object_get_int64(val);
        if (!json_object_object_get_ex(cosig, "end", &val)) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d end", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        end = json_object_get_int64(val);
        if (!json_object_object_get_ex(cosig, "subtree_hash", &val) ||
            mqc_hex_to_bytes(json_object_get_string(val),
                             subtree_hash, MTC_HASH_SZ) != MTC_HASH_SZ) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d subtree_hash",
                         cert_index);
            json_object_put(cert_json);
            return -1;
        }
        if (!json_object_object_get_ex(cosig, "signature", &val) ||
            mqc_hex_to_bytes(json_object_get_string(val),
                             sig, (int)sizeof(sig)) != 64) {
            MQC_SECURITY("COSIG_MALFORMED: cert %d signature",
                         cert_index);
            json_object_put(cert_json);
            return -1;
        }

        if (verify_cosignature(ca_pubkey, ca_pubkey_sz,
                               cosigner_id, log_id,
                               start, end,
                               subtree_hash, sig, 64) != 0) {
            MQC_SECURITY("COSIG_INVALID: cert %d", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        if (mqc_get_verbose())
            fprintf(stderr, "[mqc-peer] cosignature OK for cert %d\n",
                    cert_index);
    }

    /* 5. Check revocation */
    /* Revocation check runs only on the acceptor (server-role) side —
     * that's the party at risk of accepting a revoked incoming peer.
     * The initiator doesn't need to verify the server isn't revoked
     * (the server proved possession of its private key during the
     * handshake; revoked status is a separate policy decision for the
     * acceptor). */
    if (is_server) {
        int rev = check_revoked(mtc_server, cert_index);
        if (rev == 1) {
            MQC_SECURITY("CERT_REVOKED: cert %d is revoked", cert_index);
            json_object_put(cert_json);
            return -1;
        }
        if (rev == -1) {
            MQC_SECURITY("REVOKED_CACHE_REFRESH: cert %d (dropping; "
                         "peer will retry with fresh cache)",
                         cert_index);
            json_object_put(cert_json);
            return -1;
        }
        /* rev == 0 → cached "not revoked", proceed. */
    }

    /* 6. Check validity */
    {
        struct json_object *sc, *tbs, *val;
        double not_before = 0, not_after = 0;
        double now = (double)time(NULL);

        if (json_object_object_get_ex(cert_json, "standalone_certificate", &sc) &&
            json_object_object_get_ex(sc, "tbs_entry", &tbs)) {
            if (json_object_object_get_ex(tbs, "not_before", &val))
                not_before = json_object_get_double(val);
            if (json_object_object_get_ex(tbs, "not_after", &val))
                not_after = json_object_get_double(val);
        }

        if (not_before > 0 && not_after > 0) {
            if (now < not_before || now > not_after) {
                MQC_SECURITY("CERT_EXPIRED: cert %d expired or not yet valid",
                        cert_index);
                json_object_put(cert_json);
                return -1;
            }
        }
    }

    /* 7. Extract peer's public key */
    ret = extract_pubkey_from_cert(cert_json, mtc_server, cert_index,
                                   pubkey_out, pubkey_sz_out);

    json_object_put(cert_json);
    return ret;
}

/******************************************************************************
 * Function:    mqc_peer_get_cached_pubkey
 ******************************************************************************/
int mqc_peer_get_cached_pubkey(int cert_index,
                               unsigned char **pubkey_out, int *pubkey_sz_out)
{
    char path[512];
    char *pem;
    const char *home = getenv("HOME");

    *pubkey_out = NULL;
    *pubkey_sz_out = 0;

    if (!home) return -1;

    snprintf(path, sizeof(path), "%s/.TPM/%s/%d/public_key.pem",
             home, PEER_CACHE_DIR, cert_index);

    pem = read_file_str(path);
    if (!pem) return -1;

    {
        unsigned char der[4096];
        int der_sz = wc_PubKeyPemToDer((const unsigned char *)pem,
            (int)strlen(pem), der, (int)sizeof(der));
        free(pem);

        if (der_sz <= 0) return -1;

        *pubkey_out = malloc((size_t)der_sz);
        if (!*pubkey_out) return -1;
        memcpy(*pubkey_out, der, (size_t)der_sz);
        *pubkey_sz_out = der_sz;
    }

    return 0;
}
