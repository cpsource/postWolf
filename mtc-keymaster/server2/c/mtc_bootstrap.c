/******************************************************************************
 * File:        mtc_bootstrap.c
 * Purpose:     DH bootstrap port for pre-TLS leaf enrollment.
 *
 * Description:
 *   Listens on a dedicated TCP port and performs X25519 key exchange
 *   followed by AES-encrypted JSON enrollment via mtc_crypt.  This
 *   bypasses TLS entirely — the DH shared secret provides encryption
 *   and the nonce provides authorization.
 *
 *   Protocol:
 *     1. Client sends plaintext JSON:  {"dh_public_key":"<hex>"}
 *     2. Server sends plaintext JSON:  {"dh_public_key":"<hex>","salt":"<hex>"}
 *     3. Both derive AES key via HKDF(shared_secret, salt, "mtc-dh-bootstrap")
 *     4. Client sends [4-byte len][encrypted enrollment JSON]
 *     5. Server sends [4-byte len][encrypted certificate JSON]
 *
 * Dependencies:
 *   mtc_bootstrap.h, mtc_crypt.h, mtc_store.h, mtc_log.h
 *   mtc_checkendpoint.h, mtc_merkle.h, mtc_db.h
 *   wolfssl/wolfcrypt/curve25519.h  (X25519 key exchange)
 *   wolfssl/wolfcrypt/hmac.h        (HKDF key derivation)
 *   wolfssl/wolfcrypt/sha256.h      (SPKI fingerprint)
 *   wolfssl/wolfcrypt/random.h      (salt generation)
 *   pthread.h                       (background thread)
 *   json-c/json.h                   (JSON parsing)
 *
 * Notes:
 *   - The bootstrap thread is NOT thread-safe with respect to MtcStore.
 *     The main HTTP server is single-threaded, so concurrent access to
 *     the store requires care.  For now, the bootstrap thread serialises
 *     with the main thread via the GIL-like single-connection model.
 *   - AbuseIPDB check at 25% threshold (ABUSEIPDB_ENROLL_THRESHOLD).
 *
 * Created:     2026-04-14
 ******************************************************************************/

#include "mtc_bootstrap.h"
#include "mtc_crypt.h"
#include "mtc_store.h"
#include "mtc_merkle.h"
#include "mtc_db.h"
#include "mtc_log.h"
#include "mtc_http.h"
#include "mtc_checkendpoint.h"
#include "mtc_ratelimit.h"
#include "mtc_ca_validate.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>

#include <json-c/json.h>

#define BOOTSTRAP_BACKLOG    5
#define BOOTSTRAP_MAX_MSG    65536
#define BOOTSTRAP_HKDF_INFO  "mtc-dh-bootstrap"
#define BOOTSTRAP_SALT_SZ    16
#define BOOTSTRAP_AES_KEY_SZ 16

/******************************************************************************
 * Thread argument — passed from mtc_bootstrap_start to bootstrap_thread.
 ******************************************************************************/
typedef struct {
    int        listen_fd;
    MtcStore  *store;
} bootstrap_arg_t;

/******************************************************************************
 * Function:    secure_zero  (static)
 *
 * Description:
 *   Zero a buffer using a volatile pointer so the compiler cannot
 *   optimise the write away.
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
 *
 * Description:
 *   Convert binary data to lowercase hex string.  out must hold
 *   at least sz*2+1 bytes.
 ******************************************************************************/
static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

/******************************************************************************
 * Function:    hex_to_bytes  (static)
 *
 * Description:
 *   Convert a hex string to binary bytes.  Returns number of bytes
 *   written, or -1 on invalid hex.
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
 * Function:    write_all  (static)
 *
 * Description:
 *   Write exactly len bytes to fd.  Returns 0 on success, -1 on error.
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
 *
 * Description:
 *   Read exactly len bytes from fd.  Returns 0 on success, -1 on error.
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
 * Function:    send_http_get_proxy  (static)
 *
 * Description:
 *   Reply to {"op":"http_get","path":"<path>"} by running the path through
 *   the in-process GET dispatcher (mtc_http_dispatch_get_capture) and
 *   wrapping the captured body + status in a plaintext JSON reply:
 *     {"status":<code>,"body":<json_body>}
 *   Used to serve /certificate/<n>, /revoked/<n>, /public-key/<n>,
 *   /log/entry/<n>, etc. over the bootstrap port without TLS.
 ******************************************************************************/
static int send_http_get_proxy(int fd, MtcStore *store, const char *path)
{
    char *inner_body = NULL;
    int inner_status = 0;
    struct json_object *outer;
    const char *json_str;
    int rc = -1;

    if (!path || path[0] != '/') {
        LOG_WARN("bootstrap: http_get rejected (path='%s')",
                 path ? path : "(null)");
        return -1;
    }

    (void)mtc_http_dispatch_get_capture(store, path, &inner_body,
                                        &inner_status);
    if (!inner_body) {
        LOG_WARN("bootstrap: http_get '%s' produced no body", path);
        return -1;
    }

    outer = json_object_new_object();
    if (outer) {
        struct json_object *inner = json_tokener_parse(inner_body);
        json_object_object_add(outer, "status",
                               json_object_new_int(inner_status));
        /* Embed the inner JSON object if parseable; else pass body string */
        if (inner)
            json_object_object_add(outer, "body", inner);
        else
            json_object_object_add(outer, "body",
                                   json_object_new_string(inner_body));

        json_str = json_object_to_json_string(outer);
        if (json_str && write_all(fd, (const unsigned char *)json_str,
                                  (unsigned int)strlen(json_str)) == 0)
            rc = 0;

        json_object_put(outer);
    }

    free(inner_body);
    return rc;
}

/******************************************************************************
 * Function:    send_ca_pubkey_plaintext  (static)
 *
 * Description:
 *   Reply to a {"op":"ca_pubkey"} bootstrap request with the CA's Ed25519
 *   log-cosigner public key as plaintext JSON — no DH exchange.  Same
 *   payload shape as GET /ca/public-key on the HTTP port so clients can
 *   reuse parsing.  Safe in the clear: it is a public key, and clients
 *   must TOFU-pin it regardless of transport.
 ******************************************************************************/
static int send_ca_pubkey_plaintext(int fd, MtcStore *store)
{
    struct json_object *obj;
    char pem[1024];
    int pemSz;
    const char *json_str;
    int rc = -1;

    obj = json_object_new_object();
    if (!obj)
        return -1;

    json_object_object_add(obj, "ca_name",
        json_object_new_string(store->ca_name));
    json_object_object_add(obj, "cosigner_id",
        json_object_new_string(store->cosigner_id));
    json_object_object_add(obj, "algorithm",
        json_object_new_string("Ed25519"));

    pemSz = mtc_store_get_public_key_pem(store, pem, (int)sizeof(pem));
    if (pemSz > 0) {
        pem[pemSz] = '\0';
        json_object_object_add(obj, "public_key_pem",
            json_object_new_string(pem));
    }

    json_str = json_object_to_json_string(obj);
    if (json_str) {
        size_t len = strlen(json_str);
        if (write_all(fd, (const unsigned char *)json_str,
                      (unsigned int)len) == 0)
            rc = 0;
    }

    json_object_put(obj);
    return rc;
}

/******************************************************************************
 * Function:    read_plaintext_json  (static)
 *
 * Description:
 *   Read a plaintext JSON block from the socket by tracking brace depth.
 *   Returns the number of bytes read, or -1 on error.
 ******************************************************************************/
static int read_plaintext_json(int fd, char *buf, int bufsz)
{
    int pos = 0;
    int depth = 0;
    int started = 0;
    time_t deadline = time(NULL) + MTC_BOOTSTRAP_READ_TOTAL_SEC;

    while (pos < bufsz - 1) {
        ssize_t n;
        if (time(NULL) > deadline) {
            LOG_WARN("bootstrap: read_plaintext_json wall-clock deadline "
                     "exceeded (pos=%d, depth=%d) — dropping (slow-loris?)",
                     pos, depth);
            return -1;
        }
        n = read(fd, buf + pos, 1);
        if (n <= 0)
            return -1;
        if (buf[pos] == '{') {
            depth++;
            started = 1;
        } else if (buf[pos] == '}') {
            depth--;
        }
        pos++;
        if (started && depth == 0) {
            buf[pos] = '\0';
            return pos;
        }
    }
    return -1;  /* buffer full without complete JSON */
}

/******************************************************************************
 * Function:    send_length_prefixed  (static)
 *
 * Description:
 *   Send a 4-byte network-order length prefix followed by the payload.
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
 *
 * Description:
 *   Read a 4-byte network-order length prefix, then that many bytes.
 *   Returns the payload length, or -1 on error.  buf must be at least
 *   bufsz bytes.
 ******************************************************************************/
static int recv_length_prefixed(int fd, unsigned char *buf, int bufsz)
{
    uint32_t net_len;
    uint32_t len;

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
 * Function:    handle_bootstrap_client  (static)
 *
 * Description:
 *   Handle a single bootstrap client session:
 *   1. X25519 key exchange (plaintext JSON)
 *   2. Derive AES key via HKDF
 *   3. Receive encrypted enrollment request
 *   4. Issue certificate
 *   5. Send encrypted certificate response
 ******************************************************************************/
static int handle_bootstrap_client(int fd, MtcStore *store,
                                    const char *ip_str)
{
    /* Per-read stall timeout: a single read() blocked longer than this
     * drops the connection.  Applies to every subsequent read — both
     * the plaintext JSON and the encrypted enrollment payload.  The
     * per-read cap plus the wall-clock budget inside read_plaintext_json
     * between them kill slow-loris drips. */
    {
        struct timeval tv;
        tv.tv_sec  = MTC_BOOTSTRAP_READ_STALL_SEC;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* Ensure DB connection is alive (may have dropped since last request) */
    if (store->use_db) {
        if (mtc_db_ensure_connected(&store->db) != 0) {
            fprintf(stderr, "[bootstrap] DB connection lost and reconnect failed\n");
            store->db = NULL;
        }
    }

    /* DH exchange state */
    curve25519_key server_key, client_key;
    WC_RNG rng;
    uint8_t shared_secret[CURVE25519_KEYSIZE];
    word32 shared_sz = CURVE25519_KEYSIZE;
    uint8_t server_pub[CURVE25519_KEYSIZE];
    word32 server_pub_sz = CURVE25519_KEYSIZE;
    uint8_t client_pub[CURVE25519_KEYSIZE];
    uint8_t salt[BOOTSTRAP_SALT_SZ];
    uint8_t aes_key[BOOTSTRAP_AES_KEY_SZ];

    /* I/O buffers */
    char json_buf[BOOTSTRAP_MAX_MSG];
    unsigned char enc_buf[BOOTSTRAP_MAX_MSG];
    unsigned char dec_buf[BOOTSTRAP_MAX_MSG];
    unsigned int enc_len, dec_len;

    /* JSON parsing */
    struct json_object *req = NULL, *val;
    const char *hex_str;

    /* Enrollment state */
    const char *subject, *pub_key_pem, *key_algo, *enrollment_nonce;
    int validity_days;
    struct json_object *extensions = NULL;

    /* Operator-assigned label (from the consumed nonce row, leaf-only).
     * Empty for CA enrollment.  Echoed back in the cert-issue response
     * so bootstrap_leaf can pick the right ~/.TPM/<domain>-<label>/ dir. */
    char bootstrap_label[MTC_LABEL_MAX + 1] = {0};

    MtcCryptCtx *crypt_ctx = NULL;
    int ret, rng_ok = 0, server_key_ok = 0, client_key_ok = 0;

    /* --- Step 1: Read client request (plaintext JSON) --- */
    ret = read_plaintext_json(fd, json_buf, sizeof(json_buf));
    if (ret <= 0) {
        LOG_WARN("bootstrap: failed to read request");
        return -1;
    }
    LOG_DEBUG("bootstrap: received request (%d bytes)", ret);

    req = json_tokener_parse(json_buf);
    if (!req) {
        LOG_WARN("bootstrap: invalid request JSON");
        return -1;
    }

    /* Handle simple ops (no DH needed). */
    if (json_object_object_get_ex(req, "op", &val)) {
        const char *op = json_object_get_string(val);
        int op_rc;

        /* Read-only lookups — use RL_READ (60/min). */
        if (ip_str && ip_str[0] != '\0' &&
            !mtc_ratelimit_check(ip_str, RL_READ)) {
            LOG_WARN("bootstrap: rate limited %s (read)", ip_str);
            json_object_put(req);
            return -1;
        }

        if (strcmp(op, "ca_pubkey") == 0) {
            LOG_INFO("bootstrap: ca_pubkey request");
            op_rc = send_ca_pubkey_plaintext(fd, store);
            json_object_put(req);
            return op_rc;
        }
        if (strcmp(op, "http_get") == 0) {
            struct json_object *pval;
            const char *path = NULL;
            if (json_object_object_get_ex(req, "path", &pval))
                path = json_object_get_string(pval);
            LOG_INFO("bootstrap: http_get %s", path ? path : "(null)");
            op_rc = send_http_get_proxy(fd, store, path);
            json_object_put(req);
            return op_rc;
        }
        LOG_WARN("bootstrap: unknown op '%s'", op);
        json_object_put(req);
        return -1;
    }

    /* DH enrollment flow — expensive path, use RL_BOOTSTRAP (3/min). */
    if (ip_str && ip_str[0] != '\0' &&
        !mtc_ratelimit_check(ip_str, RL_BOOTSTRAP)) {
        LOG_WARN("bootstrap: rate limited %s (enroll)", ip_str);
        json_object_put(req);
        return -1;
    }

    if (!json_object_object_get_ex(req, "dh_public_key", &val)) {
        LOG_WARN("bootstrap: missing 'dh_public_key' in request");
        json_object_put(req);
        return -1;
    }
    hex_str = json_object_get_string(val);
    if (hex_to_bytes(hex_str, client_pub, CURVE25519_KEYSIZE) != CURVE25519_KEYSIZE) {
        LOG_WARN("bootstrap: invalid DH public key hex");
        json_object_put(req);
        return -1;
    }
    json_object_put(req);
    req = NULL;

    /* --- X25519 exchange --- */
    if (wc_InitRng(&rng) != 0) {
        LOG_ERROR("bootstrap: RNG init failed");
        return -1;
    }
    rng_ok = 1;

    if (wc_curve25519_init(&server_key) != 0) {
        LOG_ERROR("bootstrap: X25519 server key init failed");
        goto cleanup;
    }
    server_key_ok = 1;

    if (wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &server_key) != 0) {
        LOG_ERROR("bootstrap: X25519 key generation failed");
        goto cleanup;
    }

    if (wc_curve25519_export_public(&server_key, server_pub, &server_pub_sz) != 0) {
        LOG_ERROR("bootstrap: X25519 export public failed");
        goto cleanup;
    }

    /* Import client public key */
    if (wc_curve25519_init(&client_key) != 0) {
        LOG_ERROR("bootstrap: X25519 client key init failed");
        goto cleanup;
    }
    client_key_ok = 1;

    if (wc_curve25519_import_public(client_pub, CURVE25519_KEYSIZE, &client_key) != 0) {
        LOG_ERROR("bootstrap: X25519 import client public failed");
        goto cleanup;
    }

    /* Compute shared secret */
    if (wc_curve25519_shared_secret(&server_key, &client_key,
                                     shared_secret, &shared_sz) != 0) {
        LOG_ERROR("bootstrap: X25519 shared secret failed");
        goto cleanup;
    }

    /* Generate random salt */
    if (wc_RNG_GenerateBlock(&rng, salt, BOOTSTRAP_SALT_SZ) != 0) {
        LOG_ERROR("bootstrap: salt generation failed");
        goto cleanup;
    }

    /* Derive AES key via HKDF */
    if (wc_HKDF(WC_SHA256, shared_secret, shared_sz,
                 salt, BOOTSTRAP_SALT_SZ,
                 (const byte *)BOOTSTRAP_HKDF_INFO,
                 (word32)strlen(BOOTSTRAP_HKDF_INFO),
                 aes_key, BOOTSTRAP_AES_KEY_SZ) != 0) {
        LOG_ERROR("bootstrap: HKDF key derivation failed");
        goto cleanup;
    }

    LOG_DEBUG("bootstrap: DH exchange complete, AES key derived");

    /* --- Send server DH response (plaintext JSON) --- */
    {
        char pub_hex[CURVE25519_KEYSIZE * 2 + 1];
        char salt_hex[BOOTSTRAP_SALT_SZ * 2 + 1];
        int json_len;

        to_hex(server_pub, CURVE25519_KEYSIZE, pub_hex);
        to_hex(salt, BOOTSTRAP_SALT_SZ, salt_hex);

        json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"dh_public_key\":\"%s\",\"salt\":\"%s\"}", pub_hex, salt_hex);

        if (write_all(fd, (unsigned char *)json_buf, (unsigned int)json_len) != 0) {
            LOG_WARN("bootstrap: failed to send DH response");
            goto cleanup;
        }
    }

    /* --- Init mtc_crypt with derived key --- */
    crypt_ctx = mtc_crypt_init(aes_key, BOOTSTRAP_AES_KEY_SZ);
    if (!crypt_ctx) {
        LOG_ERROR("bootstrap: mtc_crypt_init failed");
        goto cleanup;
    }

    /* --- Step 2: Receive encrypted enrollment request --- */
    ret = recv_length_prefixed(fd, enc_buf, sizeof(enc_buf));
    if (ret <= 0) {
        LOG_WARN("bootstrap: failed to receive enrollment request");
        goto cleanup;
    }
    LOG_DEBUG("bootstrap: received encrypted enrollment (%d bytes)", ret);

    dec_len = sizeof(dec_buf);
    if (mtc_crypt_decode(crypt_ctx, enc_buf, (unsigned int)ret,
                         dec_buf, &dec_len) != 0) {
        LOG_WARN("bootstrap: failed to decrypt enrollment request");
        goto cleanup;
    }
    dec_buf[dec_len] = '\0';  /* NUL-terminate for JSON parsing */

    LOG_DEBUG("bootstrap: decrypted enrollment (%u bytes): %.80s...",
              dec_len, (char *)dec_buf);

    /* --- Parse enrollment request --- */
    req = json_tokener_parse((const char *)dec_buf);
    if (!req) {
        LOG_WARN("bootstrap: invalid enrollment JSON");
        goto cleanup;
    }

    if (!json_object_object_get_ex(req, "subject", &val)) {
        LOG_WARN("bootstrap: missing 'subject'");
        goto cleanup;
    }
    subject = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "public_key_pem", &val)) {
        LOG_WARN("bootstrap: missing 'public_key_pem'");
        goto cleanup;
    }
    pub_key_pem = json_object_get_string(val);

    key_algo = "EC-P256";
    if (json_object_object_get_ex(req, "key_algorithm", &val)) {
        const char *requested = json_object_get_string(val);
        if (strcmp(requested, "EC-P256") != 0 &&
            strcmp(requested, "EC-P384") != 0 &&
            strcmp(requested, "Ed25519") != 0 &&
            strcmp(requested, "ML-DSA-44") != 0 &&
            strcmp(requested, "ML-DSA-65") != 0 &&
            strcmp(requested, "ML-DSA-87") != 0) {
            LOG_WARN("bootstrap: unsupported key_algorithm '%s'", requested);
            goto cleanup;
        }
        key_algo = requested;
    }

    validity_days = 90;
    if (json_object_object_get_ex(req, "validity_days", &val)) {
        validity_days = json_object_get_int(val);
        if (validity_days < 1 || validity_days > 3650) {
            LOG_WARN("bootstrap: invalid validity_days %d", validity_days);
            goto cleanup;
        }
    }

    /* Nonce is required for leaf enrollment; CA enrollment uses DNS
     * TXT for proof of domain control and doesn't consume a nonce. */
    if (json_object_object_get_ex(req, "enrollment_nonce", &val))
        enrollment_nonce = json_object_get_string(val);
    else
        enrollment_nonce = NULL;

    json_object_object_get_ex(req, "extensions", &extensions);

    /* --- Determine enrollment type and validate --- */
    {
        int is_ca_enrollment = 0;

        /* Detect CA enrollment: extensions contains ca_certificate_pem */
        if (extensions) {
            struct json_object *ca_val;
            if (json_object_object_get_ex(extensions, "ca_certificate_pem",
                                          &ca_val))
                is_ca_enrollment = 1;
        }

        if (is_ca_enrollment) {
            /* CA enrollment: validate X.509 cert + DNS TXT record */
            LOG_INFO("bootstrap: CA enrollment request for '%s'", subject);
            if (!mtc_validate_ca_cert(extensions)) {
                LOG_WARN("bootstrap: CA validation failed for '%s'", subject);
                {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"CA certificate rejected: "
                        "DNS validation failed\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                }
                goto cleanup;
            }

            /* Revocation gate: if the most-recent CA entry for this
             * subject is revoked, the server operator has explicitly
             * said "no" to this domain.  Refuse re-enrollment.  The
             * CA subject is "<domain>-ca" (per bootstrap_ca.c's
             * convention). */
            {
                char ca_subject[520];
                int latest_idx = -1;
                int k;

                snprintf(ca_subject, sizeof(ca_subject), "%s-ca", subject);
                for (k = 0; k < store->cert_count; k++) {
                    struct json_object *entry = store->certificates[k];
                    struct json_object *sc_j, *tbs_j, *subj_j;
                    const char *entry_subj;
                    if (!entry) continue;
                    if (!json_object_object_get_ex(entry, "standalone_certificate", &sc_j)) continue;
                    if (!json_object_object_get_ex(sc_j, "tbs_entry", &tbs_j)) continue;
                    if (!json_object_object_get_ex(tbs_j, "subject", &subj_j)) continue;
                    entry_subj = json_object_get_string(subj_j);
                    if (entry_subj && strcmp(entry_subj, ca_subject) == 0) {
                        latest_idx = k;  /* keep overwriting; highest wins */
                    }
                }
                if (latest_idx >= 0 && mtc_store_is_revoked(store, latest_idx)) {
                    LOG_WARN("bootstrap: CA enrollment refused — most "
                             "recent CA for '%s' (index %d) is revoked "
                             "by server operator",
                             ca_subject, latest_idx);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"CA enrollment refused: this "
                            "domain's most recent CA certificate has "
                            "been revoked by the server operator. "
                            "Contact the server operator to lift the "
                            "revocation before re-enrolling.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }
            }

            LOG_INFO("bootstrap: CA enrollment for '%s' authorized",
                     subject);
        } else {
            /* Leaf enrollment: nonce required */
            wc_Sha256 sha;

            if (!enrollment_nonce) {
                LOG_WARN("bootstrap: missing enrollment_nonce for leaf '%s'",
                         subject);
                {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"enrollment_nonce required for leaf\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                }
                goto cleanup;
            }
            uint8_t h[32];
            char leaf_fp[65];
            int fi;

            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const uint8_t *)pub_key_pem,
                            (word32)strlen(pub_key_pem));
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            for (fi = 0; fi < 32; fi++)
                snprintf(leaf_fp + fi * 2, 3, "%02x", h[fi]);

            if (!store->db ||
                !mtc_db_validate_and_consume_nonce(store->db,
                    enrollment_nonce, subject, leaf_fp,
                    bootstrap_label, sizeof(bootstrap_label))) {
                LOG_WARN("bootstrap: invalid, expired, or used nonce for '%s'",
                         subject);
                {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"invalid, expired, or already-used nonce\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                }
                goto cleanup;
            }

            LOG_INFO("bootstrap: leaf enrollment for '%s' authorized by nonce %.16s...",
                     subject, enrollment_nonce);
        }
    }

    /* --- Issue certificate (mirrors handle_certificate_request logic) --- */
    {
        struct json_object *tbs, *sc, *result, *checkpoint;
        struct json_object *proof_arr, *cosig_arr, *cosig_obj;
        uint8_t *entry_buf = NULL;
        int entry_sz;
        int index;
        double now_ts = (double)time(NULL);
        char spk_hash[65];
        uint8_t *proof = NULL;
        int proof_count = 0;
        uint8_t subtree_hash[MTC_HASH_SIZE];
        char hash_hex[MTC_HASH_SIZE * 2 + 1];
        uint8_t sig[64];
        int sig_sz = 0;
        int i, start, end;

        /* Hash the public key */
        {
            wc_Sha256 sha;
            uint8_t h[32];
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const byte *)pub_key_pem,
                (word32)strlen(pub_key_pem));
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            to_hex(h, 32, spk_hash);
        }

        /* Build TBS JSON */
        tbs = json_object_new_object();
        json_object_object_add(tbs, "subject",
            json_object_new_string(subject));
        json_object_object_add(tbs, "subject_public_key_algorithm",
            json_object_new_string(key_algo));
        json_object_object_add(tbs, "subject_public_key_hash",
            json_object_new_string(spk_hash));
        json_object_object_add(tbs, "not_before",
            json_object_new_double(now_ts));
        json_object_object_add(tbs, "not_after",
            json_object_new_double(now_ts + validity_days * 86400.0));
        json_object_object_add(tbs, "extensions",
            extensions ? json_object_get(extensions)
                       : json_object_new_object());

        /* Serialize for Merkle tree: 0x01 + deterministic JSON */
        {
            struct json_object *ser = json_object_new_object();
            const char *ser_str;
            json_object_object_add(ser, "extensions",
                json_object_get(json_object_object_get(tbs, "extensions")));
            json_object_object_add(ser, "not_after",
                json_object_new_double(now_ts + validity_days * 86400.0));
            json_object_object_add(ser, "not_before",
                json_object_new_double(now_ts));
            json_object_object_add(ser, "spk_algorithm",
                json_object_new_string(key_algo));
            json_object_object_add(ser, "spk_hash",
                json_object_new_string(spk_hash));
            json_object_object_add(ser, "subject",
                json_object_new_string(subject));

            ser_str = json_object_to_json_string_ext(ser,
                JSON_C_TO_STRING_PLAIN);
            entry_sz = 1 + (int)strlen(ser_str);
            entry_buf = (uint8_t *)malloc((size_t)entry_sz);
            if (!entry_buf) {
                json_object_put(ser);
                json_object_put(tbs);
                goto cleanup;
            }
            entry_buf[0] = 0x01;
            memcpy(entry_buf + 1, ser_str, strlen(ser_str));
            json_object_put(ser);
        }

        /* Add to log */
        index = mtc_store_add_entry(store, entry_buf, entry_sz);

        /* Checkpoint */
        checkpoint = mtc_store_checkpoint(store);

        /* Proof */
        start = 0;
        end = store->tree.size;
        mtc_tree_inclusion_proof(&store->tree, index, start, end,
            &proof, &proof_count);
        mtc_tree_subtree_hash(&store->tree, start, end, subtree_hash);

        /* Cosign */
        mtc_store_cosign(store, start, end, sig, &sig_sz);

        /* Build standalone certificate */
        sc = json_object_new_object();
        json_object_object_add(sc, "index", json_object_new_int(index));
        json_object_object_add(sc, "tbs_entry", json_object_get(tbs));

        proof_arr = json_object_new_array();
        for (i = 0; i < proof_count; i++) {
            to_hex(proof + i * MTC_HASH_SIZE, MTC_HASH_SIZE, hash_hex);
            json_object_array_add(proof_arr,
                json_object_new_string(hash_hex));
        }
        json_object_object_add(sc, "inclusion_proof", proof_arr);

        json_object_object_add(sc, "subtree_start",
            json_object_new_int(start));
        json_object_object_add(sc, "subtree_end",
            json_object_new_int(end));

        to_hex(subtree_hash, MTC_HASH_SIZE, hash_hex);
        json_object_object_add(sc, "subtree_hash",
            json_object_new_string(hash_hex));

        /* Cosignature */
        cosig_arr = json_object_new_array();
        cosig_obj = json_object_new_object();
        json_object_object_add(cosig_obj, "cosigner_id",
            json_object_new_string(store->cosigner_id));
        json_object_object_add(cosig_obj, "log_id",
            json_object_new_string(store->log_id));
        json_object_object_add(cosig_obj, "start",
            json_object_new_int(start));
        json_object_object_add(cosig_obj, "end",
            json_object_new_int(end));
        json_object_object_add(cosig_obj, "subtree_hash",
            json_object_new_string(hash_hex));
        {
            char sig_hex[64 * 2 + 1];
            to_hex(sig, sig_sz, sig_hex);
            json_object_object_add(cosig_obj, "signature",
                json_object_new_string(sig_hex));
        }
        json_object_object_add(cosig_obj, "algorithm",
            json_object_new_string("Ed25519"));
        json_object_array_add(cosig_arr, cosig_obj);
        json_object_object_add(sc, "cosignatures", cosig_arr);
        json_object_object_add(sc, "trust_anchor_id",
            json_object_new_string(store->log_id));

        /* Build result — this is both the wire payload and what gets
         * persisted to store->certificates[index] / the DB.  The label
         * is purely in-flight (bootstrap_leaf uses it for local dir
         * naming) and must NOT be persisted alongside the cert, so we
         * add it to the wire copy only, below, after the persist. */
        result = json_object_new_object();
        json_object_object_add(result, "status",
            json_object_new_string("ok"));
        json_object_object_add(result, "index",
            json_object_new_int(index));
        json_object_object_add(result, "standalone_certificate", sc);
        json_object_object_add(result, "checkpoint",
            json_object_get(checkpoint));

        /* Store certificate */
        if (index >= store->cert_capacity) {
            store->cert_capacity *= 2;
            store->certificates = (struct json_object **)realloc(
                store->certificates,
                (size_t)store->cert_capacity * sizeof(struct json_object *));
        }
        while (store->cert_count <= index)
            store->certificates[store->cert_count++] = NULL;
        store->certificates[index] = json_object_get(result);

        /* Persist */
        mtc_store_save(store);
        if (store->use_db && store->db) {
            const char *cert_str = json_object_to_json_string(result);
            if (mtc_db_save_certificate(store->db, index, cert_str) != 0)
                fprintf(stderr, "[bootstrap] WARNING: DB save_certificate failed for index %d\n", index);
        }

        /* --- Step 3: Send encrypted certificate response ---
         * The wire payload wraps `result` plus an optional `label` field.
         * Done as a shallow copy (json_object_get refcounts the shared
         * children) so the in-memory / DB-persisted `result` stays
         * label-free.  Constraint: label is purely in-flight. */
        struct json_object *wire_resp = json_object_new_object();
        {
            struct json_object_iterator it = json_object_iter_begin(result);
            struct json_object_iterator end = json_object_iter_end(result);
            while (!json_object_iter_equal(&it, &end)) {
                json_object_object_add(wire_resp,
                    json_object_iter_peek_name(&it),
                    json_object_get(json_object_iter_peek_value(&it)));
                json_object_iter_next(&it);
            }
            if (bootstrap_label[0])
                json_object_object_add(wire_resp, "label",
                    json_object_new_string(bootstrap_label));
        }
        {
            const char *result_str = json_object_to_json_string(wire_resp);
            enc_len = sizeof(enc_buf);
            if (mtc_crypt_encode(crypt_ctx, (unsigned char *)result_str,
                    (unsigned int)strlen(result_str),
                    enc_buf, &enc_len) != 0) {
                LOG_ERROR("bootstrap: failed to encrypt certificate response");
                json_object_put(wire_resp);
                json_object_put(result);
                json_object_put(tbs);
                json_object_put(checkpoint);
                free(proof);
                free(entry_buf);
                goto cleanup;
            }
            if (send_length_prefixed(fd, enc_buf, enc_len) != 0) {
                LOG_WARN("bootstrap: failed to send certificate response");
            } else {
                LOG_INFO("bootstrap: enrolled '%s' at index %d%s%s",
                         subject, index,
                         bootstrap_label[0] ? ", label=" : "",
                         bootstrap_label[0] ? bootstrap_label : "");
            }
        }

        json_object_put(wire_resp);
        json_object_put(result);
        json_object_put(tbs);
        json_object_put(checkpoint);
        free(proof);
        free(entry_buf);
    }

    /* Fall through to cleanup with success */
    if (req) { json_object_put(req); req = NULL; }
    if (crypt_ctx) { mtc_crypt_fin(crypt_ctx); crypt_ctx = NULL; }
    if (client_key_ok) wc_curve25519_free(&client_key);
    if (server_key_ok) wc_curve25519_free(&server_key);
    if (rng_ok) wc_FreeRng(&rng);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    secure_zero(salt, sizeof(salt));
    return 0;

cleanup:
    if (req) json_object_put(req);
    if (crypt_ctx) mtc_crypt_fin(crypt_ctx);
    if (client_key_ok) wc_curve25519_free(&client_key);
    if (server_key_ok) wc_curve25519_free(&server_key);
    if (rng_ok) wc_FreeRng(&rng);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    secure_zero(salt, sizeof(salt));
    return -1;
}

/******************************************************************************
 * Function:    bootstrap_thread  (static)
 *
 * Description:
 *   Accept loop for the DH bootstrap port.  Each connection is handled
 *   synchronously: check AbuseIPDB, run the DH+enrollment protocol,
 *   then close.
 ******************************************************************************/
static void *bootstrap_thread(void *arg)
{
    bootstrap_arg_t *ba = (bootstrap_arg_t *)arg;
    int listen_fd = ba->listen_fd;
    MtcStore *store = ba->store;

    free(ba);

    LOG_INFO("bootstrap: listening (fd=%d)", listen_fd);

    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        char ip_str[64];
        int client_fd;

        client_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            LOG_ERROR("bootstrap: accept failed: %s", strerror(errno));
            continue;
        }

        /* Fork per-connection: parent resumes accept loop, child serves. */
        {
            pid_t pid = fork();
            if (pid < 0) {
                LOG_ERROR("bootstrap: fork failed: %s", strerror(errno));
                close(client_fd);
                continue;
            }
            if (pid > 0) {
                /* Parent: drop socket fd — child holds its own ref. */
                LOG_DEBUG("bootstrap: forked child pid=%d", (int)pid);
                close(client_fd);
                continue;
            }
            /* Child: no longer needs the listen socket. */
            LOG_DEBUG("bootstrap: child pid=%d handling conn", (int)getpid());
            close(listen_fd);
        }

        /* Get client IP */
        ip_str[0] = '\0';
        {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) == 0)
                inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
        }

        LOG_INFO("bootstrap: connection from %s", ip_str);

        /* Rate limiting is applied inside handle_bootstrap_client, once
         * the op type is known: read-only lookups (ca_pubkey, http_get)
         * use RL_READ, DH enrollment uses RL_BOOTSTRAP. */

        /* AbuseIPDB check at enrollment threshold (25%) */
        if (ip_str[0] != '\0') {
            int score = mtc_checkendpoint(ip_str);
            if (score >= ABUSEIPDB_ENROLL_THRESHOLD) {
                LOG_WARN("bootstrap: rejected %s (abuse score %d >= %d)",
                         ip_str, score, ABUSEIPDB_ENROLL_THRESHOLD);
                close(client_fd);
                _exit(0);
            }
        }

        handle_bootstrap_client(client_fd, store, ip_str);
        close(client_fd);
        _exit(0);
    }

    return NULL;
}

/******************************************************************************
 * Function:    mtc_bootstrap_start
 *
 * Description:
 *   Create a TCP listen socket on the given host:port and spawn a
 *   background thread to handle bootstrap connections.
 *
 * Input Arguments:
 *   host   - Bind address (NULL = "0.0.0.0").
 *   port   - TCP port for the DH bootstrap listener.
 *   store  - Initialised MTC store.  Must outlive the thread.
 *
 * Returns:
 *    0  on success (thread is running).
 *   -1  on failure (socket bind/listen or pthread_create failed).
 ******************************************************************************/
int mtc_bootstrap_start(const char *host, int port, MtcStore *store)
{
    int listen_fd;
    struct sockaddr_in addr;
    int opt = 1;
    pthread_t tid;
    bootstrap_arg_t *ba;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        LOG_ERROR("bootstrap: socket() failed: %s", strerror(errno));
        return -1;
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (host != NULL)
        inet_pton(AF_INET, host, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("bootstrap: bind(%s:%d) failed: %s",
                  host ? host : "0.0.0.0", port, strerror(errno));
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, BOOTSTRAP_BACKLOG) < 0) {
        LOG_ERROR("bootstrap: listen() failed: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    ba = malloc(sizeof(*ba));
    if (!ba) {
        close(listen_fd);
        return -1;
    }
    ba->listen_fd = listen_fd;
    ba->store = store;

    if (pthread_create(&tid, NULL, bootstrap_thread, ba) != 0) {
        LOG_ERROR("bootstrap: pthread_create failed: %s", strerror(errno));
        free(ba);
        close(listen_fd);
        return -1;
    }
    pthread_detach(tid);

    LOG_INFO("bootstrap: started on %s:%d",
             host ? host : "0.0.0.0", port);
    return 0;
}
