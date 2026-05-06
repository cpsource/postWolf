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
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#include <json-c/json.h>

#define BOOTSTRAP_BACKLOG    5
#define BOOTSTRAP_MAX_MSG    65536
#define BOOTSTRAP_HKDF_INFO  "mtc-dh-bootstrap"
#define BOOTSTRAP_SALT_SZ    16
/* TODO #62: AES-256-GCM AEAD requires 32-byte keys, one per
 * direction.  HKDF below produces 64 bytes total (c2s||s2c). */
#define BOOTSTRAP_AES_KEY_SZ      32   /* AES-256 */
#define BOOTSTRAP_AES_KEYS_TOTAL  (BOOTSTRAP_AES_KEY_SZ * 2)

/* Proof-of-possession (README-issues.md issue #5).
 *
 * The server includes BOOTSTRAP_POP_NONCE_SZ random bytes in its
 * DH reply (hex-encoded as `pop_nonce`).  The client signs
 *
 *     MQC-CA-REGISTER|<domain>|<subject>|<spki_hash_hex>|<pop_nonce_hex>
 *
 * with the CA private key (ML-DSA-87, ctx=MTC_CA_POP_LABEL) and
 * returns the signature in the encrypted enrollment JSON as
 * `pop_signature` (hex).  The server re-builds the same canonical
 * string from the request fields and verifies the signature
 * against the submitted public_key_pem.  Bootstrap_leaf does not
 * use this — the leaf flow proves possession via the issued
 * nonce. */
#define BOOTSTRAP_POP_NONCE_SZ 32
#define MTC_CA_POP_LABEL      "mtc-ca-pop/v1\n\x00"
#define MTC_CA_POP_LABEL_LEN  16
#define MTC_CA_POP_PREFIX     "MQC-CA-REGISTER"

/* P0 / TODO #9b leaf branch — bootstrap-response signing.
 *
 * The leaf-enroll response is now signed under the cosigner's
 * ML-DSA-87 private key.  The signature covers the CANONICAL
 * JSON of the response with `ca_cosigner_pem` set and
 * `ca_response_sig` set to the empty string.  The leaf operator
 * pastes the cosigner SHA-256 fingerprint alongside the
 * enrollment nonce; bootstrap_leaf verifies the fingerprint
 * matches `ca_cosigner_pem`, then verifies this signature, then
 * pins the now-authenticated PEM at
 * ~/.TPM/<subject>[-<label>]/ca-cosigner.pem.  An on-path
 * attacker on port 8445 cannot forge this signature without the
 * cosigner private key. */
#define MTC_BOOTSTRAP_LABEL      "mtc-bootstrap/v1\n\x00"
#define MTC_BOOTSTRAP_LABEL_LEN  16

/* P0 / TODO #63 — DH-transcript signature label.  Distinct from the
 * response-signing label above so the same cosigner key signing the
 * step-2 transcript can never have its signature reused as a response
 * signature (different ctx → different domain-separated tag). */
#define MTC_BOOTSTRAP_DH_LABEL      "mtc-boot-dh/v1\n\x00"
#define MTC_BOOTSTRAP_DH_LABEL_LEN  16

/* Bootstrap-channel protocol version for #63's signed transcript.
 * Bumping this requires both peers to be rebuilt simultaneously (per
 * CLAUDE.md "MQC wire-format invariants are NOT operator-tunable"). */
#define MTC_BOOTSTRAP_PROTO_V1      0x01

/******************************************************************************
 * Function:    add_cosigner_sig_to_response
 *
 * Description:
 *   Append `ca_cosigner_pem` and `ca_response_sig` to a bootstrap-leaf
 *   response object so the leaf can verify the response was actually
 *   produced by the cosigner-key holder (P0 / TODO #9b leaf branch).
 *
 *   `ca_response_sig` covers the canonical JSON of the response
 *   WITHOUT the signature field — verifier strips it, re-serializes
 *   with JSON_C_TO_STRING_PLAIN, and verifies.  Both sides use
 *   json-c's PLAIN flag, which preserves insertion order across
 *   the parse → mutate → serialize cycle.
 *
 * Returns:
 *   0   on success (resp is mutated in place).
 *  -1   on signing / encoding failure.  Caller should NOT send the
 *       response — the leaf would refuse it anyway.
 ******************************************************************************/
static int add_cosigner_sig_to_response(MtcStore *store,
                                        struct json_object *resp)
{
    char cosigner_pem[8192];
    int  cosigner_pem_sz = mtc_store_get_public_key_pem(
        store, cosigner_pem, (int)sizeof(cosigner_pem));
    if (cosigner_pem_sz <= 0) {
        LOG_ERROR("bootstrap: cannot export cosigner PEM (rc=%d)",
                  cosigner_pem_sz);
        return -1;
    }
    json_object_object_add(resp, "ca_cosigner_pem",
        json_object_new_string_len(cosigner_pem, cosigner_pem_sz));

    /* Sign the canonical JSON of the response WITHOUT the signature
     * field.  Verifier rebuilds the same bytes by deleting
     * ca_response_sig from the parsed object and re-serializing
     * with the same PLAIN flag. */
    const char *to_sign = json_object_to_json_string_ext(
        resp, JSON_C_TO_STRING_PLAIN);
    int to_sign_len = (int)strlen(to_sign);

    uint8_t  sig[DILITHIUM_LEVEL5_SIG_SIZE];
    word32   sig_sz = (word32)sizeof(sig);
    {
        dilithium_key dil;
        WC_RNG        rng;
        int           ret;
        word32        idx_w = 0;

        if ((ret = wc_InitRng(&rng)) != 0) {
            LOG_ERROR("bootstrap: wc_InitRng failed (rc=%d)", ret);
            return -1;
        }
        if ((ret = wc_dilithium_init(&dil)) != 0) {
            wc_FreeRng(&rng);
            LOG_ERROR("bootstrap: wc_dilithium_init failed (rc=%d)", ret);
            return -1;
        }
        if ((ret = wc_dilithium_set_level(&dil, WC_ML_DSA_87)) != 0) {
            wc_dilithium_free(&dil);
            wc_FreeRng(&rng);
            LOG_ERROR("bootstrap: dilithium_set_level (rc=%d)", ret);
            return -1;
        }
        if ((ret = wc_Dilithium_PrivateKeyDecode(
                 store->ca_priv_key, &idx_w, &dil,
                 (word32)store->ca_priv_key_sz)) != 0) {
            wc_dilithium_free(&dil);
            wc_FreeRng(&rng);
            LOG_ERROR("bootstrap: Dilithium_PrivateKeyDecode (rc=%d)",
                      ret);
            return -1;
        }
        ret = wc_dilithium_sign_ctx_msg(
            (const byte *)MTC_BOOTSTRAP_LABEL,
            MTC_BOOTSTRAP_LABEL_LEN,
            (const byte *)to_sign, (word32)to_sign_len,
            sig, &sig_sz, &dil, &rng);
        wc_dilithium_free(&dil);
        wc_FreeRng(&rng);
        if (ret != 0) {
            LOG_ERROR("bootstrap: dilithium_sign (rc=%d)", ret);
            return -1;
        }
    }

    /* Hex-encode signature (consistent with other binary blobs in
     * this codebase — see cosignatures field in mtc_store_cosign).
     * 4627 sig bytes → 9254 hex chars + NUL. */
    char *sig_hex = (char *)malloc((size_t)sig_sz * 2 + 1);
    if (!sig_hex) {
        LOG_ERROR("bootstrap: out of memory for sig_hex");
        return -1;
    }
    {
        int i;
        for (i = 0; i < (int)sig_sz; i++)
            snprintf(sig_hex + i * 2, 3, "%02x", sig[i]);
    }
    json_object_object_add(resp, "ca_response_sig",
        json_object_new_string(sig_hex));
    free(sig_hex);
    return 0;
}

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
 * Function:    bootstrap_path_allowed  (static)
 *
 * Description:
 *   Allowlist gate for the {"op":"http_get",...} bootstrap proxy
 *   (TODO #67 / ChatGPT review item #8).  Only the read-only API
 *   surface that bootstrap clients legitimately need over the
 *   pre-trust-anchor channel is allowed; anything else (including a
 *   hypothetical future POST endpoint accidentally added to
 *   dispatch_get) is refused before reaching dispatch_get_capture.
 *
 *   The allowlist intentionally tracks what dispatch_get itself
 *   exposes.  When a new public GET endpoint is added there, this
 *   list MUST be extended too — otherwise bootstrap clients lose
 *   visibility on the new endpoint.
 ******************************************************************************/
static int bootstrap_path_allowed(const char *path)
{
    if (!path || path[0] != '/')
        return 0;

    /* Exact-match endpoints. */
    static const char *const exact[] = {
        "/log",
        "/log/checkpoint",
        "/trust-anchors",
        "/revoked",
        "/ca/public-key",
        "/ech/configs",
        NULL
    };
    for (size_t i = 0; exact[i]; i++) {
        if (strcmp(path, exact[i]) == 0)
            return 1;
    }

    /* Prefix-match endpoints (require something non-empty after
     * the prefix so e.g. "/certificate/" alone doesn't match — the
     * dispatch_get layer would 400 it anyway, but rejecting earlier
     * keeps the failure surface small). */
    static const char *const prefix[] = {
        "/log/entry/",
        "/log/proof/",
        "/log/consistency",      /* ?from=&to= query string */
        "/certificate/search",   /* ?subject=...           */
        "/certificate/",
        "/revoked/",
        "/public-key/",
        NULL
    };
    for (size_t i = 0; prefix[i]; i++) {
        size_t n = strlen(prefix[i]);
        if (strncmp(path, prefix[i], n) == 0)
            return 1;
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
 *
 *   Path is gated by bootstrap_path_allowed (TODO #67 allowlist).
 ******************************************************************************/
static int send_http_get_proxy(int fd, MtcStore *store, const char *path)
{
    char *inner_body = NULL;
    int inner_status = 0;
    struct json_object *outer;
    const char *json_str;
    int rc = -1;

    if (!bootstrap_path_allowed(path)) {
        LOG_WARN("bootstrap: http_get rejected (path='%s', not in allowlist)",
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
 *   Reply to a {"op":"ca_pubkey"} bootstrap request with the CA's
 *   ML-DSA-87 log-cosigner public key as plaintext JSON — no DH
 *   exchange.  Same payload shape as GET /ca/public-key on the HTTP
 *   port so clients can reuse parsing.  Safe in the clear: it is a
 *   public key, and clients must TOFU-pin it regardless of transport.
 ******************************************************************************/
static int send_ca_pubkey_plaintext(int fd, MtcStore *store)
{
    struct json_object *obj;
    /* ML-DSA-87 PEM-wrapped DER is ~3.5 KiB; size generously. */
    char pem[8192];
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
        json_object_new_string("ML-DSA-87"));

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
    uint8_t aes_keys[BOOTSTRAP_AES_KEYS_TOTAL];   /* c2s||s2c */
    uint8_t pop_nonce[BOOTSTRAP_POP_NONCE_SZ];
    char    pop_nonce_hex[BOOTSTRAP_POP_NONCE_SZ * 2 + 1];

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

    /* Generate random PoP nonce (issue #5) — included in the
     * plaintext DH reply; the CA-enrollment client signs it under
     * the submitted CA private key to prove possession. */
    if (wc_RNG_GenerateBlock(&rng, pop_nonce, BOOTSTRAP_POP_NONCE_SZ) != 0) {
        LOG_ERROR("bootstrap: pop_nonce generation failed");
        goto cleanup;
    }
    to_hex(pop_nonce, BOOTSTRAP_POP_NONCE_SZ, pop_nonce_hex);

    /* TODO #62: derive 64 bytes via HKDF — first 32 = c2s_key,
     * last 32 = s2c_key.  Per-direction keys eliminate any
     * GCM-nonce-reuse risk across directions. */
    if (wc_HKDF(WC_SHA256, shared_secret, shared_sz,
                 salt, BOOTSTRAP_SALT_SZ,
                 (const byte *)BOOTSTRAP_HKDF_INFO,
                 (word32)strlen(BOOTSTRAP_HKDF_INFO),
                 aes_keys, BOOTSTRAP_AES_KEYS_TOTAL) != 0) {
        LOG_ERROR("bootstrap: HKDF key derivation failed");
        goto cleanup;
    }

    LOG_DEBUG("bootstrap: DH exchange complete, AES-256-GCM keys derived");

    /* --- Build + send server DH response (plaintext JSON, P0 #63
     *     signed-transcript fields added) --- */
    {
        struct json_object *resp;
        char pub_hex[CURVE25519_KEYSIZE * 2 + 1];
        char salt_hex[BOOTSTRAP_SALT_SZ * 2 + 1];
        char cosigner_pem[8192];
        int  cosigner_pem_sz;
        const char *resp_str;
        size_t resp_len;

        to_hex(server_pub, CURVE25519_KEYSIZE, pub_hex);
        to_hex(salt, BOOTSTRAP_SALT_SZ, salt_hex);

        resp = json_object_new_object();
        json_object_object_add(resp, "dh_public_key",
            json_object_new_string(pub_hex));
        json_object_object_add(resp, "salt",
            json_object_new_string(salt_hex));
        json_object_object_add(resp, "pop_nonce",
            json_object_new_string(pop_nonce_hex));
        json_object_object_add(resp, "protocol_version",
            json_object_new_int(MTC_BOOTSTRAP_PROTO_V1));

        /* P0 #63: include the cosigner PEM so the client can verify
         * the transcript signature without a prior PEM fetch. */
        cosigner_pem_sz = mtc_store_get_public_key_pem(
            store, cosigner_pem, (int)sizeof(cosigner_pem));
        if (cosigner_pem_sz <= 0) {
            LOG_ERROR("bootstrap: cannot export cosigner PEM "
                      "(rc=%d)", cosigner_pem_sz);
            json_object_put(resp);
            goto cleanup;
        }
        json_object_object_add(resp, "ca_cosigner_pem",
            json_object_new_string_len(cosigner_pem, cosigner_pem_sz));

        /* P0 #63: ML-DSA-87 sign the DH transcript so a MitM
         * substituting either side's DH key invalidates the
         * signature.  Message:
         *
         *   client_dh_pub (32) || server_dh_pub (32) ||
         *   salt          (16) || pop_nonce     (32) ||
         *   protocol_version (1 byte)
         *
         * Total 113 bytes.  ctx = MTC_BOOTSTRAP_DH_LABEL (16). */
        {
            unsigned char sig_msg[CURVE25519_KEYSIZE * 2 +
                                  BOOTSTRAP_SALT_SZ +
                                  BOOTSTRAP_POP_NONCE_SZ + 1];
            unsigned int  sig_msg_len = 0;
            uint8_t       sig[DILITHIUM_LEVEL5_SIG_SIZE];
            word32        sig_sz = (word32)sizeof(sig);
            int           sign_rc = -1;

            memcpy(sig_msg + sig_msg_len, client_pub,
                   CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, server_pub,
                   CURVE25519_KEYSIZE);
            sig_msg_len += CURVE25519_KEYSIZE;
            memcpy(sig_msg + sig_msg_len, salt, BOOTSTRAP_SALT_SZ);
            sig_msg_len += BOOTSTRAP_SALT_SZ;
            memcpy(sig_msg + sig_msg_len, pop_nonce,
                   BOOTSTRAP_POP_NONCE_SZ);
            sig_msg_len += BOOTSTRAP_POP_NONCE_SZ;
            sig_msg[sig_msg_len++] = MTC_BOOTSTRAP_PROTO_V1;

            {
                dilithium_key dil;
                WC_RNG        sign_rng;
                int           ret2;
                word32        idx_w = 0;

                if ((ret2 = wc_InitRng(&sign_rng)) == 0) {
                    if ((ret2 = wc_dilithium_init(&dil)) == 0) {
                        if ((ret2 = wc_dilithium_set_level(
                                 &dil, WC_ML_DSA_87)) == 0 &&
                            (ret2 = wc_Dilithium_PrivateKeyDecode(
                                 store->ca_priv_key, &idx_w, &dil,
                                 (word32)store->ca_priv_key_sz)) == 0) {
                            ret2 = wc_dilithium_sign_ctx_msg(
                                (const byte *)MTC_BOOTSTRAP_DH_LABEL,
                                MTC_BOOTSTRAP_DH_LABEL_LEN,
                                sig_msg, sig_msg_len,
                                sig, &sig_sz, &dil, &sign_rng);
                            if (ret2 == 0) sign_rc = 0;
                        }
                        wc_dilithium_free(&dil);
                    }
                    wc_FreeRng(&sign_rng);
                }
                if (sign_rc != 0)
                    LOG_ERROR("bootstrap: DH-transcript sign rc=%d",
                              ret2);
            }

            if (sign_rc != 0) {
                json_object_put(resp);
                goto cleanup;
            }

            char *sig_hex = (char *)malloc((size_t)sig_sz * 2 + 1);
            if (!sig_hex) {
                json_object_put(resp);
                goto cleanup;
            }
            to_hex(sig, (int)sig_sz, sig_hex);
            json_object_object_add(resp, "transcript_sig",
                json_object_new_string(sig_hex));
            free(sig_hex);
        }

        resp_str = json_object_to_json_string(resp);
        resp_len = strlen(resp_str);
        if (resp_len >= sizeof(json_buf)) {
            LOG_ERROR("bootstrap: step-2 response too large (%zu)",
                      resp_len);
            json_object_put(resp);
            goto cleanup;
        }
        if (write_all(fd, (unsigned char *)resp_str,
                      (unsigned int)resp_len) != 0) {
            LOG_WARN("bootstrap: failed to send DH response");
            json_object_put(resp);
            goto cleanup;
        }
        json_object_put(resp);
    }

    /* --- Init mtc_crypt with derived keys (TODO #62 AEAD) --- */
    crypt_ctx = mtc_crypt_init(aes_keys,                          /* c2s */
                               aes_keys + BOOTSTRAP_AES_KEY_SZ);  /* s2c */
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
    if (mtc_crypt_decode(crypt_ctx, MTC_DIR_C2S, enc_buf, (unsigned int)ret,
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
            char x509_spki_fp[65] = {0};
            char x509_san[256] = {0};
            LOG_INFO("bootstrap: CA enrollment request for '%s'", subject);
            if (!mtc_validate_ca_cert(extensions,
                                      x509_spki_fp, sizeof(x509_spki_fp),
                                      x509_san, sizeof(x509_san))) {
                LOG_WARN("bootstrap: CA validation failed for '%s'", subject);
                {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"CA certificate rejected: "
                        "DNS validation failed\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C, (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                }
                goto cleanup;
            }

            /* Subject must equal "<SAN>-ca" (TODO #37).  Without this an
             * attacker who owns DNS for bar.com could submit an X.509
             * with SAN=bar.com alongside subject=factsorlie.com-ca and
             * claim a CA slot for a domain they don't own. */
            if (x509_san[0]) {
                char expected_subject[260];
                snprintf(expected_subject, sizeof(expected_subject),
                         "%s-ca", x509_san);
                if (strcmp(subject, expected_subject) != 0) {
                    LOG_WARN("bootstrap: CA enrollment refused — subject "
                             "'%s' does not match SAN-derived expected "
                             "subject '%s'",
                             subject, expected_subject);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"subject must equal "
                            "<X.509 SAN DNS name>-ca — the enrollment "
                            "subject and the CA cert's SAN must "
                            "describe the same domain.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }
            }

            /* Cross-check that the top-level public_key_pem hashes to the
             * same SPKI fingerprint as the X.509 cert.  Without this an
             * attacker could submit the legitimate operator's public X.509
             * (which passes DNS validation) in ca_certificate_pem while
             * planting their own public_key_pem at the top level — the
             * minted cert would then bind to the attacker's key.
             *
             * Both sides MUST use the same canonical hash:
             * SHA3-256 over the SubjectPublicKeyInfo DER.  The cert
             * side (mtc_validate_ca_cert in mtc_ca_validate.c)
             * computes that via wc_GetSubjectPubKeyInfoDerFromCert +
             * wc_Sha3_256_*; the PEM side decodes the PEM with
             * wc_PubKeyPemToDer (which produces the same SPKI DER)
             * and runs the same SHA3-256.  Pre-mqc-3-server this
             * arm hashed SHA-256(PEM text bytes), which can never
             * match SHA3-256(SPKI DER) — the cross-check was a
             * no-op (always rejected) for any well-formed CA
             * enrollment.  README-issues.md issue #1. */
            if (x509_spki_fp[0]) {
                unsigned char spki_der[4096]; /* ML-DSA-87 SPKI ~2.6 KB */
                int spki_der_sz;
                wc_Sha3 sha_pk;
                uint8_t pk_h[WC_SHA3_256_DIGEST_SIZE];
                char pk_fp[65];
                int pi;

                spki_der_sz = wc_PubKeyPemToDer(
                    (const unsigned char *)pub_key_pem,
                    (int)strlen(pub_key_pem),
                    spki_der, (int)sizeof(spki_der));
                if (spki_der_sz <= 0) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "public_key_pem PEM-to-DER failed (%d)",
                             spki_der_sz);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"public_key_pem is not a "
                            "valid PEM-encoded public key.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }

                wc_InitSha3_256(&sha_pk, NULL, INVALID_DEVID);
                wc_Sha3_256_Update(&sha_pk, spki_der, (word32)spki_der_sz);
                wc_Sha3_256_Final(&sha_pk, pk_h);
                wc_Sha3_256_Free(&sha_pk);
                for (pi = 0; pi < WC_SHA3_256_DIGEST_SIZE; pi++)
                    snprintf(pk_fp + pi * 2, 3, "%02x", pk_h[pi]);
                pk_fp[64] = '\0';

                if (strcmp(pk_fp, x509_spki_fp) != 0) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "public_key_pem fp %.16s... does not match "
                             "ca_certificate_pem SPKI fp %.16s...",
                             pk_fp, x509_spki_fp);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"public_key_pem does not match "
                            "ca_certificate_pem SPKI — both fields must "
                            "carry the same public key.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }
            }

            /* Revocation gate: if the most-recent CA entry for this
             * subject is revoked, the server operator has explicitly
             * said "no" to this domain.  Refuse re-enrollment.  The
             * CA subject is "<domain>-ca" (per bootstrap_ca.c's
             * convention) — `subject` already carries that suffix
             * because the earlier expected-subject check above
             * required `subject == <x509_san>-ca`.
             *
             * Pre-fix this block re-appended "-ca" and looked up
             * "<domain>-ca-ca" in the cert store; nothing ever
             * matched, so the revocation gate was a no-op and
             * revoked CAs could silently re-enroll.
             * README-issues.md issue #2. */
            {
                char ca_subject[520];
                int latest_idx = -1;
                int k;

                snprintf(ca_subject, sizeof(ca_subject), "%s", subject);
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
                            "Open an issue at "
                            "https://github.com/cpsource/postWolf/issues "
                            "to request the revocation be lifted before "
                            "re-enrolling.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }
            }

            /* Proof-of-possession (issue #5): verify the client
             * signed `MQC-CA-REGISTER|<domain>|<subject>|<spki_hash>|
             * <pop_nonce_hex>` with the CA private key whose public
             * half is in public_key_pem.  DNSSEC pinning (issue #3)
             * proves the published TXT names this SPKI; this PoP
             * proves the requester actually controls the matching
             * private key. */
            {
                struct json_object *sig_val = NULL;
                const char *sig_hex = NULL;
                size_t sig_hex_len;
                unsigned char sig_bin[DILITHIUM_LEVEL5_SIG_SIZE];
                size_t sig_bin_len = 0;
                unsigned char spki_der[4096];
                int spki_der_sz;
                dilithium_key dil_pub;
                int dil_pub_init = 0;
                int verified = 0;
                char pop_msg[1024];
                int pop_msg_len;
                int pop_ok = 0;

                if (!json_object_object_get_ex(req, "pop_signature",
                                               &sig_val) ||
                    (sig_hex = json_object_get_string(sig_val)) == NULL) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "missing pop_signature");
                    goto pop_fail;
                }
                sig_hex_len = strlen(sig_hex);
                if (sig_hex_len != DILITHIUM_LEVEL5_SIG_SIZE * 2) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "pop_signature wrong length: %zu (expect %d)",
                             sig_hex_len, DILITHIUM_LEVEL5_SIG_SIZE * 2);
                    goto pop_fail;
                }
                if (hex_to_bytes(sig_hex, sig_bin,
                                 DILITHIUM_LEVEL5_SIG_SIZE)
                    != DILITHIUM_LEVEL5_SIG_SIZE) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "pop_signature is not valid hex");
                    goto pop_fail;
                }
                sig_bin_len = DILITHIUM_LEVEL5_SIG_SIZE;

                /* Build the canonical signed message.  Both sides
                 * MUST construct the same byte sequence here.
                 *   PREFIX|domain|subject|spki_hash_hex|pop_nonce_hex
                 * domain = SAN extracted from the cert (no -ca);
                 * subject = the wire-subject ("<domain>-ca"). */
                pop_msg_len = snprintf(pop_msg, sizeof(pop_msg),
                    "%s|%s|%s|%s|%s",
                    MTC_CA_POP_PREFIX, x509_san, subject,
                    x509_spki_fp, pop_nonce_hex);
                if (pop_msg_len <= 0 ||
                    pop_msg_len >= (int)sizeof(pop_msg)) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "pop_msg too large");
                    goto pop_fail;
                }

                /* Decode the operator-supplied PEM to SPKI DER and
                 * load it as an ML-DSA-87 public key. */
                spki_der_sz = wc_PubKeyPemToDer(
                    (const unsigned char *)pub_key_pem,
                    (int)strlen(pub_key_pem),
                    spki_der, (int)sizeof(spki_der));
                if (spki_der_sz <= 0) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "public_key_pem PEM-to-DER for PoP failed (%d)",
                             spki_der_sz);
                    goto pop_fail;
                }
                wc_dilithium_init(&dil_pub);
                dil_pub_init = 1;
                wc_dilithium_set_level(&dil_pub, WC_ML_DSA_87);
                {
                    word32 idx = 0;
                    if (wc_Dilithium_PublicKeyDecode(spki_der, &idx,
                            &dil_pub, (word32)spki_der_sz) != 0) {
                        LOG_WARN("bootstrap: CA enrollment refused — "
                                 "ML-DSA-87 public-key decode failed for PoP");
                        goto pop_fail;
                    }
                }

                if (wc_dilithium_verify_ctx_msg(
                        sig_bin, (word32)sig_bin_len,
                        (const byte *)MTC_CA_POP_LABEL,
                        MTC_CA_POP_LABEL_LEN,
                        (const byte *)pop_msg, (word32)pop_msg_len,
                        &verified, &dil_pub) != 0 || !verified) {
                    LOG_WARN("bootstrap: CA enrollment refused — "
                             "PoP signature INVALID under submitted "
                             "public_key_pem (subject=%s)", subject);
                    goto pop_fail;
                }

                LOG_INFO("bootstrap: PoP signature verified for '%s'",
                         subject);
                pop_ok = 1;

            pop_fail:
                if (dil_pub_init) wc_dilithium_free(&dil_pub);
                if (!pop_ok) {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"CA enrollment refused: "
                        "proof-of-possession signature missing or "
                        "invalid.  Rebuild bootstrap_ca from a tree "
                        "that includes the README-issues.md issue #5 "
                        "fix.\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                            (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                    goto cleanup;
                }
            }

            LOG_INFO("bootstrap: CA enrollment for '%s' authorized",
                     subject);
        } else {
            /* Leaf enrollment: nonce required */
            wc_Sha256 sha;

            /* Explicit "-ca" suffix reject (defence-in-depth, TODO #36).
             * The nonce-validation path already blocks this implicitly
             * because validate_and_consume_nonce receives the submitted
             * subject as its domain arg and a CA wouldn't issue a nonce
             * for "<domain>-ca".  But an explicit reject makes the
             * invariant resilient to refactors that decouple subject
             * from domain. */
            {
                size_t slen = strlen(subject);
                if (slen >= 3 && strcmp(subject + slen - 3, "-ca") == 0) {
                    LOG_WARN("bootstrap: leaf enrollment refused — "
                             "subject '%s' ends in '-ca'; CA subjects "
                             "go through the CA bootstrap path with "
                             "an X.509 + DNS proof, not a leaf nonce",
                             subject);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"leaf subject must not end in "
                            "'-ca' — use CA bootstrap (ca_certificate_pem "
                            "in extensions) for CA enrollments.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }
            }

            if (!enrollment_nonce) {
                LOG_WARN("bootstrap: missing enrollment_nonce for leaf '%s'",
                         subject);
                {
                    const char *err_json = "{\"status\":\"error\","
                        "\"message\":\"enrollment_nonce required for leaf\"}";
                    unsigned int err_enc_len = sizeof(enc_buf);
                    if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C, (unsigned char *)err_json,
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
                    if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C, (unsigned char *)err_json,
                            (unsigned int)strlen(err_json),
                            enc_buf, &err_enc_len) == 0) {
                        send_length_prefixed(fd, enc_buf, err_enc_len);
                    }
                }
                goto cleanup;
            }

            /* Duplicate + revocation gate on (subject, SPKI fp):
             *   active match   → LOG_WARN, allow (ghost entry per
             *                    TODO #32; visible in syslog so
             *                    operators can spot duplicates)
             *   revoked match  → reject (revocation veto)
             *   expired-only   → allow silently (old cert is dead)
             *   no match       → allow silently (first enrollment)
             *
             * Matching by (subject, fp) not subject alone because
             * labels (~/.TPM/<domain>-Jane/ vs -John/) are local-only
             * (TODO #26) and share the same cert subject.  Blocking
             * on subject alone would revoke Jane and lock John out.
             * The CA-issued nonce remains the primary authorization;
             * the revocation branch is defense-in-depth against
             * resurrecting a known-revoked key. */
            {
                int latest_active_idx = -1;
                int latest_revoked_idx = -1;
                double now_ts = (double)time(NULL);
                int k;
                for (k = 0; k < store->cert_count; k++) {
                    struct json_object *entry = store->certificates[k];
                    struct json_object *sc_j, *tbs_j, *subj_j, *fp_j, *na_j;
                    const char *entry_subj, *entry_fp;
                    double entry_not_after;
                    if (!entry) continue;
                    if (!json_object_object_get_ex(entry, "standalone_certificate", &sc_j)) continue;
                    if (!json_object_object_get_ex(sc_j, "tbs_entry", &tbs_j)) continue;
                    if (!json_object_object_get_ex(tbs_j, "subject", &subj_j)) continue;
                    if (!json_object_object_get_ex(tbs_j, "subject_public_key_hash", &fp_j)) continue;
                    if (!json_object_object_get_ex(tbs_j, "not_after", &na_j)) continue;
                    entry_subj = json_object_get_string(subj_j);
                    entry_fp = json_object_get_string(fp_j);
                    entry_not_after = json_object_get_double(na_j);
                    if (!entry_subj || !entry_fp) continue;
                    if (strcmp(entry_subj, subject) != 0) continue;
                    if (strcmp(entry_fp, leaf_fp) != 0) continue;

                    if (mtc_store_is_revoked(store, k)) {
                        latest_revoked_idx = k;
                    } else if (entry_not_after > now_ts) {
                        latest_active_idx = k;
                    }
                    /* else: expired and not revoked — silently ignore */
                }

                if (latest_revoked_idx >= 0) {
                    LOG_WARN("bootstrap: leaf enrollment refused — prior "
                             "cert for '%s' with same key fp (index %d) "
                             "is revoked",
                             subject, latest_revoked_idx);
                    {
                        const char *err_json = "{\"status\":\"error\","
                            "\"message\":\"leaf enrollment refused: this "
                            "exact public key was previously issued a "
                            "certificate that has since been revoked. "
                            "Generate a fresh keypair (register-leaf.sh "
                            "--force-keygen) and have your CA issue a "
                            "new nonce.\"}";
                        unsigned int err_enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)err_json,
                                (unsigned int)strlen(err_json),
                                enc_buf, &err_enc_len) == 0) {
                            send_length_prefixed(fd, enc_buf, err_enc_len);
                        }
                    }
                    goto cleanup;
                }

                if (latest_active_idx >= 0) {
                    LOG_WARN("bootstrap: leaf '%s' already has an active "
                             "cert with the same key fp at index %d — "
                             "proceeding, but this creates a ghost log "
                             "entry (TODO #32)",
                             subject, latest_active_idx);
                }

                /* allow through */
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
        uint8_t sig[DILITHIUM_LEVEL5_SIG_SIZE];
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

        /* TODO #57 idempotency check.
         *
         * If a live (non-revoked, in-validity-window) cert already
         * exists for this (subject, spk_hash) pair, return it
         * verbatim instead of issuing a fresh entry.  Closes the
         * fork-after-accept duplicate-idx race that produced the
         * cert/leaf divergence on frflashy.com's enrollment: same
         * (subject, public_key) re-enrollment used to append a new
         * row at idx N+1 with a different not_before timestamp,
         * causing the cosignature to be over a tree state that
         * didn't match the leaf actually persisted in the DB.  Now
         * the second invocation just gets the first one's cert
         * back. */
        if (store->use_db && store->db) {
            int existing_idx =
                mtc_db_find_live_cert_by_pubkey_hash(store->db,
                                                     subject, spk_hash);
            if (existing_idx >= 0) {
                struct json_object *existing =
                    mtc_db_load_certificate(store->db, existing_idx);
                if (existing) {
                    /* Refresh the response's outer checkpoint to the
                     * current STH (the cert's own cosignature is
                     * self-contained over its issue-time subtree, so
                     * stale outer checkpoint is not load-bearing for
                     * verification, but a fresh one keeps clients
                     * happier when they cross-reference). */
                    struct json_object *cur_ckpt =
                        mtc_store_checkpoint(store);
                    if (cur_ckpt) {
                        json_object_object_add(existing, "checkpoint",
                            json_object_get(cur_ckpt));
                        json_object_put(cur_ckpt);
                    }

                    /* Add the (in-flight only) label if requested. */
                    if (bootstrap_label[0]) {
                        json_object_object_add(existing, "label",
                            json_object_new_string(bootstrap_label));
                    }

                    /* P0 / TODO #9b leaf branch — also sign the
                     * idempotent re-enroll response so a leaf that
                     * happens to land on this path (same key, same
                     * subject) still gets a verifiable cosigner PEM
                     * to pin.  Without this the leaf would refuse
                     * the reply with "missing P0 #9b fields". */
                    if (add_cosigner_sig_to_response(store, existing) != 0) {
                        LOG_WARN("bootstrap: idempotent re-enroll for "
                                 "'%s' could not sign response — "
                                 "dropping connection", subject);
                        json_object_put(existing);
                        goto cleanup;
                    }

                    {
                        const char *resp_str =
                            json_object_to_json_string(existing);
                        enc_len = sizeof(enc_buf);
                        if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C,
                                (unsigned char *)resp_str,
                                (unsigned int)strlen(resp_str),
                                enc_buf, &enc_len) == 0 &&
                            send_length_prefixed(fd, enc_buf, enc_len) == 0)
                        {
                            LOG_INFO("bootstrap: idempotent re-enroll for "
                                     "'%s' returned existing cert at "
                                     "index %d (TODO #57)",
                                     subject, existing_idx);
                        } else {
                            LOG_WARN("bootstrap: failed to send idempotent "
                                     "response for existing cert %d",
                                     existing_idx);
                        }
                    }

                    json_object_put(existing);
                    goto cleanup;
                }
            }
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

        /* Add to log.  Failure here means the DB write didn't commit
         * — abort the enrollment cleanly rather than continue with
         * an in-memory-only entry that will silently disappear at the
         * next service restart (TODO #57 item 4). */
        index = mtc_store_add_entry(store, entry_buf, entry_sz);
        if (index < 0) {
            LOG_ERROR("bootstrap: mtc_store_add_entry failed for '%s' "
                      "(DB persist error) — aborting enrollment", subject);
            json_object_put(tbs);
            free(entry_buf);
            goto cleanup;
        }

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
            /* ML-DSA-87 signature = 4627 bytes → 9254 hex chars + NUL.
             * Heap-allocate to keep the per-connection stack small. */
            char *sig_hex = (char *)malloc((size_t)sig_sz * 2 + 1);
            if (sig_hex) {
                to_hex(sig, sig_sz, sig_hex);
                json_object_object_add(cosig_obj, "signature",
                    json_object_new_string(sig_hex));
                free(sig_hex);
            }
        }
        json_object_object_add(cosig_obj, "algorithm",
            json_object_new_string("ML-DSA-87"));
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
            /* Record the pubkey under the same directory-naming
             * convention the client uses under ~/.TPM/:
             *     subject                for an unlabelled leaf/CA
             *     subject-label          for a labelled leaf
             * This keeps /public-key/<name> self-serving from the
             * server without relying on the client to push the
             * pubkey into Neon out of band. */
            {
                char key_name[256];
                if (bootstrap_label[0])
                    snprintf(key_name, sizeof(key_name), "%s-%s",
                             subject, bootstrap_label);
                else
                    snprintf(key_name, sizeof(key_name), "%s", subject);
                if (mtc_db_save_public_key(store->db, key_name,
                                           pub_key_pem) != 0) {
                    fprintf(stderr,
                        "[bootstrap] WARNING: DB save_public_key failed "
                        "for %s\n", key_name);
                }
            }
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

        /* P0 / TODO #9b leaf branch — bind cosigner PEM into the
         * response and sign the canonical JSON.  Helper appends both
         * ca_cosigner_pem (whole PEM) and ca_response_sig (hex
         * ML-DSA-87 signature over the canonical JSON of the
         * response BEFORE the signature field is added). */
        if (add_cosigner_sig_to_response(store, wire_resp) != 0) {
            json_object_put(wire_resp);
            json_object_put(result);
            json_object_put(tbs);
            json_object_put(checkpoint);
            free(proof);
            free(entry_buf);
            goto cleanup;
        }

        {
            const char *result_str = json_object_to_json_string(wire_resp);
            enc_len = sizeof(enc_buf);
            if (mtc_crypt_encode(crypt_ctx, MTC_DIR_S2C, (unsigned char *)result_str,
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

                /* Tell the parent its in-memory MtcStore is now stale
                 * (TODO #56 fix).  We're a forked child; the parent's
                 * reload_thread sigwait()s on SIGHUP and calls
                 * mtc_store_reload to refresh the tree/cert arrays
                 * from the DB.  Without this, /certificate/N for the
                 * just-issued index returns 404 from the parent's
                 * stale view until the next service restart. */
                if (kill(getppid(), SIGHUP) != 0) {
                    LOG_WARN("bootstrap: kill(getppid, SIGHUP) failed: %s",
                             strerror(errno));
                }
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
    secure_zero(aes_keys, sizeof(aes_keys));
    secure_zero(salt, sizeof(salt));
    return 0;

cleanup:
    if (req) json_object_put(req);
    if (crypt_ctx) mtc_crypt_fin(crypt_ctx);
    if (client_key_ok) wc_curve25519_free(&client_key);
    if (server_key_ok) wc_curve25519_free(&server_key);
    if (rng_ok) wc_FreeRng(&rng);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_keys, sizeof(aes_keys));
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

        /* TODO #65: gate accept() on the active-child counter so a
         * connection flood can't fork-storm the host.  Same global
         * mqc-max-children cap the TLS/plain/MQC listeners use; see
         * mtc_http.c::mtc_wait_for_child_slot. */
        mtc_wait_for_child_slot("bootstrap");

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
                /* Parent: drop socket fd — child holds its own ref.
                 * TODO #65: count this child against the global
                 * mqc-max-children cap.  SIGCHLD reaper (in
                 * mtc_http.c) decrements on exit. */
                mtc_register_active_child();
                LOG_DEBUG("bootstrap: forked child pid=%d", (int)pid);
                close(client_fd);
                continue;
            }
            /* Child: no longer needs the listen socket. */
            LOG_DEBUG("bootstrap: child pid=%d handling conn", (int)getpid());
            close(listen_fd);
            /* Detach from the parent's PGconn — see comment at the
             * TLS/plain fork site in mtc_http.c.  Fixes TODO #25
             * (gratuitous reconnect churn). */
            mtc_db_after_fork(&store->db);
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
