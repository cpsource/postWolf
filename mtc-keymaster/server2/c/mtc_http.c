#define _GNU_SOURCE  /* for strcasestr */

/******************************************************************************
 * File:        mtc_http.c
 * Purpose:     Minimal single-threaded HTTP server for the MTC CA/Log.
 *
 * Description:
 *   Implements the REST API endpoints matching the Python server.  Uses
 *   raw sockets with an I/O abstraction layer (client_io) that supports
 *   both plain TCP and TLS via the slc library.  Request parsing is
 *   hand-rolled (no external HTTP library).
 *
 *   API endpoints:
 *     GET  /                        — server info
 *     GET  /log                     — tree state (size, root, landmarks)
 *     GET  /log/entry/<n>           — single log entry
 *     GET  /log/proof/<n>           — inclusion proof
 *     GET  /log/checkpoint          — latest checkpoint
 *     GET  /log/consistency?old=&new= — consistency proof
 *     GET  /certificate/<n>         — certificate by index
 *     GET  /certificate/search?q=   — search by subject
 *     GET  /trust-anchors           — trust anchor list
 *     GET  /ca/public-key           — CA ML-DSA-87 public key
 *     GET  /ech/configs             — ECH config (base64)
 *     GET  /revoked                 — revocation list
 *     GET  /revoked/<n>             — revocation check
 *     POST /enrollment/nonce        — issue enrollment nonce
 *     POST /certificate/request     — enroll (CA or leaf)
 *     POST /renew-cert              — renew (MQC-authenticated, 8446 only)
 *     POST /cancel-nonce            — retract a pending reservation nonce (MQC-only, issuer CA only)
 *     POST /revoke                  — revoke a certificate
 *
 * Dependencies:
 *   mtc_http.h, mtc_checkendpoint.h, mtc_log.h, mtc_ratelimit.h
 *   stdio.h, stdlib.h, string.h, unistd.h
 *   sys/socket.h, arpa/inet.h, netinet/in.h, time.h
 *   resolv.h, arpa/nameser.h            (DNS TXT lookups)
 *   wolfssl/wolfcrypt/sha256.h           (fingerprint hashing)
 *   wolfssl/wolfcrypt/asn.h              (certificate parsing)
 *   wolfssl/wolfcrypt/coding.h           (Base64 for ECH)
 *
 * Notes:
 *   - Single-threaded, blocking accept loop.  NOT thread-safe.
 *   - All requests are read into a single HTTP_BUF_SZ buffer.
 *   - Per-IP AbuseIPDB checks run on every connection.
 *   - Per-IP rate limiting is applied per endpoint category.
 *
 * Created:     2026-04-13
 ******************************************************************************/

#include "mtc_http.h"
#include "mtc_checkendpoint.h"
#include "mtc_log.h"
#include "mtc_ca_validate.h"
#include "mtc_domain.h"
#include "mtc_ratelimit.h"
#include "mtc_fips.h"
#include "mqc.h"
#include "../../read-config/read-config.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdatomic.h>

#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sha3.h>           /* P0 #9b CA branch */
#include <wolfssl/wolfcrypt/coding.h>

#define HTTP_BUF_SZ  65536   /**< Maximum HTTP request size (headers + body) */
#define MAX_PATH_SZ  512     /**< Maximum URL path length                     */

/* ------------------------------------------------------------------ */
/* I/O abstraction — TLS (slc) or plain socket                         */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Struct:      client_io
 *
 * Description:
 *   Per-connection I/O context.  Wraps either a TLS connection (slc) or a
 *   plain TCP socket behind a uniform read/write/close interface.  Also
 *   carries the client's IP string for logging and abuse checks.
 *
 *   Lifetime: stack-allocated in the accept loop, valid for the duration
 *   of a single request.  cio_close() must be called before discard.
 ******************************************************************************/
typedef struct {
    slc_conn_t *tls;        /**< TLS connection (non-NULL = TLS mode)      */
    mqc_conn_t *mqc;        /**< MQC connection (non-NULL = MQC mode)      */
    int         fd;         /**< Raw socket fd (used in plain mode, or for
                                 getpeername when TLS is active)            */
    char        ip_str[64]; /**< Client IP string for logging/abuse checks */

    /* In-process capture mode: when capture_body != NULL, response bodies
     * produced by http_send_json/http_send_error are strdup'd into
     * *capture_body (caller frees) and the status code into *capture_status,
     * instead of being written to a socket.  Used by the bootstrap port
     * to proxy GET endpoints through handle_request without a network
     * round-trip. */
    char      **capture_body;
    int        *capture_status;
} client_io;

/******************************************************************************
 * Function:    cio_read
 *
 * Description:
 *   Read from the client, dispatching to TLS or plain socket as appropriate.
 *
 * Input Arguments:
 *   io   - Client I/O context.
 *   buf  - Destination buffer.
 *   sz   - Maximum bytes to read.
 *
 * Returns:
 *   Number of bytes read (>0), 0 on EOF, or <0 on error.
 ******************************************************************************/
static int cio_read(client_io *io, void *buf, int sz)
{
    if (io->mqc)
        return mqc_read(io->mqc, buf, sz);
    if (io->tls)
        return slc_read(io->tls, buf, sz);
    return (int)recv(io->fd, buf, (size_t)sz, 0);
}

/******************************************************************************
 * Function:    cio_write
 *
 * Description:
 *   Write to the client, dispatching to TLS or plain socket as appropriate.
 *
 * Input Arguments:
 *   io   - Client I/O context.
 *   buf  - Data to send.
 *   sz   - Number of bytes to send.
 *
 * Returns:
 *   Number of bytes written (>0), or <0 on error.
 ******************************************************************************/
static int cio_write(client_io *io, const void *buf, int sz)
{
    if (io->mqc)
        return mqc_write(io->mqc, buf, sz);
    if (io->tls)
        return slc_write(io->tls, buf, sz);
    return (int)send(io->fd, buf, (size_t)sz, 0);
}

/******************************************************************************
 * Function:    cio_close
 *
 * Description:
 *   Close the client connection.  Shuts down TLS if active, otherwise
 *   closes the raw socket.  Safe to call multiple times.
 *
 * Input Arguments:
 *   io  - Client I/O context.  After return, io->tls is NULL and
 *         io->fd is -1.
 ******************************************************************************/
static void cio_close(client_io *io)
{
    if (io->mqc) {
        mqc_close(io->mqc);
        io->mqc = NULL;
    } else if (io->tls) {
        slc_close(io->tls);
        io->tls = NULL;
    } else if (io->fd >= 0) {
        close(io->fd);
    }
    io->fd = -1;
}

/* ------------------------------------------------------------------ */
/* HTTP response helpers                                               */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    http_send_json
 *
 * Description:
 *   Send an HTTP response with JSON (or raw string) body.  Includes
 *   security headers (nosniff, DENY framing, no-store cache).
 *
 * Input Arguments:
 *   io        - Client I/O context.
 *   status    - HTTP status code (200, 201, 400, 403, 404, 409, 413, 429).
 *   json_str  - Response body string.
 ******************************************************************************/
static void http_send_json(client_io *io, int status, const char *json_str)
{
    char hdr[512];
    int hdr_len, body_len;
    char *combined;

    if (io->capture_body) {
        if (io->capture_status) *io->capture_status = status;
        *io->capture_body = strdup(json_str);
        return;
    }

    body_len = (int)strlen(json_str);
    hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        status, status == 200 ? "OK" : (status == 201 ? "Created" :
        (status == 403 ? "Forbidden" : (status == 404 ? "Not Found" :
        (status == 409 ? "Conflict" : (status == 413 ? "Payload Too Large" :
        (status == 429 ? "Too Many Requests" : "Bad Request")))))),
        body_len);

    /* Send header + body as a single write so MQC packs them into one
     * AEAD frame.  The MQC client reads one frame per mqc_read() and
     * cannot recover if a second frame arrives larger than the caller's
     * remaining buffer (mqc_read consumes the length prefix before the
     * buffer-size check).  Packing keeps the on-wire message shape
     * single-framed regardless of body size, up to MQC_MAX_MSG (1 MiB).
     * TLS and plain sockets behave the same either way. */
    combined = (char *)malloc((size_t)(hdr_len + body_len));
    if (combined) {
        memcpy(combined, hdr, (size_t)hdr_len);
        memcpy(combined + hdr_len, json_str, (size_t)body_len);
        cio_write(io, combined, hdr_len + body_len);
        free(combined);
    } else {
        /* malloc failure: fall back to two writes.  MQC clients reading
         * >buffer-size bodies may still truncate here, but at least
         * TLS/plain callers continue to work. */
        cio_write(io, hdr, hdr_len);
        cio_write(io, json_str, body_len);
    }
}

/******************************************************************************
 * Function:    http_send_json_obj
 *
 * Description:
 *   Serialize a json_object to a pretty-printed string and send it as an
 *   HTTP JSON response.
 *
 * Input Arguments:
 *   io      - Client I/O context.
 *   status  - HTTP status code.
 *   obj     - json_object to serialize.  Caller retains ownership.
 ******************************************************************************/
static void http_send_json_obj(client_io *io, int status, struct json_object *obj)
{
    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    http_send_json(io, status, s);
}

/******************************************************************************
 * Function:    http_send_error
 *
 * Description:
 *   Send an HTTP error response as {"error": "<msg>"}.
 *
 * Input Arguments:
 *   io      - Client I/O context.
 *   status  - HTTP status code (4xx/5xx).
 *   msg     - Human-readable error message.
 ******************************************************************************/
static void http_send_error(client_io *io, int status, const char *msg)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "error", json_object_new_string(msg));
    http_send_json_obj(io, status, obj);
    json_object_put(obj);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    safe_atoi
 *
 * Description:
 *   Safe integer parse with bounds check.  Accepts digits terminated by
 *   NUL, '?', '&', '\r', or '\n'.  ' ' (space) is deliberately NOT
 *   accepted: URL path components never contain unescaped spaces (per
 *   RFC 3986 they're %20-encoded), and Content-Length's leading
 *   whitespace is stripped by the caller before this function runs.
 *   Historically space was allowed, which let `/certificate/5 OR 1=1`
 *   parse as cert index 5 rather than rejecting outright.
 *
 * Input Arguments:
 *   s        - String to parse.  NULL or empty returns -1.
 *   max_val  - Upper bound (inclusive).
 *
 * Returns:
 *   Parsed integer [0, max_val] on success.
 *  -1  on NULL/empty input, non-numeric content, or out-of-range value.
 ******************************************************************************/
static int safe_atoi(const char *s, int max_val)
{
    long v;
    char *end;
    if (!s || !*s) return -1;
    v = strtol(s, &end, 10);
    if (*end != '\0' && *end != '?' && *end != '&' &&
        *end != '\r' && *end != '\n')
        return -1;
    if (v < 0 || v > max_val)
        return -1;
    return (int)v;
}

/******************************************************************************
 * Function:    to_hex
 *
 * Description:
 *   Convert binary data to a lowercase hex string.
 *
 * Input Arguments:
 *   data  - Binary input.
 *   sz    - Number of bytes in data.
 *   out   - Caller-owned buffer, must be at least (sz * 2 + 1) bytes.
 *           NUL-terminated on return.
 ******************************************************************************/
static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

/* ------------------------------------------------------------------ */
/* API handlers                                                        */
/* ------------------------------------------------------------------ */

/* GET / — server info (version, CA name, log ID, tree size). */
static void handle_index(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "server",
        json_object_new_string("MTC CA/Log Server (C)"));
    json_object_object_add(obj, "version", json_object_new_string("0.1.0"));
    json_object_object_add(obj, "draft",
        json_object_new_string("draft-ietf-plants-merkle-tree-certs-02"));
    json_object_object_add(obj, "ca_name",
        json_object_new_string(store->ca_name));
    json_object_object_add(obj, "log_id",
        json_object_new_string(store->log_id));
    json_object_object_add(obj, "tree_size",
        json_object_new_int(store->tree.size));
    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /log — full tree state (log_id, size, root hash). */
static void handle_log_state(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    uint8_t root[MTC_HASH_SIZE];
    char root_hex[MTC_HASH_SIZE * 2 + 1];

    mtc_tiled_tree_root_hash(&store->tree, store->tree.size, root);
    to_hex(root, MTC_HASH_SIZE, root_hex);

    json_object_object_add(obj, "log_id",
        json_object_new_string(store->log_id));
    json_object_object_add(obj, "ca_name",
        json_object_new_string(store->ca_name));
    json_object_object_add(obj, "cosigner_id",
        json_object_new_string(store->cosigner_id));
    json_object_object_add(obj, "tree_size",
        json_object_new_int(store->tree.size));
    json_object_object_add(obj, "root_hash",
        json_object_new_string(root_hex));

    /* `landmarks` field retired 2026-05-07 (TODO #76).  The Python
     * client tolerates its absence (defaults to []). */

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /log/proof/<index> — Merkle inclusion proof for a log entry. */
static void handle_log_proof(client_io *io, MtcStore *store, int index)
{
    struct json_object *obj;
    uint8_t *proof = NULL;
    int proof_count = 0;
    uint8_t entry_hash[MTC_HASH_SIZE], root[MTC_HASH_SIZE];
    char hash_hex[MTC_HASH_SIZE * 2 + 1];
    struct json_object *proof_arr;
    int i, start = 0, end = store->tree.size;

    if (index < 0 || index >= store->tree.size) {
        http_send_error(io, 404, "entry not found");
        return;
    }

    /* Compute entry hash by fetching the serialized blob from
     * mtc_log_entries and hashing it (entry hash is leaf-domain
     * SHA-256 with the 0x00 prefix, per RFC 9162). */
    {
        uint8_t *ser = NULL;
        int ser_sz = 0;
        if (mtc_db_load_entry_serialized(store->db, index, &ser, &ser_sz) != 0) {
            http_send_error(io, 500, "entry blob fetch failed");
            return;
        }
        mtc_hash_leaf(ser, ser_sz, entry_hash);
        free(ser);
    }

    /* Get inclusion proof */
    if (mtc_tiled_tree_inclusion_proof(&store->tree, index, start, end,
                                  &proof, &proof_count) != 0) {
        http_send_error(io, 500, "proof generation failed");
        return;
    }

    /* Get root hash */
    mtc_tiled_tree_subtree_hash(&store->tree, start, end, root);

    obj = json_object_new_object();
    json_object_object_add(obj, "index", json_object_new_int(index));

    to_hex(entry_hash, MTC_HASH_SIZE, hash_hex);
    json_object_object_add(obj, "entry_hash",
        json_object_new_string(hash_hex));

    {
        struct json_object *st = json_object_new_object();
        json_object_object_add(st, "start", json_object_new_int(start));
        json_object_object_add(st, "end", json_object_new_int(end));
        json_object_object_add(obj, "subtree", st);
    }

    to_hex(root, MTC_HASH_SIZE, hash_hex);
    json_object_object_add(obj, "root_hash",
        json_object_new_string(hash_hex));

    proof_arr = json_object_new_array();
    for (i = 0; i < proof_count; i++) {
        to_hex(proof + i * MTC_HASH_SIZE, MTC_HASH_SIZE, hash_hex);
        json_object_array_add(proof_arr, json_object_new_string(hash_hex));
    }
    json_object_object_add(obj, "proof", proof_arr);
    json_object_object_add(obj, "valid", json_object_new_boolean(1));

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
    free(proof);
}

/* GET /certificate/<index> — retrieve a stored certificate by log index. */
static void handle_get_certificate(client_io *io, MtcStore *store, int index)
{
    struct json_object *cert = mtc_store_get_cert(store, index);
    if (!cert) {
        http_send_error(io, 404, "certificate not found");
        return;
    }
    http_send_json_obj(io, 200, cert);
    json_object_put(cert);
}

/* ------------------------------------------------------------------ */
/* DNS TXT validation for CA certificates                              */
/* ------------------------------------------------------------------ */

/* validate_ca_dns_txt / validate_ca_cert_if_present — now in
 * mtc_ca_validate.c (mtc_validate_ca_dns_txt /
 * mtc_validate_ca_cert).  The shared module switched in mqc-3
 * from libresolv `_mtc-ca./fp=sha256:` to libunbound-DNSSEC
 * `_mqc-ca./kh=sha3-256:`; see mtc_ca_validate.c file header. */

/******************************************************************************
 * Function:    handle_enrollment_nonce
 *
 * Description:
 *   POST /enrollment/nonce — issue a server-side enrollment nonce.
 *
 *   CA enrollment (type=ca or omitted):
 *     Body: {"domain": "...", "public_key_fingerprint": "sha256:..."}
 *     No CA needs to exist — DNS TXT validates domain ownership.
 *
 *   Leaf enrollment (type=leaf):
 *     Body: {"domain": "...", "public_key_fingerprint": "sha256:...",
 *            "type": "leaf"}
 *     A registered CA must exist for this domain.
 *
 *   Returns a JSON response with the nonce, expiration, and (for CA
 *   nonces) the DNS record the caller must create.
 *
 * Input Arguments:
 *   io        - Client I/O context.
 *   store     - MTC store (DB connection used for nonce storage).
 *   body      - HTTP request body (JSON).
 *   body_len  - Length of body in bytes.
 *
 * Side Effects:
 *   Creates a pending nonce row in mtc_enrollment_nonces.
 ******************************************************************************/
static void handle_enrollment_nonce(client_io *io, MtcStore *store,
                                     const char *body, int body_len)
{
    struct json_object *req, *val;
    const char *domain, *fp_raw, *nonce_type;
    char domain_canon[256];        /* canonical form, lives for the function */
    const char *label_in = NULL;    /* optional, leaf-only */
    const char *fp_hex_for_db = NULL;  /* NULL = long-lived reservation */
    char fp_hex[65];
    char nonce[MTC_NONCE_HEX_LEN + 1];
    char label_canon[MTC_LABEL_MAX + 1] = {0};
    long expires;
    long ttl_secs = 0;              /* 0 = server default */
    long max_ttl = (long)MTC_NONCE_MAX_TTL_DAYS * 86400L;
    struct json_object *resp;
    int ret, ca_index = -1;

    if (!store->db) {
        http_send_error(io, 503, "database not available");
        return;
    }
    int is_leaf = 0;

    (void)body_len;

    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        return;
    }

    if (!json_object_object_get_ex(req, "domain", &val)) {
        http_send_error(io, 400, "missing 'domain'");
        json_object_put(req);
        return;
    }
    {
        const char *raw = json_object_get_string(val);
        if (!raw || mtc_canonicalize_domain(raw, domain_canon,
                                            sizeof(domain_canon)) != 0) {
            http_send_error(io, 400,
                "invalid 'domain' (must be lowercase ASCII LDH; "
                "no wildcards, no underscore-prefixed labels, no IDN — "
                "punycode to xn--... yourself)");
            json_object_put(req);
            return;
        }
        domain = domain_canon;
    }

    /* Check nonce type (needed before fp validation since leaf nonces
     * may omit fp for long-lived reservation mode). */
    nonce_type = "ca";
    if (json_object_object_get_ex(req, "type", &val))
        nonce_type = json_object_get_string(val);
    is_leaf = (strcmp(nonce_type, "leaf") == 0);

    /* TODO #64: leaf-type nonce issuance requires MQC peer-cert
     * authentication AND the caller must be the CA for the
     * requested domain.  Without this gate any in-log peer can
     * mint a leaf nonce for any other CA's domain (cross-CA
     * leaf hopping — see README-bugsandtodo.md §64).  CA-type
     * nonces remain open: their auth is the subsequent DNSSEC
     * TXT validation at consume time.  Mirrors the same pattern
     * /cancel-nonce already uses. */
    if (is_leaf) {
        if (!io->mqc) {
            LOG_WARN("enrollment-nonce (leaf) rejected: non-MQC "
                     "transport from %s", io->ip_str);
            http_send_error(io, 403,
                "leaf nonce issuance requires MQC peer-cert auth "
                "(use issue_leaf_nonce, which speaks MQC)");
            json_object_put(req);
            return;
        }
        int peer_idx = mqc_get_peer_index(io->mqc);
        if (peer_idx < 0) {
            LOG_WARN("enrollment-nonce (leaf) rejected: no MQC peer "
                     "identity from %s", io->ip_str);
            http_send_error(io, 403, "MQC peer identity unavailable");
            json_object_put(req);
            return;
        }
        struct json_object *caller_cert = mtc_store_get_cert(store, peer_idx);
        if (!caller_cert) {
            http_send_error(io, 404, "caller cert not found in log");
            json_object_put(req);
            return;
        }
        struct json_object *sc_j, *tbs_j, *subj_j;
        if (!json_object_object_get_ex(caller_cert, "standalone_certificate", &sc_j) ||
            !json_object_object_get_ex(sc_j, "tbs_entry", &tbs_j) ||
            !json_object_object_get_ex(tbs_j, "subject", &subj_j)) {
            http_send_error(io, 500, "internal error: malformed caller cert");
            json_object_put(caller_cert);
            json_object_put(req);
            return;
        }
        const char *caller_subject = json_object_get_string(subj_j);

        /* Require caller_subject == "<domain>-ca" exactly.  No
         * cross-CA hopping — a CA for example.com cannot mint
         * leaf nonces for frflashy.com. */
        char expected_subject[280];
        int n = snprintf(expected_subject, sizeof(expected_subject),
                         "%s-ca", domain);
        if (n < 0 || n >= (int)sizeof(expected_subject) ||
            !caller_subject ||
            strcmp(caller_subject, expected_subject) != 0) {
            LOG_WARN("enrollment-nonce (leaf) refused: caller '%s' "
                     "(idx %d) is not the CA for domain '%s' "
                     "(expected subject '%s')",
                     caller_subject ? caller_subject : "(null)",
                     peer_idx, domain, expected_subject);
            http_send_error(io, 403,
                "only the CA for this domain (subject "
                "'<domain>-ca') may mint leaf nonces");
            json_object_put(caller_cert);
            json_object_put(req);
            return;
        }
        json_object_put(caller_cert);
    }

    /* Optional fingerprint.  Required for CA nonces and short-lived
     * leaf nonces; may be omitted for long-lived leaf reservations
     * (fp late-binds at consume).
     *
     * mqc-3: the canonical hash is SHA3-256 over the SubjectPublicKey
     * Info DER, advertised on the wire as the prefix `sha3-256:`.
     * The legacy `sha256:` prefix and SHA-256-of-SPKI form were
     * dropped as part of the _mtc-ca. → _mqc-ca. cutover. */
    if (json_object_object_get_ex(req, "public_key_fingerprint", &val)) {
        fp_raw = json_object_get_string(val);
        /* Accept either prefix (or none).  Two canonical forms in
         * play here:
         *   - `sha3-256:<hex>` — SHA3-256 over the SPKI DER, used
         *     for CA-side fingerprints (mqc-3, matches what
         *     mtc_validate_ca_cert recomputes from a PEM/X.509).
         *   - `sha256:<hex>` — SHA-256 over the raw PEM text, used
         *     for LEAF-nonce binding (matches what mtc_bootstrap.c's
         *     consume-nonce path recomputes via wc_Sha256 over
         *     `strlen(pub_key_pem)` bytes).
         * The handler stores the 64 hex chars verbatim and the
         * downstream consume code knows which canonical form to
         * recompute against — so both prefixes are valid here. */
        if (strncmp(fp_raw, "sha3-256:", 9) == 0)
            fp_raw += 9;
        else if (strncmp(fp_raw, "sha256:", 7) == 0)
            fp_raw += 7;
        if (strlen(fp_raw) != 64) {
            http_send_error(io, 400, "fingerprint must be exactly 64 hex chars");
            json_object_put(req);
            return;
        }
        {
            int fi;
            for (fi = 0; fi < 64; fi++) {
                char c = fp_raw[fi];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'))) {
                    http_send_error(io, 400, "fingerprint contains non-hex chars");
                    json_object_put(req);
                    return;
                }
            }
        }
        snprintf(fp_hex, sizeof(fp_hex), "%s", fp_raw);
        fp_hex_for_db = fp_hex;
    } else if (!is_leaf) {
        http_send_error(io, 400,
            "missing 'public_key_fingerprint' (CA nonces require fp)");
        json_object_put(req);
        return;
    }

    /* Optional operator-assigned label (leaf-only).  Server-side
     * canonicalization gate (TODO #68): even though the client
     * tools (bootstrap_leaf / bootstrap_ca / issue_leaf_nonce) all
     * sanitize before sending, a malicious /enrollment/nonce caller
     * could plant a label that downstream tooling (or a future bug)
     * turns into a directory name.  mtc_canonicalize_label enforces
     * the same charset + length + path-traversal rules the client
     * tools do, so the DB row + on-the-wire echo are guaranteed
     * safe. */
    char label_validated[MTC_LABEL_MAX + 1] = {0};
    if (is_leaf && json_object_object_get_ex(req, "label", &val)) {
        const char *s = json_object_get_string(val);
        if (s && s[0]) {
            if (mtc_canonicalize_label(s, label_validated,
                                       sizeof(label_validated)) != 0) {
                http_send_error(io, 400,
                    "invalid label (charset [A-Za-z0-9._-], "
                    "1..64 chars, no leading '-' or '.', "
                    "not '.' or '..')");
                json_object_put(req);
                return;
            }
            label_in = label_validated;
        }
    }

    /* Long-lived reservation mode requires a label to pin the slot. */
    if (is_leaf && !fp_hex_for_db && !label_in) {
        http_send_error(io, 400,
            "long-lived reservation nonces require 'label' "
            "to pin the slot");
        json_object_put(req);
        return;
    }

    /* Optional TTL override.  Accept ttl_seconds OR ttl_days; clamp
     * to [MTC_NONCE_TTL_SECS, MTC_NONCE_MAX_TTL_DAYS*86400].  Absence
     * leaves ttl_secs=0 which the DB layer translates into the
     * 15-minute default. */
    if (json_object_object_get_ex(req, "ttl_seconds", &val)) {
        ttl_secs = json_object_get_int64(val);
    } else if (json_object_object_get_ex(req, "ttl_days", &val)) {
        ttl_secs = (long)json_object_get_int(val) * 86400L;
    }
    if (ttl_secs > 0 && ttl_secs < MTC_NONCE_TTL_SECS)
        ttl_secs = MTC_NONCE_TTL_SECS;
    if (ttl_secs > max_ttl) {
        LOG_INFO("nonce TTL clamped from %ld to %ld (MTC_NONCE_MAX_TTL_DAYS=%d)",
                 ttl_secs, max_ttl, MTC_NONCE_MAX_TTL_DAYS);
        ttl_secs = max_ttl;
    }

    /* Rate limit: leaf nonces (10/min, 100/hr) vs CA nonces (3/min, 10/hr) */
    if (!mtc_ratelimit_check(io->ip_str, is_leaf ? RL_NONCE_LEAF : RL_NONCE_CA)) {
        http_send_error(io, 429, "rate limit exceeded");
        json_object_put(req);
        return;
    }

    /* For leaf nonces, verify a registered CA exists for this domain */
    if (is_leaf) {
        ca_index = mtc_db_find_ca_for_domain(store->db, domain);
        if (ca_index < 0) {
            http_send_error(io, 403,
                "no registered CA exists for this domain — "
                "enroll a CA first via enroll-ca");
            json_object_put(req);
            return;
        }
        LOG_INFO("leaf nonce requested for %s (authorized by CA index %d%s%s)",
                 domain, ca_index,
                 fp_hex_for_db ? ", fp=" : ", RESERVATION for label=",
                 fp_hex_for_db ? fp_hex_for_db : (label_in ? label_in : "?"));
    }

    /* Create or reissue pending nonce in DB.  Idempotent on either
     * (domain, fp) or (domain, label) match depending on fp_hex. */
    ret = mtc_db_create_nonce(store->db, domain, fp_hex_for_db, ca_index,
                              label_in, ttl_secs,
                              nonce, &expires,
                              label_canon, sizeof(label_canon));
    if (ret < 0) {
        http_send_error(io, 500, "nonce generation failed");
        json_object_put(req);
        return;
    }

    LOG_INFO("%s nonce issued for %s (fp=%s, expires=%ld%s%s)",
             is_leaf ? "leaf" : "CA", domain,
             fp_hex_for_db ? fp_hex : "<late-bind>", expires,
             label_canon[0] ? ", label=" : "",
             label_canon[0] ? label_canon : "");

    resp = json_object_new_object();
    json_object_object_add(resp, "nonce", json_object_new_string(nonce));
    json_object_object_add(resp, "expires", json_object_new_int64(expires));
    json_object_object_add(resp, "type",
                           json_object_new_string(is_leaf ? "leaf" : "ca"));
    if (ca_index >= 0)
        json_object_object_add(resp, "ca_index",
                               json_object_new_int(ca_index));
    if (label_canon[0])
        json_object_object_add(resp, "label",
                               json_object_new_string(label_canon));

    if (!is_leaf) {
        /* CA nonce: include DNS record to create.  mqc-3 wire
         * format — see mtc_ca_validate.c file header for the
         * deprecated _mtc-ca./SHA-256/res_query form.  The
         * server-side validator only requires kh=sha3-256:<fp>;
         * we still emit the issued nonce + expiry as bonus
         * tokens for operators who want to audit-trail when a
         * pin was minted, but mqc_dnssec_validate_ca_kh ignores
         * unknown tokens. */
        char dns_name[280], dns_value[512];   /* "_mqc-ca." + 253 + "." + NUL */
        snprintf(dns_name, sizeof(dns_name), "_mqc-ca.%s.", domain);
        snprintf(dns_value, sizeof(dns_value),
                 "v=MQC1; role=ca; alg=ML-DSA-87; "
                 "kh=sha3-256:%s; n=%s; exp=%ld",
                 fp_hex, nonce, expires);
        json_object_object_add(resp, "dns_record_name",
                               json_object_new_string(dns_name));
        json_object_object_add(resp, "dns_record_value",
                               json_object_new_string(dns_value));
    }

    /* P0 / TODO #9b leaf branch — emit the cosigner-key fingerprint
     * so the CA operator can paste it alongside the nonce when
     * delivering both out-of-band to the leaf operator.  The leaf's
     * bootstrap_leaf consumes --cosigner-fp <hex>, recomputes the
     * same SHA-256 over DER(SPKI(ca_cosigner_pem)) from the
     * bootstrap response, and refuses to pin the PEM unless the
     * fingerprints match.  An attacker on port 8445 cannot replace
     * the cosigner PEM without breaking the SHA-256 the leaf
     * operator pasted in. */
    {
        char cosigner_pem[8192];
        int  cosigner_pem_sz = mtc_store_get_public_key_pem(
            store, cosigner_pem, (int)sizeof(cosigner_pem));
        if (cosigner_pem_sz > 0) {
            unsigned char spki_der[4096];     /* ML-DSA-87 SPKI ~2.6 KB */
            int spki_der_sz = wc_PubKeyPemToDer(
                (const unsigned char *)cosigner_pem,
                cosigner_pem_sz, spki_der, (int)sizeof(spki_der));
            if (spki_der_sz > 0) {
                unsigned char digest[WC_SHA256_DIGEST_SIZE];
                if (wc_Sha256Hash(spki_der, (word32)spki_der_sz,
                                  digest) == 0) {
                    char hex[WC_SHA256_DIGEST_SIZE * 2 + 1];
                    int  hi;
                    static const char hexdigits[] = "0123456789abcdef";
                    for (hi = 0; hi < (int)sizeof(digest); hi++) {
                        hex[hi * 2]     = hexdigits[(digest[hi] >> 4) & 0xf];
                        hex[hi * 2 + 1] = hexdigits[digest[hi] & 0xf];
                    }
                    hex[sizeof(digest) * 2] = '\0';
                    json_object_object_add(resp, "ca_cosigner_fp",
                        json_object_new_string(hex));
                }
            }
        }
    }

    http_send_json_obj(io, 200, resp);
    json_object_put(resp);
    json_object_put(req);
}

/* handle_certificate_request removed — enrollment now goes through the
 * DH bootstrap port (mtc_bootstrap.c).  See README-unsure.md. */

/******************************************************************************
 * Function:    handle_cancel_nonce
 *
 * Description:
 *   POST /cancel-nonce — retract a pending reservation nonce early.
 *   MQC-only: caller's peer cert_index is read from the transport and
 *   used as the authorization token against the nonce row's ca_index.
 *   Only the CA that issued the reservation can cancel it.
 *
 *   The client sends:
 *     - domain:  domain the nonce was issued for
 *     - label:   label the reservation was bound to
 *
 *   The server:
 *     1. Verifies MQC transport and reads peer_index
 *     2. Verifies the peer is a CA (subject ends in "-ca")
 *     3. Atomically expires the matching pending nonce (DB gate
 *        requires ca_index == peer_index)
 *
 *   On success returns 200 with {"cancelled": true, "domain": D,
 *   "label": L}.  If no matching pending nonce (already consumed,
 *   expired, wrong CA, wrong label), returns 404 — treat as
 *   "nothing to cancel."
 *
 * Input Arguments:
 *   io        - Client I/O context (must have io->mqc != NULL).
 *   store     - MTC store (tree, certs, DB).
 *   body      - HTTP request body (JSON).
 *   body_len  - Length of body in bytes.
 ******************************************************************************/
static void handle_cancel_nonce(client_io *io, MtcStore *store,
                                const char *body, int body_len)
{
    struct json_object *req, *val, *caller_cert, *sc_j, *tbs_j, *subj_j;
    const char *domain, *label, *caller_subject;
    char domain_canon[256];        /* canonical form, lives for the function */
    int peer_idx, rc;
    size_t subj_len;
    (void)body_len;

    /* Step 1: MQC-only */
    if (!io->mqc) {
        LOG_WARN("cancel-nonce rejected: non-MQC transport from %s",
                 io->ip_str);
        http_send_error(io, 403, "/cancel-nonce requires MQC transport");
        return;
    }
    peer_idx = mqc_get_peer_index(io->mqc);
    if (peer_idx < 0) {
        LOG_WARN("cancel-nonce rejected: no MQC peer identity from %s",
                 io->ip_str);
        http_send_error(io, 403, "MQC peer identity unavailable");
        return;
    }

    /* Step 2: verify caller is a CA (subject ends in "-ca") */
    caller_cert = mtc_store_get_cert(store, peer_idx);
    if (!caller_cert) {
        http_send_error(io, 404, "caller cert not found in log");
        return;
    }
    if (!json_object_object_get_ex(caller_cert, "standalone_certificate", &sc_j) ||
        !json_object_object_get_ex(sc_j, "tbs_entry", &tbs_j) ||
        !json_object_object_get_ex(tbs_j, "subject", &subj_j)) {
        http_send_error(io, 500, "internal error: malformed caller cert");
        json_object_put(caller_cert);
        return;
    }
    caller_subject = json_object_get_string(subj_j);
    subj_len = caller_subject ? strlen(caller_subject) : 0;
    if (subj_len < 3 ||
        strcmp(caller_subject + subj_len - 3, "-ca") != 0) {
        LOG_WARN("cancel-nonce refused: caller '%s' (idx %d) is not a CA",
                 caller_subject ? caller_subject : "(null)", peer_idx);
        http_send_error(io, 403,
            "only CA identities (subject ending in '-ca') may cancel "
            "reservation nonces");
        json_object_put(caller_cert);
        return;
    }
    /* caller_subject borrowed from caller_cert; finished with it now. */
    json_object_put(caller_cert);
    caller_cert = NULL;
    caller_subject = NULL;
    (void)caller_subject;

    /* Step 3: parse body */
    if (!body) {
        http_send_error(io, 400, "missing request body");
        return;
    }
    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        return;
    }
    if (!json_object_object_get_ex(req, "domain", &val)) {
        http_send_error(io, 400, "missing 'domain'");
        json_object_put(req);
        return;
    }
    {
        const char *raw = json_object_get_string(val);
        if (!raw || mtc_canonicalize_domain(raw, domain_canon,
                                            sizeof(domain_canon)) != 0) {
            http_send_error(io, 400,
                "invalid 'domain' (must be lowercase ASCII LDH; "
                "no wildcards, no underscore-prefixed labels, no IDN — "
                "punycode to xn--... yourself)");
            json_object_put(req);
            return;
        }
        domain = domain_canon;
    }
    if (!json_object_object_get_ex(req, "label", &val)) {
        http_send_error(io, 400, "missing 'label'");
        json_object_put(req);
        return;
    }
    label = json_object_get_string(val);
    if (!label || !label[0]) {
        http_send_error(io, 400, "'label' must be non-empty");
        json_object_put(req);
        return;
    }

    /* Step 4: DB cancel; ca_index gate happens inside the helper */
    if (!store->db) {
        http_send_error(io, 503, "database not available");
        json_object_put(req);
        return;
    }
    rc = mtc_db_cancel_nonce(store->db, domain, label, peer_idx);
    if (rc < 0) {
        http_send_error(io, 500, "cancel_nonce DB error");
        json_object_put(req);
        return;
    }
    if (rc == 0) {
        LOG_INFO("cancel-nonce: no matching pending nonce for "
                 "(domain=%s, label=%s, ca_index=%d)",
                 domain, label, peer_idx);
        http_send_error(io, 404,
            "no pending reservation matches (domain, label, caller) "
            "— it may have been consumed, expired, or issued by a "
            "different CA");
        json_object_put(req);
        return;
    }

    LOG_INFO("cancel-nonce: cancelled reservation (domain=%s, "
             "label=%s, ca_index=%d)",
             domain, label, peer_idx);

    {
        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, "cancelled", json_object_new_boolean(1));
        json_object_object_add(resp, "domain", json_object_new_string(domain));
        json_object_object_add(resp, "label", json_object_new_string(label));
        http_send_json_obj(io, 200, resp);
        json_object_put(resp);
    }
    json_object_put(req);
}

/******************************************************************************
 * Function:    handle_renew_cert
 *
 * Description:
 *   POST /renew-cert — renew a certificate, authenticated by MQC peer
 *   identity.  MQC-only: the handshake already proved the caller owns
 *   the cert at its peer_index, so no nonce, no old-key signature, and
 *   no cert_index in the body.  The peer_index *is* the cert being
 *   renewed.
 *
 *   The client sends:
 *     - new_public_key_pem:  new public key for the renewed cert
 *     - validity_days:       optional, 1..3650, default 90
 *
 *   The server:
 *     1. Verifies MQC transport and reads peer_index
 *     2. Looks up the caller's current cert in the log
 *     3. Rejects if the cert is revoked
 *     4. Issues a new certificate with the new public key, same subject,
 *        and same algorithm
 *
 * Input Arguments:
 *   io        - Client I/O context (must have io->mqc != NULL).
 *   store     - MTC store (tree, certs, DB).
 *   body      - HTTP request body (JSON).
 *   body_len  - Length of body in bytes.
 ******************************************************************************/
static void handle_renew_cert(client_io *io, MtcStore *store,
                              const char *body, int body_len)
{
    struct json_object *req, *val, *old_cert, *old_sc, *old_tbs;
    const char *new_pub_pem;
    const char *old_subject, *old_algo;
    int cert_index, validity_days;
    (void)body_len;

    /* --- Step 1: MQC transport + peer identity required --- */
    if (!io->mqc) {
        LOG_WARN("renew-cert rejected: non-MQC transport from %s",
                 io->ip_str);
        http_send_error(io, 403, "/renew-cert requires MQC transport");
        return;
    }
    cert_index = mqc_get_peer_index(io->mqc);
    if (cert_index < 0) {
        LOG_WARN("renew-cert rejected: no MQC peer identity from %s",
                 io->ip_str);
        http_send_error(io, 403, "MQC peer identity unavailable");
        return;
    }

    /* --- Step 2: look up caller's cert in the log --- */
    old_cert = mtc_store_get_cert(store, cert_index);
    if (!old_cert) {
        http_send_error(io, 404, "caller cert not found in log");
        return;
    }
    if (!json_object_object_get_ex(old_cert, "standalone_certificate", &old_sc) ||
        !json_object_object_get_ex(old_sc, "tbs_entry", &old_tbs)) {
        http_send_error(io, 500, "internal error: malformed stored cert");
        json_object_put(old_cert);
        return;
    }
    if (!json_object_object_get_ex(old_tbs, "subject", &val)) {
        http_send_error(io, 500, "internal error: no subject in stored cert");
        json_object_put(old_cert);
        return;
    }
    /* old_subject + old_algo are borrowed string pointers into old_cert;
     * keep old_cert alive until we're done reading them.  copy_subject
     * guarantees the caller-visible string outlives old_cert's put. */
    old_subject = json_object_get_string(val);
    old_algo = "ML-DSA-87";
    if (json_object_object_get_ex(old_tbs, "subject_public_key_algorithm", &val))
        old_algo = json_object_get_string(val);

    /* --- Step 3: refuse revoked certs --- */
    if (mtc_store_is_revoked(store, cert_index)) {
        LOG_WARN("renew-cert: cert %d (%s) is revoked; refusing",
                 cert_index, old_subject);
        http_send_error(io, 403, "certificate is revoked");
        json_object_put(old_cert);
        return;
    }

    /* --- Step 4: parse body --- */
    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        json_object_put(old_cert);
        return;
    }
    if (!json_object_object_get_ex(req, "new_public_key_pem", &val)) {
        http_send_error(io, 400, "missing 'new_public_key_pem'");
        json_object_put(req);
        json_object_put(old_cert);
        return;
    }
    new_pub_pem = json_object_get_string(val);
    validity_days = 90;
    if (json_object_object_get_ex(req, "validity_days", &val)) {
        validity_days = json_object_get_int(val);
        if (validity_days < 1 || validity_days > 3650) {
            http_send_error(io, 400,
                "validity_days must be between 1 and 3650");
            json_object_put(req);
            json_object_put(old_cert);
            return;
        }
    }

    LOG_INFO("renew-cert: authorized for '%s' via MQC peer_index=%d",
             old_subject, cert_index);

    /* --- Step 5: Issue new certificate --- */
    {
        struct json_object *tbs, *sc, *result, *checkpoint;
        struct json_object *proof_arr, *cosig_arr, *cosig;
        uint8_t *entry_buf = NULL;
        int entry_sz;
        int new_index;
        double now = (double)time(NULL);
        char spk_hash[65];
        uint8_t *proof = NULL;
        int proof_count = 0;
        uint8_t subtree_hash[MTC_HASH_SIZE];
        char hash_hex[MTC_HASH_SIZE * 2 + 1];
        uint8_t sig[DILITHIUM_LEVEL5_SIG_SIZE];
        int sig_sz = 0;
        int i, start, end;

        /* Hash the new public key */
        {
            wc_Sha256 sha;
            uint8_t h[32];
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const byte *)new_pub_pem,
                (word32)strlen(new_pub_pem));
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            to_hex(h, 32, spk_hash);
        }

        /* Build TBS JSON */
        tbs = json_object_new_object();
        json_object_object_add(tbs, "subject",
            json_object_new_string(old_subject));
        json_object_object_add(tbs, "subject_public_key_algorithm",
            json_object_new_string(old_algo));
        json_object_object_add(tbs, "subject_public_key_hash",
            json_object_new_string(spk_hash));
        json_object_object_add(tbs, "not_before",
            json_object_new_double(now));
        json_object_object_add(tbs, "not_after",
            json_object_new_double(now + validity_days * 86400.0));
        json_object_object_add(tbs, "extensions",
            json_object_new_object());

        /* Serialize for Merkle tree */
        {
            struct json_object *ser = json_object_new_object();
            const char *ser_str;
            json_object_object_add(ser, "extensions",
                json_object_new_object());
            json_object_object_add(ser, "not_after",
                json_object_new_double(now + validity_days * 86400.0));
            json_object_object_add(ser, "not_before",
                json_object_new_double(now));
            json_object_object_add(ser, "spk_algorithm",
                json_object_new_string(old_algo));
            json_object_object_add(ser, "spk_hash",
                json_object_new_string(spk_hash));
            json_object_object_add(ser, "subject",
                json_object_new_string(old_subject));

            ser_str = json_object_to_json_string_ext(ser,
                JSON_C_TO_STRING_PLAIN);
            entry_sz = 1 + (int)strlen(ser_str);
            entry_buf = (uint8_t *)malloc((size_t)entry_sz);
            entry_buf[0] = 0x01;
            memcpy(entry_buf + 1, ser_str, strlen(ser_str));
            json_object_put(ser);
        }

        /* Add to log.  -1 means the DB persist failed; abort the
         * renewal cleanly rather than continue with an in-memory-only
         * entry that vanishes on the next service restart (TODO #57
         * item 4). */
        new_index = mtc_store_add_entry(store, entry_buf, entry_sz);
        if (new_index < 0) {
            LOG_ERROR("renew-cert: mtc_store_add_entry failed for '%s' "
                      "(DB persist error) — aborting renewal",
                      old_subject);
            http_send_error(io, 500, "DB persist failed");
            json_object_put(tbs);
            free(entry_buf);
            json_object_put(req);
            json_object_put(old_cert);
            return;
        }

        /* Checkpoint */
        checkpoint = mtc_store_checkpoint(store);

        /* Proof */
        start = 0;
        end = store->tree.size;
        mtc_tiled_tree_inclusion_proof(&store->tree, new_index, start, end,
            &proof, &proof_count);
        mtc_tiled_tree_subtree_hash(&store->tree, start, end, subtree_hash);

        /* Cosign */
        mtc_store_cosign(store, start, end, sig, &sig_sz);

        /* Build standalone certificate */
        sc = json_object_new_object();
        json_object_object_add(sc, "index",
            json_object_new_int(new_index));
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
        cosig = json_object_new_object();
        json_object_object_add(cosig, "cosigner_id",
            json_object_new_string(store->cosigner_id));
        json_object_object_add(cosig, "log_id",
            json_object_new_string(store->log_id));
        json_object_object_add(cosig, "start",
            json_object_new_int(start));
        json_object_object_add(cosig, "end",
            json_object_new_int(end));
        json_object_object_add(cosig, "subtree_hash",
            json_object_new_string(hash_hex));
        {
            /* ML-DSA-87 sig is 4627 bytes → 9254 hex chars + NUL.
             * Heap-allocate so we don't blow the per-connection stack. */
            char *sig_hex_out = (char *)malloc((size_t)sig_sz * 2 + 1);
            if (sig_hex_out) {
                to_hex(sig, sig_sz, sig_hex_out);
                json_object_object_add(cosig, "signature",
                    json_object_new_string(sig_hex_out));
                free(sig_hex_out);
            }
        }
        json_object_object_add(cosig, "algorithm",
            json_object_new_string("ML-DSA-87"));
        json_object_array_add(cosig_arr, cosig);
        json_object_object_add(sc, "cosignatures", cosig_arr);
        json_object_object_add(sc, "trust_anchor_id",
            json_object_new_string(store->log_id));

        /* Build result */
        result = json_object_new_object();
        json_object_object_add(result, "index",
            json_object_new_int(new_index));
        json_object_object_add(result, "standalone_certificate", sc);
        json_object_object_add(result, "checkpoint",
            json_object_get(checkpoint));

        /* Persist.  Phase 3: the row in mtc_certificates is the source
         * of truth and reads fault through cert_cache on demand. */
        {
            const char *cert_str = json_object_to_json_string(result);
            if (mtc_db_save_certificate(store->db, new_index, cert_str) != 0) {
                LOG_ERROR("renew-cert: DB save_certificate failed for index %d", new_index);
                http_send_error(io, 500, "DB persist failed");
                json_object_put(result);
                json_object_put(tbs);
                json_object_put(checkpoint);
                free(proof);
                free(entry_buf);
                json_object_put(old_cert);
                json_object_put(req);
                return;
            }
        }

        LOG_INFO("renew-cert: issued new cert for '%s' at index %d (was %d)",
                 old_subject, new_index, cert_index);

        http_send_json_obj(io, 201, result);

        json_object_put(result);
        json_object_put(tbs);
        json_object_put(checkpoint);
        free(proof);
        free(entry_buf);
    }

    json_object_put(old_cert);
    json_object_put(req);
}

/* GET /log/entry/<index> — single log entry with type and leaf hash. */
static void handle_log_entry(client_io *io, MtcStore *store, int index)
{
    struct json_object *obj;
    char hash_hex[MTC_HASH_SIZE * 2 + 1];
    uint8_t lh[MTC_HASH_SIZE];

    if (index < 0 || index >= store->tree.size) {
        http_send_error(io, 404, "entry not found");
        return;
    }

    /* Phase 3: fetch the serialized entry from mtc_log_entries on
     * demand instead of an in-memory tree.entries[] read. */
    {
        uint8_t *ser = NULL;
        int ser_sz = 0;
        if (mtc_db_load_entry_serialized(store->db, index, &ser, &ser_sz) != 0) {
            http_send_error(io, 500, "entry blob fetch failed");
            return;
        }
        mtc_hash_leaf(ser, ser_sz, lh);
        to_hex(lh, MTC_HASH_SIZE, hash_hex);

        obj = json_object_new_object();
        json_object_object_add(obj, "index", json_object_new_int(index));

        if (ser_sz > 0 && ser[0] == 0x01) {
            /* TBS entry — JSON after the 0x01 prefix */
            char *json_str = (char *)malloc((size_t)ser_sz);
            if (json_str) {
                memcpy(json_str, ser + 1, (size_t)(ser_sz - 1));
                json_str[ser_sz - 1] = 0;
                {
                    struct json_object *data = json_tokener_parse(json_str);
                    json_object_object_add(obj, "type", json_object_new_int(1));
                    json_object_object_add(obj, "data",
                        data ? data : json_object_new_null());
                }
                free(json_str);
            }
        } else {
            json_object_object_add(obj, "type", json_object_new_int(0));
            json_object_object_add(obj, "data", json_object_new_null());
        }
        free(ser);
    }

    json_object_object_add(obj, "leaf_hash",
        json_object_new_string(hash_hex));

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /log/checkpoint — latest checkpoint (or generates one on the fly). */
static void handle_checkpoint(client_io *io, MtcStore *store)
{
    struct json_object *cp;

    /* Prefer the persisted latest row — its ts reflects when a real
     * tree-change event was recorded.  In fork-after-accept, the child's
     * in-memory checkpoint_count is stale at fork time and each new
     * child would otherwise regenerate with ts=now, giving a bogus
     * "freshness" reading to clients. */
    if (store->use_db && store->db) {
        cp = mtc_db_load_latest_checkpoint(store->db, store->log_id);
        if (cp) {
            http_send_json_obj(io, 200, cp);
            json_object_put(cp);
            return;
        }
    }

    /* Fallback: in-memory cache (file-only mode, or DB empty). */
    if (store->checkpoint_count > 0) {
        http_send_json_obj(io, 200,
            store->checkpoints[store->checkpoint_count - 1]);
        return;
    }

    /* No checkpoint exists at all — generate one now (cold-start
     * path; mtc_store_checkpoint also persists it for next time). */
    cp = mtc_store_checkpoint(store);
    http_send_json_obj(io, 200, cp);
    json_object_put(cp);
}

/* GET /log/diagnostics — operator-side health probe.
 *
 * Returns counters that let `show-tpm` (and other clients) detect
 * inconsistencies between the SQL log and the on-disk Merkle tile
 * store.  Symptom we care about: leaves are appended to
 * mtc_log_entries but mtc_merkle_tiles isn't advanced, so receipt
 * builders for newly-added leaves fail with "inclusion_proof
 * failed".  Cosigned checkpoint stays at the older size and
 * show-tpm previously had no signal.
 *
 * Response shape:
 *   {
 *     "log_entries_count":          <int>,
 *     "log_entries_max_index":      <int>,
 *     "checkpoint_tree_size":       <int>,
 *     "tiles_max_leaf_coverage":    <int>,
 *     "last_tile_update_age_sec":   <int>,
 *     "last_tile_update_iso":       "<UTC ISO 8601>"
 *   }
 *
 * Coverage = MAX(first_node + node_count) over level=0 tiles.  When
 * tiles_max_leaf_coverage < log_entries_count, the tile store is
 * lagging the log and any submit landing above coverage will fail
 * to produce a receipt.
 */
static void handle_log_diagnostics(client_io *io, MtcStore *store)
{
    if (!store->use_db || !store->db) {
        http_send_error(io, 503, "diagnostics require DB-backed store");
        return;
    }

    long log_count = -1, log_max_index = -1;
    long tiles_coverage = 0;
    long stale_sec = -1;
    char tile_iso[64] = {0};
    int  cp_tree_size = -1;

    PGresult *r;

    r = PQexec(store->db,
        "SELECT COUNT(*)::bigint, COALESCE(MAX(index), -1)::bigint "
        "FROM mtc_log_entries");
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
        log_count     = atol(PQgetvalue(r, 0, 0));
        log_max_index = atol(PQgetvalue(r, 0, 1));
    }
    PQclear(r);

    /* Leaves live at level=1 in this schema; level=2+ are interior
     * tile nodes.  Coverage = max(first_node + node_count) at the
     * leaf level, which is the count of leaves the tile-store can
     * build proofs for. */
    r = PQexec(store->db,
        "SELECT COALESCE(MAX(first_node + node_count), 0)::bigint, "
        "       COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(updated_at)))::bigint, -1), "
        "       COALESCE(to_char(MAX(updated_at) AT TIME ZONE 'UTC', "
        "                        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), '') "
        "FROM mtc_merkle_tiles WHERE level = 1");
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
        tiles_coverage = atol(PQgetvalue(r, 0, 0));
        stale_sec      = atol(PQgetvalue(r, 0, 1));
        snprintf(tile_iso, sizeof(tile_iso), "%s", PQgetvalue(r, 0, 2));
    }
    PQclear(r);

    /* Checkpoint tree_size: pull the latest row's payload and parse. */
    {
        struct json_object *cp =
            mtc_db_load_latest_checkpoint(store->db, store->log_id);
        if (cp) {
            struct json_object *v = NULL;
            if (json_object_object_get_ex(cp, "tree_size", &v))
                cp_tree_size = json_object_get_int(v);
            json_object_put(cp);
        }
    }

    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "log_entries_count",
        json_object_new_int64(log_count));
    json_object_object_add(out, "log_entries_max_index",
        json_object_new_int64(log_max_index));
    json_object_object_add(out, "checkpoint_tree_size",
        json_object_new_int(cp_tree_size));
    json_object_object_add(out, "tiles_max_leaf_coverage",
        json_object_new_int64(tiles_coverage));
    json_object_object_add(out, "last_tile_update_age_sec",
        json_object_new_int64(stale_sec));
    json_object_object_add(out, "last_tile_update_iso",
        json_object_new_string(tile_iso));

    http_send_json_obj(io, 200, out);
    json_object_put(out);
}

/* GET /log/consistency?old=N&new=M — Merkle consistency proof. */
static void handle_consistency(client_io *io, MtcStore *store, const char *path)
{
    /* Parse ?old=N&new=M from the query string */
    const char *qs;
    int old_size = 0, new_size = 0;
    uint8_t *proof = NULL;
    int proof_count = 0;
    uint8_t old_root[MTC_HASH_SIZE], new_root[MTC_HASH_SIZE];
    char hash_hex[MTC_HASH_SIZE * 2 + 1];
    struct json_object *obj, *proof_arr;
    int i;

    qs = strchr(path, '?');
    if (qs) {
        const char *p = qs + 1;
        while (*p) {
            if (strncmp(p, "old=", 4) == 0)
                old_size = safe_atoi(p + 4, 10000000);
            else if (strncmp(p, "new=", 4) == 0)
                new_size = safe_atoi(p + 4, 10000000);
            p = strchr(p, '&');
            if (!p) break;
            p++;
        }
    }

    if (old_size < 1 || new_size > store->tree.size || old_size > new_size) {
        http_send_error(io, 400, "invalid sizes");
        return;
    }

    if (mtc_tiled_tree_consistency_proof(&store->tree, old_size, new_size,
                                    &proof, &proof_count) != 0) {
        http_send_error(io, 500, "consistency proof failed");
        return;
    }

    mtc_tiled_tree_root_hash(&store->tree, old_size, old_root);
    mtc_tiled_tree_root_hash(&store->tree, new_size, new_root);

    obj = json_object_new_object();
    json_object_object_add(obj, "old_size", json_object_new_int(old_size));
    json_object_object_add(obj, "new_size", json_object_new_int(new_size));

    to_hex(old_root, MTC_HASH_SIZE, hash_hex);
    json_object_object_add(obj, "old_root",
        json_object_new_string(hash_hex));
    to_hex(new_root, MTC_HASH_SIZE, hash_hex);
    json_object_object_add(obj, "new_root",
        json_object_new_string(hash_hex));

    proof_arr = json_object_new_array();
    for (i = 0; i < proof_count; i++) {
        to_hex(proof + i * MTC_HASH_SIZE, MTC_HASH_SIZE, hash_hex);
        json_object_array_add(proof_arr, json_object_new_string(hash_hex));
    }
    json_object_object_add(obj, "proof", proof_arr);

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
    free(proof);
}

/* GET /certificate/search?q=<subject> — case-insensitive subject search. */
static void handle_search_certificates(client_io *io, MtcStore *store, const char *path)
{
    const char *qs, *qval = NULL;
    struct json_object *obj, *arr;

    qs = strchr(path, '?');
    if (qs) {
        const char *p = qs + 1;
        if (strncmp(p, "q=", 2) == 0)
            qval = p + 2;
    }

    if (!qval || *qval == 0) {
        http_send_error(io, 400, "requires ?q=<subject>");
        return;
    }

    obj = json_object_new_object();
    json_object_object_add(obj, "query", json_object_new_string(qval));

    /* DB-backed search (TODO #74): a single ILIKE-on-JSONB query
     * returns the entire result set, no in-memory walk needed. */
    arr = mtc_db_search_certs_by_subject(store->db, qval);
    if (!arr) arr = json_object_new_array();

    json_object_object_add(obj, "results", arr);
    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /fips/list — read-only browse over the FIPS-manifest log.
 *
 * Lets a leaf with a valid MQC handshake browse mtc_fips_manifest_entries
 * (joined with mtc_log_entries / mtc_revocations) without holding direct
 * MERKLE_NEON DB credentials.  Query string keys: publisher, package,
 * version, limit, log_index.  All optional; log_index switches to a
 * single-row detail response that includes the parsed manifest tbs JSON.
 *
 * Conservative percent-decoder: only %20 is recognised (space).  Any
 * other percent escape is left as-is and then rejected by the
 * filter_str_ok charset guard inside mtc_fips_list.  This is enough for
 * our domain (publisher = DNS name, package + version = identifier-like
 * strings) and avoids pulling in libcurl for an unused capability. */
static void handle_fips_list(client_io *io, MtcStore *store, const char *path)
{
    char publisher[MTC_FIPS_LIST_FILTER_MAX + 1] = {0};
    char package[MTC_FIPS_LIST_FILTER_MAX + 1] = {0};
    char version[MTC_FIPS_LIST_FILTER_MAX + 1] = {0};
    int  has_publisher = 0, has_package = 0, has_version = 0;
    int  limit = 0;
    int  detail_index = -1;

    const char *qs = strchr(path, '?');
    if (qs) {
        const char *p = qs + 1;
        while (*p) {
            const char *amp = strchr(p, '&');
            size_t pair_len = amp ? (size_t)(amp - p) : strlen(p);
            const char *eq = memchr(p, '=', pair_len);
            if (eq) {
                size_t klen = (size_t)(eq - p);
                size_t vlen = pair_len - klen - 1;
                const char *vstart = eq + 1;
                /* Decode value: only %20 -> ' '; everything else passes through. */
                char dec[MTC_FIPS_LIST_FILTER_MAX + 1] = {0};
                size_t dlen = 0;
                for (size_t i = 0; i < vlen && dlen < sizeof(dec) - 1; i++) {
                    if (vstart[i] == '+') {
                        dec[dlen++] = ' ';
                    } else if (vstart[i] == '%' && i + 2 < vlen &&
                               vstart[i+1] == '2' &&
                               (vstart[i+2] == '0' || vstart[i+2] == 'F' ||
                                vstart[i+2] == 'f')) {
                        dec[dlen++] = (vstart[i+2] == '0') ? ' ' : '/';
                        i += 2;
                    } else {
                        dec[dlen++] = vstart[i];
                    }
                }
                dec[dlen] = 0;

                if (klen == 9 && strncmp(p, "publisher", 9) == 0) {
                    snprintf(publisher, sizeof(publisher), "%s", dec);
                    has_publisher = 1;
                } else if (klen == 7 && strncmp(p, "package", 7) == 0) {
                    snprintf(package, sizeof(package), "%s", dec);
                    has_package = 1;
                } else if (klen == 7 && strncmp(p, "version", 7) == 0) {
                    snprintf(version, sizeof(version), "%s", dec);
                    has_version = 1;
                } else if (klen == 5 && strncmp(p, "limit", 5) == 0) {
                    limit = safe_atoi(dec, MTC_FIPS_LIST_LIMIT_MAX);
                    if (limit < 0) limit = 0;
                } else if (klen == 9 && strncmp(p, "log_index", 9) == 0) {
                    detail_index = safe_atoi(dec, 100000000);
                    if (detail_index < 0) {
                        http_send_error(io, 400, "invalid log_index");
                        return;
                    }
                }
                /* unknown keys ignored */
            }
            if (!amp) break;
            p = amp + 1;
        }
    }

    struct json_object *resp = NULL;
    int status = 500;
    char err[512]; err[0] = 0;
    int rc = mtc_fips_list(store,
                           has_publisher ? publisher : NULL,
                           has_package   ? package   : NULL,
                           has_version   ? version   : NULL,
                           limit, detail_index,
                           &resp, &status, err, sizeof(err));
    if (rc == 0 && resp) {
        http_send_json_obj(io, 200, resp);
        json_object_put(resp);
    } else {
        if (resp) json_object_put(resp);
        if (err[0]) LOG_INFO("[fips] list rejected: %s", err);
        if (status == 404) http_send_error(io, 404, "not found");
        else if (status == 400) http_send_error(io, 400, "invalid filter");
        else if (status == 503) http_send_error(io, 503, "database unavailable");
        else http_send_error(io, 500, "internal error");
    }
}

/* GET /ca/public-key — CA ML-DSA-87 public key in PEM format. */
static void handle_ca_public_key(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    /* ML-DSA-87 PEM-wrapped DER is ~3.5 KiB; size generously. */
    char pem[8192];
    int pemSz;

    json_object_object_add(obj, "ca_name",
        json_object_new_string(store->ca_name));
    json_object_object_add(obj, "cosigner_id",
        json_object_new_string(store->cosigner_id));
    json_object_object_add(obj, "algorithm",
        json_object_new_string("ML-DSA-87"));

    pemSz = mtc_store_get_public_key_pem(store, pem, (int)sizeof(pem));
    if (pemSz > 0) {
        pem[pemSz] = 0;
        json_object_object_add(obj, "public_key_pem",
            json_object_new_string(pem));
    }

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /public-key/<name> — look up a public key from mtc_public_keys table. */
static void handle_public_key_lookup(client_io *io, MtcStore *store,
                                     const char *key_name)
{
    char *pem;

    if (!store->db) {
        http_send_error(io, 503, "database not available");
        return;
    }

    pem = mtc_db_get_public_key(store->db, key_name);
    if (!pem) {
        http_send_error(io, 404, "public key not found");
        return;
    }

    /* Ensure the PEM ends with a newline.  The cert's
     * subject_public_key_hash field is sha256(pem_bytes), computed at
     * enrollment time over the PEM as the operator wrote it (text
     * file, trailing '\n').  The DB round-trip and certain JSON
     * encoders strip that final newline, so when a peer-verifier
     * fetches via /public-key/<name> and hashes the result, the
     * sha256 differs by exactly one byte.  Re-adding the newline
     * here keeps the served bytes aligned with the cert's claim.
     * (Same class of whitespace-sensitive PEM hashing as TODO #53,
     * different code path.) */
    {
        size_t plen = strlen(pem);
        if (plen == 0 || pem[plen - 1] != '\n') {
            char *fixed = (char *)malloc(plen + 2);
            if (fixed) {
                memcpy(fixed, pem, plen);
                fixed[plen]     = '\n';
                fixed[plen + 1] = '\0';
                free(pem);
                pem = fixed;
            }
        }
    }

    {
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "key_name",
            json_object_new_string(key_name));
        json_object_object_add(obj, "key_value",
            json_object_new_string(pem));
        http_send_json_obj(io, 200, obj);
        json_object_put(obj);
    }

    free(pem);
}

/* GET /trust-anchors — list of trust anchors.
 *
 * Pre-2026-05-07 this also enumerated landmark anchors backed by
 * mtc_landmarks; that table was retired (TODO #76) since no live
 * client used the landmark trust-anchor format.  The endpoint
 * stays as the single-element standalone anchor for compat. */
static void handle_trust_anchors(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct json_object *anchor;

    anchor = json_object_new_object();
    json_object_object_add(anchor, "id",
        json_object_new_string(store->log_id));
    json_object_object_add(anchor, "type",
        json_object_new_string("standalone"));
    json_object_array_add(arr, anchor);

    json_object_object_add(obj, "trust_anchors", arr);
    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* ------------------------------------------------------------------ */
/* Revocation handlers                                                 */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    handle_revoke
 *
 * Description:
 *   POST /revoke — revoke a LEAF certificate under a CA's authority.
 *
 *   Authorization model:
 *     - Only a CA (subject "<domain>-ca") may revoke.
 *     - The CA may revoke only LEAVES (subject not ending in "-ca").
 *     - The target leaf's subject must be within the CA's domain:
 *       leaf subject == "<ca-domain>" or ends in ".<ca-domain>".
 *     - The CA may not revoke itself (ca_cert_index != cert_index).
 *     - The caller must sign a freshness-bound payload using the CA's
 *       private key; the server rehashes the supplied PEM against the
 *       CA's logged public-key hash.
 *
 *   Body (all fields required):
 *     {
 *       "ca_cert_index":     M,                    // the revoking CA
 *       "cert_index":        N,                    // the leaf being revoked
 *       "reason":            "...",
 *       "timestamp":         <epoch, ±5 min>,
 *       "ca_public_key_pem": "-----BEGIN ...-----\n...",
 *       "signature":         "<hex>"
 *     }
 *
 *   sign_msg = "revoke:<ca_cert_index>:<cert_index>:<reason>:<timestamp>"
 ******************************************************************************/
static void handle_revoke(client_io *io, MtcStore *store,
                          const char *body, int body_len)
{
    struct json_object *req, *val;
    struct json_object *ca_cert_json, *ca_sc, *ca_tbs;
    struct json_object *tgt_cert_json, *tgt_sc, *tgt_tbs;
    int   ca_cert_index = -1;
    int   cert_index    = -1;
    const char *reason        = "";
    const char *ca_pub_pem    = NULL;
    const char *sig_hex       = NULL;
    const char *ca_logged_hash;
    const char *ca_algo;
    const char *ca_subject;
    const char *tgt_subject;
    long timestamp = 0;
    long now;
    char computed_hash[65];
    char ca_domain[256];
    size_t ca_subj_len, ca_dom_len, tgt_subj_len;

    /* Enrollment-level AbuseIPDB gate */
    if (io->ip_str[0] != '\0') {
        int score = mtc_checkendpoint(io->ip_str);
        if (score >= ABUSEIPDB_ENROLL_THRESHOLD) {
            LOG_WARN("revoke rejected for %s (abuse score %d >= %d)",
                     io->ip_str, score, ABUSEIPDB_ENROLL_THRESHOLD);
            http_send_error(io, 403, "revocation denied");
            return;
        }
    }

    (void)body_len;
    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        return;
    }

    if (!json_object_object_get_ex(req, "ca_cert_index", &val)) {
        http_send_error(io, 400, "missing 'ca_cert_index'");
        json_object_put(req);
        return;
    }
    ca_cert_index = json_object_get_int(val);

    if (!json_object_object_get_ex(req, "cert_index", &val)) {
        http_send_error(io, 400, "missing 'cert_index'");
        json_object_put(req);
        return;
    }
    cert_index = json_object_get_int(val);

    if (json_object_object_get_ex(req, "reason", &val))
        reason = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "timestamp", &val)) {
        http_send_error(io, 400, "missing 'timestamp'");
        json_object_put(req);
        return;
    }
    timestamp = (long)json_object_get_int64(val);

    if (!json_object_object_get_ex(req, "ca_public_key_pem", &val)) {
        http_send_error(io, 400, "missing 'ca_public_key_pem'");
        json_object_put(req);
        return;
    }
    ca_pub_pem = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "signature", &val)) {
        http_send_error(io, 400, "missing 'signature'");
        json_object_put(req);
        return;
    }
    sig_hex = json_object_get_string(val);

    /* --- Self-revocation check --- */
    if (ca_cert_index == cert_index) {
        LOG_WARN("revoke: CA %d attempted self-revocation", ca_cert_index);
        http_send_error(io, 403, "CA may not revoke itself");
        json_object_put(req);
        return;
    }

    /* --- Freshness ---
     * Window is operator-tunable via mqc-sig-freshness-sec in
     * /etc/postWolf/config (issue 6a); falls back to
     * MTC_SIG_FRESHNESS_SEC compiled default. */
    now = (long)time(NULL);
    if (timestamp < now - mqc_rt_cfg()->sig_freshness_sec ||
        timestamp > now + mqc_rt_cfg()->sig_freshness_sec) {
        LOG_WARN("revoke: stale/future timestamp %ld (server now=%ld)",
                 timestamp, now);
        http_send_error(io, 400,
            "timestamp outside freshness window");
        json_object_put(req);
        return;
    }

    /* --- Look up CA cert --- */
    ca_cert_json = mtc_store_get_cert(store, ca_cert_index);
    if (!ca_cert_json) {
        http_send_error(io, 404, "CA certificate not found");
        json_object_put(req);
        return;
    }
    if (!json_object_object_get_ex(ca_cert_json, "standalone_certificate",
                                   &ca_sc) ||
        !json_object_object_get_ex(ca_sc, "tbs_entry", &ca_tbs)) {
        http_send_error(io, 500, "malformed CA cert");
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    if (!json_object_object_get_ex(ca_tbs, "subject", &val)) {
        http_send_error(io, 500, "CA cert missing subject");
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    ca_subject = json_object_get_string(val);

    /* Verify caller is a CA — subject ends in "-ca" */
    ca_subj_len = strlen(ca_subject);
    if (ca_subj_len < 3 || strcmp(ca_subject + ca_subj_len - 3, "-ca") != 0) {
        LOG_WARN("revoke: caller subject '%s' is not a CA", ca_subject);
        http_send_error(io, 403, "caller is not a CA");
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    /* Derive CA domain = subject minus "-ca" suffix */
    ca_dom_len = ca_subj_len - 3;
    if (ca_dom_len >= sizeof(ca_domain)) ca_dom_len = sizeof(ca_domain) - 1;
    memcpy(ca_domain, ca_subject, ca_dom_len);
    ca_domain[ca_dom_len] = '\0';

    if (!json_object_object_get_ex(ca_tbs, "subject_public_key_hash", &val)) {
        http_send_error(io, 500, "CA cert missing key hash");
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    ca_logged_hash = json_object_get_string(val);

    ca_algo = "ML-DSA-87";
    if (json_object_object_get_ex(ca_tbs, "subject_public_key_algorithm",
                                  &val))
        ca_algo = json_object_get_string(val);

    /* --- Look up target cert --- */
    tgt_cert_json = mtc_store_get_cert(store, cert_index);
    if (!tgt_cert_json) {
        http_send_error(io, 404, "target certificate not found");
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    if (!json_object_object_get_ex(tgt_cert_json, "standalone_certificate",
                                   &tgt_sc) ||
        !json_object_object_get_ex(tgt_sc, "tbs_entry", &tgt_tbs)) {
        http_send_error(io, 500, "malformed target cert");
        json_object_put(tgt_cert_json);
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    if (!json_object_object_get_ex(tgt_tbs, "subject", &val)) {
        http_send_error(io, 500, "target cert missing subject");
        json_object_put(tgt_cert_json);
        json_object_put(ca_cert_json);
        json_object_put(req);
        return;
    }
    tgt_subject = json_object_get_string(val);
    tgt_subj_len = strlen(tgt_subject);

    /* Verify target is a leaf (subject NOT ending in "-ca") */
    if (tgt_subj_len >= 3 &&
        strcmp(tgt_subject + tgt_subj_len - 3, "-ca") == 0) {
        LOG_WARN("revoke: target '%s' is a CA, not a leaf", tgt_subject);
        http_send_error(io, 403, "target is not a leaf");
        goto cleanup;
    }

    /* Verify target subject is in CA's domain (exact or *.domain) */
    {
        int in_domain = 0;
        if (tgt_subj_len == ca_dom_len &&
            strcmp(tgt_subject, ca_domain) == 0) {
            in_domain = 1;
        } else if (tgt_subj_len > ca_dom_len + 1 &&
                   tgt_subject[tgt_subj_len - ca_dom_len - 1] == '.' &&
                   strcmp(tgt_subject + tgt_subj_len - ca_dom_len,
                          ca_domain) == 0) {
            in_domain = 1;
        }
        if (!in_domain) {
            LOG_WARN("revoke: target '%s' not in CA domain '%s'",
                     tgt_subject, ca_domain);
            http_send_error(io, 403,
                "target leaf is not within the CA's domain");
            goto cleanup;
        }
    }

    /* --- Hash caller's CA PEM vs logged CA hash --- */
    {
        wc_Sha256 sha;
        uint8_t h[32];
        int fi;
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, (const uint8_t *)ca_pub_pem,
                        (word32)strlen(ca_pub_pem));
        wc_Sha256Final(&sha, h);
        wc_Sha256Free(&sha);
        for (fi = 0; fi < 32; fi++)
            snprintf(computed_hash + fi * 2, 3, "%02x", h[fi]);
    }
    if (strcmp(computed_hash, ca_logged_hash) != 0) {
        LOG_WARN("revoke: CA key hash mismatch for ca_cert_index %d",
                 ca_cert_index);
        http_send_error(io, 403,
            "ca_public_key_pem does not match logged CA certificate");
        goto cleanup;
    }

    /* --- Verify signature --- */
    {
        uint8_t sig_bytes[8192];
        int sig_len;
        char sign_msg[MAX_PATH_SZ];
        int verified = 0;
        int ret;
        uint8_t der_buf[4096];
        int der_sz;

        snprintf(sign_msg, sizeof(sign_msg), "revoke:%d:%d:%s:%ld",
                 ca_cert_index, cert_index, reason, timestamp);

        sig_len = (int)strlen(sig_hex) / 2;
        if (sig_len <= 0 || sig_len > (int)sizeof(sig_bytes)) {
            http_send_error(io, 400, "invalid signature length");
            goto cleanup;
        }
        {
            int si;
            for (si = 0; si < sig_len; si++) {
                unsigned int b;
                if (sscanf(sig_hex + si * 2, "%02x", &b) != 1) {
                    http_send_error(io, 400, "invalid signature hex");
                    goto cleanup;
                }
                sig_bytes[si] = (uint8_t)b;
            }
        }

        der_sz = (int)sizeof(der_buf);
        ret = wc_PubKeyPemToDer((const unsigned char *)ca_pub_pem,
                                (int)strlen(ca_pub_pem),
                                der_buf, der_sz);
        if (ret < 0) {
            LOG_WARN("revoke: CA PEM to DER failed: %d", ret);
            http_send_error(io, 400, "invalid CA public key PEM");
            goto cleanup;
        }
        der_sz = ret;

        if (strncmp(ca_algo, "ML-DSA-", 7) == 0) {
            dilithium_key dil;
            byte level;
            word32 didx = 0;
            if (strcmp(ca_algo, "ML-DSA-44") == 0)       level = WC_ML_DSA_44;
            else if (strcmp(ca_algo, "ML-DSA-65") == 0)  level = WC_ML_DSA_65;
            else if (strcmp(ca_algo, "ML-DSA-87") == 0)  level = WC_ML_DSA_87;
            else {
                http_send_error(io, 400, "unsupported ML-DSA variant");
                goto cleanup;
            }
            wc_dilithium_init(&dil);
            wc_dilithium_set_level(&dil, level);
            /* der_buf holds the SPKI-wrapped DER produced by
             * wc_PubKeyPemToDer above (~2614 bytes for ML-DSA-87).
             * wc_dilithium_import_public expects RAW key bytes
             * (2592 for ML-DSA-87) and would silently fail with -173
             * on the SPKI form, masking the real cause as
             * "signature verification failed".  Use
             * wc_Dilithium_PublicKeyDecode, which strips the SPKI
             * wrapper.  Same pattern as mtc_bootstrap.c:1279. */
            ret = wc_Dilithium_PublicKeyDecode(der_buf, &didx, &dil,
                                               (word32)der_sz);
            if (ret == 0)
                ret = wc_dilithium_verify_ctx_msg(sig_bytes,
                                                   (word32)sig_len,
                                                   NULL, 0,
                                                   (const uint8_t *)sign_msg,
                                                   (word32)strlen(sign_msg),
                                                   &verified, &dil);
            wc_dilithium_free(&dil);
        }
        else {
            http_send_error(io, 400,
                "unsupported key algorithm for revocation");
            goto cleanup;
        }

        if (ret != 0 || !verified) {
            LOG_WARN("revoke: signature verification failed "
                     "(ca=%d target=%d algo=%s)",
                     ca_cert_index, cert_index, ca_algo);
            http_send_error(io, 403, "signature verification failed");
            goto cleanup;
        }
    }

    /* Authorized — perform the revocation */
    if (mtc_store_revoke(store, cert_index, reason) != 0) {
        http_send_error(io, 500, "revocation failed");
        goto cleanup;
    }

    LOG_INFO("revoke: cert %d ('%s') revoked by CA %d ('%s') reason='%s'",
             cert_index, tgt_subject, ca_cert_index, ca_subject, reason);

    /* Phase 3 retired the SIGHUP-reload pipeline.  Tile state is
     * authoritative in Neon; subsequent forks fault tiles + cert
     * blobs through the LRU on miss, picking up the just-committed
     * revocation row automatically. */

    {
        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, "revoked",
            json_object_new_boolean(1));
        json_object_object_add(resp, "cert_index",
            json_object_new_int(cert_index));
        json_object_object_add(resp, "ca_cert_index",
            json_object_new_int(ca_cert_index));
        json_object_object_add(resp, "target_subject",
            json_object_new_string(tgt_subject));
        json_object_object_add(resp, "reason",
            json_object_new_string(reason[0] ? reason : "unspecified"));
        http_send_json_obj(io, 200, resp);
        json_object_put(resp);
    }

cleanup:
    json_object_put(tgt_cert_json);
    json_object_put(ca_cert_json);
    json_object_put(req);
}

/* GET /revoked — full revocation list. */
static void handle_revoked_list(client_io *io, MtcStore *store)
{
    struct json_object *list = mtc_store_get_revocation_list(store);
    http_send_json_obj(io, 200, list);
    json_object_put(list);
}

/* GET /revoked/<index> — check if a specific certificate is revoked. */
static void handle_revoked_check(client_io *io, MtcStore *store, int index)
{
    struct json_object *obj = json_object_new_object();
    int revoked = mtc_store_is_revoked(store, index);

    json_object_object_add(obj, "cert_index", json_object_new_int(index));
    json_object_object_add(obj, "revoked", json_object_new_boolean(revoked));
    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* ------------------------------------------------------------------ */
/* Request parsing and dispatch                                        */
/* ------------------------------------------------------------------ */

static slc_ctx_t *g_slc_ctx = NULL;  /**< Set by mtc_http_serve for ECH */

/* GET /ech/configs — serve the server's ECH config as base64 JSON. */
static void handle_ech_configs(client_io *io, MtcStore *store)
{
    (void)store;
#ifdef HAVE_ECH
    if (g_slc_ctx != NULL) {
        unsigned char raw[1024];
        int sz = (int)sizeof(raw);
        if (slc_ctx_get_ech_configs(g_slc_ctx, raw, &sz) == 0 && sz > 0) {
            /* Base64 encode */
            word32 b64Sz = 0;
            Base64_Encode(raw, (word32)sz, NULL, &b64Sz);
            if (b64Sz > 0) {
                char *b64 = (char *)malloc(b64Sz + 1);
                if (b64 != NULL) {
                    Base64_Encode(raw, (word32)sz, (byte *)b64, &b64Sz);
                    b64[b64Sz] = '\0';
                    /* Strip any trailing newlines from Base64_Encode */
                    while (b64Sz > 0 && (b64[b64Sz-1] == '\n' ||
                           b64[b64Sz-1] == '\r'))
                        b64[--b64Sz] = '\0';
                    http_send_json(io, 200, b64);
                    free(b64);
                    return;
                }
            }
        }
    }
#endif
    http_send_error(io, 404, "ECH not configured");
}

/******************************************************************************
 * Function:    dispatch_get  (static)
 *
 * Description:
 *   Route a GET path to the appropriate handler.  No rate limiting here;
 *   callers apply their own (handle_request does RL_READ network-side;
 *   the bootstrap capture path applies its own per-request limits).
 ******************************************************************************/
static void dispatch_get(client_io *io, MtcStore *store, const char *path)
{
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        handle_index(io, store);
    }
    else if (strcmp(path, "/log") == 0) {
        handle_log_state(io, store);
    }
    else if (strncmp(path, "/log/entry/", 11) == 0) {
        int index = safe_atoi(path + 11, 10000000);
        if (index < 0) { http_send_error(io, 400, "invalid index"); }
        else handle_log_entry(io, store, index);
    }
    else if (strncmp(path, "/log/proof/", 11) == 0) {
        int index = safe_atoi(path + 11, 10000000);
        if (index < 0) { http_send_error(io, 400, "invalid index"); }
        else handle_log_proof(io, store, index);
    }
    else if (strcmp(path, "/log/checkpoint") == 0) {
        handle_checkpoint(io, store);
    }
    else if (strcmp(path, "/log/diagnostics") == 0) {
        handle_log_diagnostics(io, store);
    }
    else if (strncmp(path, "/log/consistency", 16) == 0) {
        handle_consistency(io, store, path);
    }
    else if (strncmp(path, "/certificate/search", 19) == 0) {
        handle_search_certificates(io, store, path);
    }
    else if (strncmp(path, "/certificate/", 13) == 0) {
        int index = safe_atoi(path + 13, 10000000);
        if (index < 0) { http_send_error(io, 400, "invalid index"); }
        else handle_get_certificate(io, store, index);
    }
    else if (strcmp(path, "/trust-anchors") == 0) {
        handle_trust_anchors(io, store);
    }
    else if (strcmp(path, "/revoked") == 0) {
        handle_revoked_list(io, store);
    }
    else if (strncmp(path, "/revoked/", 9) == 0) {
        int index = safe_atoi(path + 9, 10000000);
        if (index < 0) { http_send_error(io, 400, "invalid index"); }
        else handle_revoked_check(io, store, index);
    }
    else if (strcmp(path, "/ca/public-key") == 0) {
        handle_ca_public_key(io, store);
    }
    else if (strncmp(path, "/public-key/", 12) == 0) {
        handle_public_key_lookup(io, store, path + 12);
    }
    else if (strcmp(path, "/ech/configs") == 0) {
        handle_ech_configs(io, store);
    }
    else if (strcmp(path, "/fips/list") == 0 ||
             strncmp(path, "/fips/list?", 11) == 0) {
        handle_fips_list(io, store, path);
    }
    else if (strncmp(path, "/fips/revoked/", 14) == 0) {
        int idx = safe_atoi(path + 14, 100000000);
        if (idx < 0) { http_send_error(io, 400, "invalid log_index"); }
        else {
            struct json_object *resp = NULL;
            int status = 500;
            char err[256]; err[0] = 0;
            int rc = mtc_fips_revoke_status(store, idx, &resp, &status,
                                            err, sizeof(err));
            if (rc == 0 && resp) {
                http_send_json_obj(io, 200, resp);
                json_object_put(resp);
            } else {
                if (resp) json_object_put(resp);
                if (err[0]) LOG_INFO("[fips] revoked-status: %s", err);
                if (status == 503)
                    http_send_error(io, 503, "database unavailable");
                else
                    http_send_error(io, 500, "internal error");
            }
        }
    }
    else {
        http_send_error(io, 404, "not found");
    }
}

/******************************************************************************
 * Function:    mtc_http_dispatch_get_capture
 *
 * Description:
 *   Public in-process GET dispatcher.  Builds a capture-mode client_io,
 *   calls dispatch_get, and returns the captured JSON body + HTTP-style
 *   status code.  Caller owns *body_out (free it).  Used by the bootstrap
 *   port's {"op":"http_get","path":...} handler to reach the same
 *   endpoints as the network HTTP listener without a socket round-trip.
 ******************************************************************************/
int mtc_http_dispatch_get_capture(MtcStore *store, const char *path,
                                  char **body_out, int *status_out)
{
    client_io io;
    memset(&io, 0, sizeof(io));
    io.fd = -1;
    io.capture_body = body_out;
    io.capture_status = status_out;
    *body_out = NULL;
    *status_out = 0;
    dispatch_get(&io, store, path);
    return (*body_out != NULL && *status_out != 0) ? 0 : -1;
}

/******************************************************************************
 * Function:    handle_request
 *
 * Description:
 *   Reads a single HTTP request from the client, parses method and path,
 *   extracts the body (reading additional data if Content-Length indicates
 *   more), applies rate limiting, and dispatches to the appropriate API
 *   handler.
 *
 * Input Arguments:
 *   io     - Client I/O context.
 *   store  - MTC store.
 *
 * Notes:
 *   The entire request (headers + body) must fit in HTTP_BUF_SZ.
 *   Requests exceeding 1 MB Content-Length are rejected with 413.
 ******************************************************************************/
static void handle_request(client_io *io, MtcStore *store)
{
    char buf[HTTP_BUF_SZ];
    int n;
    char method[16], path[MAX_PATH_SZ];
    char *body = NULL;
    int body_len = 0;

    /* TODO #66: bound the per-read wall-clock so a slow-loris client
     * cannot tie up this forked worker indefinitely.  Applies to TLS
     * and plain transports only — MQC has its own handshake-deadline
     * machinery and post-handshake framing that a kernel-level
     * SO_RCVTIMEO would clobber. */
    if (io->fd >= 0 && !io->mqc) {
        struct timeval tv;
        tv.tv_sec  = MTC_HTTP_READ_STALL_SEC;
        tv.tv_usec = 0;
        (void)setsockopt(io->fd, SOL_SOCKET, SO_RCVTIMEO,
                         &tv, sizeof(tv));
    }

    /* Read until we have the full headers (\r\n\r\n).
     * TLS may fragment the request across multiple reads. */
    n = 0;
    while (n < (int)sizeof(buf) - 1) {
        int r = cio_read(io, buf + n, (int)sizeof(buf) - 1 - n);
        if (r <= 0) {
            if (n == 0) return;  /* no data at all */
            break;
        }
        n += r;
        buf[n] = 0;
        if (strstr(buf, "\r\n\r\n"))
            break;  /* have complete headers */
    }

    /* Parse method and path */
    if (sscanf(buf, "%15s %511s", method, path) != 2) {
        http_send_error(io, 400, "bad request");
        return;
    }

    /* Strip trailing slash */
    {
        int plen = (int)strlen(path);
        if (plen > 1 && path[plen - 1] == '/')
            path[plen - 1] = 0;
    }

    /* Find body (after \r\n\r\n) */
    body = strstr(buf, "\r\n\r\n");
    if (body) {
        body += 4;
        body_len = n - (int)(body - buf);
    }

    /* If Content-Length says there's more body to read, keep reading */
    if (body) {
        /* Search for Content-Length only in headers (before body) */
        char saved = body[-4]; /* save char at \r\n\r\n boundary */
        body[-4] = 0;         /* temporarily null-terminate headers */
        {
            char *cl = strcasestr(buf, "Content-Length:");
            body[-4] = saved;
            if (cl) {
                /* Skip "Content-Length:" and any whitespace */
                const char *val_start = cl + 15;
                while (*val_start == ' ' || *val_start == '\t')
                    val_start++;
                int content_len = safe_atoi(val_start, 1024 * 1024);
                int max_body = (int)(sizeof(buf) - 1) - (int)(body - buf);
                if (content_len < 0 || content_len > max_body) {
                    http_send_error(io, 413, "request body too large");
                    return;
                }
                if (content_len > 0) {
                    while (body_len < content_len) {
                        int r = cio_read(io, body + body_len,
                                         content_len - body_len);
                        if (r <= 0) break;
                        body_len += r;
                    }
                    body[body_len] = 0;
                }
            }
        }
    }

    /* Ensure DB connection is alive before dispatching */
    if (store->use_db) {
        if (mtc_db_ensure_connected(&store->db) != 0) {
            LOG_ERROR("DB connection lost and reconnect failed");
            store->db = NULL;
        }
    }

    /* Dispatch */
    LOG_DEBUG("%s %s from %s", method, path, io->ip_str);

    if (strcmp(method, "GET") == 0) {
        /* Rate limit all reads */
        if (!mtc_ratelimit_check(io->ip_str, RL_READ)) {
            http_send_error(io, 429, "rate limit exceeded");
            return;
        }
        dispatch_get(io, store, path);
    }
    else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/enrollment/nonce") == 0) {
            /* Rate limit checked inside handler (leaf vs CA have different limits) */
            handle_enrollment_nonce(io, store, body, body_len);
        }
        else if (strcmp(path, "/certificate/request") == 0) {
            http_send_error(io, 410,
                "endpoint removed — use DH bootstrap port for enrollment");
        }
        else if (strcmp(path, "/renew-cert") == 0) {
            if (!mtc_ratelimit_check(io->ip_str, RL_ENROLL)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            handle_renew_cert(io, store, body, body_len);
        }
        else if (strcmp(path, "/fips/manifest") == 0) {
            /* FIPS-manifest submission.  Validation pipeline lives in
             * mtc_fips.c (spec-canonical-leaf v1).  Errors are surfaced
             * as a generic 4xx string to the client; the operator-side
             * detail is logged via INFO/WARN inside mtc_fips_submit. */
            if (!mtc_ratelimit_check(io->ip_str, RL_ENROLL)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            struct json_object *receipt = NULL;
            int status = 500;
            char err_msg[512];
            err_msg[0] = 0;
            int rc = mtc_fips_submit(store,
                                     (const uint8_t *)body, (size_t)body_len,
                                     &receipt, &status,
                                     err_msg, sizeof(err_msg));
            if (rc == 0 && receipt) {
                http_send_json_obj(io, 200, receipt);
                json_object_put(receipt);
            } else {
                LOG_INFO("[fips] submission rejected: %s", err_msg);
                if (receipt) json_object_put(receipt);
                /* Generic surface — no field-level detail to the client */
                if (status == 403)
                    http_send_error(io, 403, "publisher revoked");
                else if (status == 429)
                    http_send_error(io, 429, "rate limit exceeded");
                else if (status >= 500)
                    http_send_error(io, 500, "internal error");
                else
                    http_send_error(io, 400, "invalid manifest");
            }
        }
        else if (strcmp(path, "/fips/revoke") == 0) {
            /* FIPS-manifest revocation.  Validation pipeline lives in
             * mtc_fips.c::mtc_fips_revoke (spec-canonical-leaf.md
             * "Manifest revocation").  Same surface posture as
             * /fips/manifest: generic 4xx string out, operator detail
             * logged inside the handler. */
            if (!mtc_ratelimit_check(io->ip_str, RL_REVOKE)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            struct json_object *resp = NULL;
            int status = 500;
            char err_msg[512];
            err_msg[0] = 0;
            int rc = mtc_fips_revoke(store,
                                     (const uint8_t *)body, (size_t)body_len,
                                     &resp, &status,
                                     err_msg, sizeof(err_msg));
            if (rc == 0 && resp) {
                http_send_json_obj(io, 200, resp);
                json_object_put(resp);
            } else {
                LOG_INFO("[fips] revoke rejected: %s", err_msg);
                if (resp) json_object_put(resp);
                if (status == 403)
                    http_send_error(io, 403, "not authorized");
                else if (status == 404)
                    http_send_error(io, 404, "not found");
                else if (status == 429)
                    http_send_error(io, 429, "rate limit exceeded");
                else if (status == 503)
                    http_send_error(io, 503, "database unavailable");
                else if (status >= 500)
                    http_send_error(io, 500, "internal error");
                else
                    http_send_error(io, 400, "invalid request");
            }
        }
        else if (strcmp(path, "/cancel-nonce") == 0) {
            if (!mtc_ratelimit_check(io->ip_str, RL_REVOKE)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            handle_cancel_nonce(io, store, body, body_len);
        }
        else if (strcmp(path, "/revoke") == 0) {
            if (!mtc_ratelimit_check(io->ip_str, RL_REVOKE)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            handle_revoke(io, store, body, body_len);
        }
        else {
            http_send_error(io, 404, "not found");
        }
    }
    else {
        http_send_error(io, 405, "method not allowed");
    }
}

/* ------------------------------------------------------------------ */
/* Server main loop                                                    */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    mtc_http_serve
 *
 * Description:
 *   Main server entry point.  Sets up TLS (if configured), binds the
 *   listen socket, and enters a blocking accept loop.  Each accepted
 *   connection is handled synchronously: extract client IP, check
 *   AbuseIPDB score, dispatch request, then close.
 *
 * Input Arguments:
 *   host     - Bind address (NULL = "0.0.0.0").
 *   port     - TCP port.
 *   store    - Initialised MTC store.  Must outlive the server.
 *   tls_cfg  - TLS configuration (NULL = plain HTTP).
 *
 * Returns:
 *    0  on clean exit (currently unreachable — loops forever).
 *   -1  on fatal startup error (TLS init or listen failure).
 *
 * Side Effects:
 *   - Calls slc_ctx_new() / slc_listen() to bind the socket.
 *   - Sets g_slc_ctx for the /ech/configs endpoint.
 *   - Per-connection: calls mtc_checkendpoint() for AbuseIPDB screening.
 ******************************************************************************/
/* ----------------------------------------------------------------------
 * Per-connection fork backpressure
 *
 * Each accept on either the TLS/plain listener or the MQC listener
 * spawns a child via fork().  Without an upper bound, a burst of N
 * client connects translates directly into N concurrent children --
 * which has been observed to wedge the host (~70+ children).  Hold
 * the active-child count below mqc-max-children (default 20); if we
 * already have that many, sleep(1) and re-check before accepting the
 * next connection.  Children continue to run; only the *accept rate*
 * is throttled, so bursts stretch out over time rather than fanning
 * into an arbitrary fork-storm.
 *
 * Counter maintenance: SIGCHLD handler reaps in WNOHANG-loop and
 * decrements the counter.  Replaces the pre-existing
 * `signal(SIGCHLD, SIG_IGN)` (auto-reap-without-counter) -- callers
 * MUST invoke mtc_install_child_reaper() during startup or the
 * counter will only ever grow.
 * -------------------------------------------------------------------- */

static atomic_int g_active_children = 0;

static void mtc_sigchld_reap(int sig)
{
    (void)sig;
    int saved_errno = errno;
    pid_t pid;
    /* SIGCHLD coalesces — multiple deaths may queue a single signal
     * delivery, so loop until waitpid drains. */
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        atomic_fetch_sub(&g_active_children, 1);
    }
    errno = saved_errno;
}

void mtc_install_child_reaper(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = mtc_sigchld_reap;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        LOG_ERROR("sigaction(SIGCHLD) failed: %s", strerror(errno));
    }
}

static long mtc_max_children(void)
{
    static long cached = -1;
    if (cached < 0) {
        cached = read_config_long("global/mqc-max-children",
                                  MTC_MAX_CHILDREN_DEFAULT);
        if (cached <= 0) cached = MTC_MAX_CHILDREN_DEFAULT;
        LOG_INFO("backpressure: max-children=%ld", cached);
    }
    return cached;
}

void mtc_wait_for_child_slot(const char *which)
{
    int active;
    int logged = 0;
    while ((active = atomic_load(&g_active_children)) >= mtc_max_children()) {
        if (!logged) {
            LOG_INFO("%s backpressure: %d/%ld active children, "
                     "sleeping before accept", which, active,
                     mtc_max_children());
            logged = 1;
        }
        sleep(1);
    }
}

void mtc_register_active_child(void)
{
    atomic_fetch_add(&g_active_children, 1);
}

int mtc_http_serve(const char *host, int port, MtcStore *store,
                   const mtc_tls_cfg_t *tls_cfg)
{
    int listen_fd;
    slc_ctx_t *ctx = NULL;
    int use_tls = (tls_cfg != NULL && tls_cfg->cert_file != NULL);

    /* Set up TLS context if configured */
    if (use_tls) {
        slc_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.role            = SLC_SERVER;
        cfg.cert_file       = tls_cfg->cert_file;
        cfg.key_file        = tls_cfg->key_file;
        cfg.ca_file         = tls_cfg->ca_file;
        cfg.ech_public_name = tls_cfg->ech_public_name;

        ctx = slc_ctx_new(&cfg);
        if (ctx == NULL) {
            fprintf(stderr, "slc_ctx_new failed\n");
            return -1;
        }
        g_slc_ctx = ctx;  /* for /ech/configs endpoint */
    }

    /* Listen */
    listen_fd = slc_listen(host, port);
    if (listen_fd < 0) {
        fprintf(stderr, "slc_listen failed on %s:%d\n",
                host ? host : "0.0.0.0", port);
        if (ctx) slc_ctx_free(ctx);
        return -1;
    }

    printf("MTC CA/Log Server (C) listening on %s:%d%s\n",
           host ? host : "0.0.0.0", port,
           use_tls ? " (TLS 1.3)" : " (plain)");
    printf("  CA Name:  %s\n", store->ca_name);
    printf("  Log ID:   %s\n", store->log_id);
    printf("  Log size: %d entries\n", store->tree.size);
    printf("  Data dir: %s\n", store->data_dir);

    /* P0 / TODO #9b CA branch — print the cosigner-key DNS pin
     * the operator MUST publish at _mqc-cosigner.<their-domain>
     * for cross-host bootstrap_ca to verify the cosigner PEM via
     * DNSSEC.  Computed from the cosigner SPKI DER + SHA3-256 +
     * lowercase hex.  Pasted once into Route 53 / equivalent;
     * never changes unless the cosigner key is rotated.  Logged
     * on every startup so the operator can pull it from the
     * journal at any time. */
    {
        char pem[8192];
        int  pem_sz = mtc_store_get_public_key_pem(store, pem,
                                                   (int)sizeof(pem));
        unsigned char der[4096];
        int  der_sz = (pem_sz > 0)
            ? wc_PubKeyPemToDer((const unsigned char *)pem, pem_sz,
                                der, (int)sizeof(der))
            : -1;
        if (der_sz > 0) {
            unsigned char digest[32];
            wc_Sha3 sha;
            wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
            wc_Sha3_256_Update(&sha, der, (word32)der_sz);
            wc_Sha3_256_Final(&sha, digest);
            wc_Sha3_256_Free(&sha);
            char hex[65];
            int  hi;
            static const char hexdigits[] = "0123456789abcdef";
            for (hi = 0; hi < 32; hi++) {
                hex[hi * 2]     = hexdigits[(digest[hi] >> 4) & 0xf];
                hex[hi * 2 + 1] = hexdigits[digest[hi] & 0xf];
            }
            hex[64] = '\0';
            printf("  Cosigner DNS pin (publish at _mqc-cosigner.<your-domain>):\n");
            printf("    \"v=MQC1; role=cosigner; alg=ML-DSA-87; "
                   "kh=sha3-256:%s\"\n", hex);
        } else {
            printf("  Cosigner DNS pin: <unavailable; "
                   "wc_PubKeyPemToDer rc=%d>\n", der_sz);
        }
    }

    printf("\n");
    fflush(stdout);

    for (;;) {
        client_io cio;
        memset(&cio, 0, sizeof(cio));
        cio.fd = -1;

        /* Backpressure: if we already have mqc-max-children active
         * forks, sleep until the SIGCHLD reaper drains some.  Done
         * BEFORE accept so the kernel just leaves new connections in
         * the listen backlog instead of letting us fork-storm. */
        mtc_wait_for_child_slot(use_tls ? "TLS" : "plain");

        if (use_tls) {
            /* TLS accept */
            cio.tls = slc_accept(ctx, listen_fd);
            if (cio.tls == NULL) {
                LOG_WARN("TLS accept/handshake failed");
                continue;
            }
            cio.fd = slc_get_fd(cio.tls);
        } else {
            /* Plain accept */
            struct sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            cio.fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (cio.fd < 0) {
                perror("accept");
                continue;
            }
        }

        /* Fork per-connection: parent resumes accept loop, child serves.
         * Phase 3 retired the reload-lock — tile state is authoritative
         * in Neon, no SIGHUP-driven mutation of in-memory store. */
        {
            pid_t pid = fork();
            if (pid < 0) {
                LOG_ERROR("fork failed: %s", strerror(errno));
                cio_close(&cio);
                continue;
            }
            if (pid > 0) {
                /* Parent: drop socket fd — child holds its own ref.
                 * Bump child counter; SIGCHLD reaper decrements on exit. */
                atomic_fetch_add(&g_active_children, 1);
                LOG_DEBUG("forked child pid=%d for %s conn (active=%d)",
                          (int)pid, use_tls ? "TLS" : "plain",
                          atomic_load(&g_active_children));
                close(cio.fd);
                continue;
            }
            /* Child: no longer needs the listen socket. */
            LOG_DEBUG("child pid=%d handling %s conn",
                      (int)getpid(), use_tls ? "TLS" : "plain");
            close(listen_fd);
            /* Detach from the parent's PGconn — must NOT PQfinish
             * (would close the TCP socket the parent still uses).
             * mtc_db_ensure_connected will lazily open a fresh
             * connection in the child on first DB query.  Fixes
             * TODO #25 (gratuitous reconnect churn). */
            mtc_db_after_fork(&store->db);
        }

        /* Get client IP, log connection, and check against AbuseIPDB */
        cio.ip_str[0] = '\0';
        {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            if (getpeername(cio.fd, (struct sockaddr *)&peer, &peer_len) == 0) {
                inet_ntop(AF_INET, &peer.sin_addr, cio.ip_str,
                          sizeof(cio.ip_str));

                LOG_DEBUG("connection from %s", cio.ip_str);

                int abuse_score = mtc_checkendpoint(cio.ip_str);
                if (abuse_score >= mtc_get_abuse_threshold()) {
                    LOG_INFO("rejected %s (abuse score %d >= %d)",
                             cio.ip_str, abuse_score,
                             mtc_get_abuse_threshold());
                    http_send_error(&cio, 403, "Forbidden");
                    cio_close(&cio);
                    _exit(0);
                }
            }
        }

        handle_request(&cio, store);
        cio_close(&cio);
        _exit(0);
    }

    close(listen_fd);
    if (ctx) {
        g_slc_ctx = NULL;
        slc_ctx_free(ctx);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* MQC listener (port 8446)                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int          listen_fd;
    MtcStore    *store;
    mqc_ctx_t   *mqc_ctx;
} mqc_listener_arg_t;

static void *mqc_listener_thread(void *arg)
{
    mqc_listener_arg_t *la = (mqc_listener_arg_t *)arg;
    int listen_fd = la->listen_fd;
    MtcStore *store = la->store;
    mqc_ctx_t *mqc_ctx = la->mqc_ctx;
    free(la);

    LOG_INFO("MQC listener ready (fd=%d)", listen_fd);

    for (;;) {
        client_io cio;
        memset(&cio, 0, sizeof(cio));
        cio.fd = -1;

        /* Backpressure: hold the active-child count below
         * mqc-max-children before accepting the next connection.
         * See mtc_wait_for_child_slot() for rationale. */
        mtc_wait_for_child_slot("MQC");

        /* Accept MQC connection (auto-detects clear/encrypted) */
        cio.mqc = mqc_accept_auto(mqc_ctx, listen_fd);
        if (cio.mqc == NULL) {
            const char *peer = mqc_last_accept_peer_ip();
            LOG_WARN("MQC accept failed from %s",
                     peer && peer[0] ? peer : "unknown");
            continue;
        }

        cio.fd = mqc_get_fd(cio.mqc);

        /* Fork per-connection: parent resumes accept loop, child serves.
         * Phase 3 retired the reload-lock. */
        {
            pid_t pid = fork();
            if (pid < 0) {
                LOG_ERROR("MQC fork failed: %s", strerror(errno));
                cio_close(&cio);
                continue;
            }
            if (pid > 0) {
                /* Parent: drop socket fd — child holds its own ref. */
                atomic_fetch_add(&g_active_children, 1);
                LOG_DEBUG("forked child pid=%d for MQC conn (active=%d)",
                          (int)pid, atomic_load(&g_active_children));
                close(cio.fd);
                continue;
            }
            /* Child: no longer needs the listen socket. */
            LOG_DEBUG("child pid=%d handling MQC conn", (int)getpid());
            close(listen_fd);
            /* Detach from the parent's PGconn — see TLS/plain fork
             * site above for the same comment.  Fixes TODO #25. */
            mtc_db_after_fork(&store->db);
        }

        /* Get client IP */
        {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            if (getpeername(cio.fd, (struct sockaddr *)&peer, &peer_len) == 0)
                inet_ntop(AF_INET, &peer.sin_addr, cio.ip_str, sizeof(cio.ip_str));
        }

        LOG_INFO("MQC connection from %s (peer_index=%d)",
                 cio.ip_str, mqc_get_peer_index(cio.mqc));

        /* Ensure DB connection */
        if (store->use_db) {
            if (mtc_db_ensure_connected(&store->db) != 0) {
                LOG_ERROR("MQC: DB connection lost and reconnect failed");
                store->db = NULL;
            }
        }

        /* Handle request using the same dispatcher as TLS */
        handle_request(&cio, store);
        cio_close(&cio);
        _exit(0);
    }

    return NULL;
}

int mtc_mqc_start(const char *host, int port, MtcStore *store,
                  const char *tpm_path, const char *mtc_server,
                  const unsigned char *ca_pubkey, int ca_pubkey_sz)
{
    int listen_fd;
    mqc_cfg_t cfg;
    mqc_ctx_t *ctx;
    pthread_t tid;
    mqc_listener_arg_t *la;

    /* Create MQC context */
    memset(&cfg, 0, sizeof(cfg));
    cfg.role       = MQC_SERVER;
    cfg.tpm_path   = tpm_path;
    cfg.mtc_server = mtc_server;
    cfg.ca_pubkey  = ca_pubkey;
    cfg.ca_pubkey_sz = ca_pubkey_sz;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) {
        LOG_ERROR("MQC context creation failed");
        return -1;
    }

    /* Listen */
    listen_fd = mqc_listen(host, port);
    if (listen_fd < 0) {
        LOG_ERROR("MQC listen failed on %s:%d",
                  host ? host : "0.0.0.0", port);
        mqc_ctx_free(ctx);
        return -1;
    }

    /* Launch thread */
    la = malloc(sizeof(*la));
    if (!la) { close(listen_fd); mqc_ctx_free(ctx); return -1; }
    la->listen_fd = listen_fd;
    la->store = store;
    la->mqc_ctx = ctx;

    if (pthread_create(&tid, NULL, mqc_listener_thread, la) != 0) {
        LOG_ERROR("MQC thread creation failed");
        free(la);
        close(listen_fd);
        mqc_ctx_free(ctx);
        return -1;
    }
    pthread_detach(tid);

    LOG_INFO("MQC started on %s:%d", host ? host : "0.0.0.0", port);
    return 0;
}
