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
 *     GET  /ca/public-key           — CA Ed25519 public key
 *     GET  /ech/configs             — ECH config (base64)
 *     GET  /revoked                 — revocation list
 *     GET  /revoked/<n>             — revocation check
 *     POST /enrollment/nonce        — issue enrollment nonce
 *     POST /certificate/request     — enroll (CA or leaf)
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
#include "mtc_ratelimit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
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
    int         fd;         /**< Raw socket fd (used in plain mode, or for
                                 getpeername when TLS is active)            */
    char        ip_str[64]; /**< Client IP string for logging/abuse checks */
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
    if (io->tls) {
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

    cio_write(io, hdr, hdr_len);
    cio_write(io, json_str, body_len);
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
 *   NUL, '?', '&', or ' ' (to handle URL path/query string contexts).
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
    if (*end != '\0' && *end != '?' && *end != '&' && *end != ' ' &&
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

/* GET /log — full tree state (log_id, size, root hash, landmarks). */
static void handle_log_state(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    struct json_object *lm_arr = json_object_new_array();
    uint8_t root[MTC_HASH_SIZE];
    char root_hex[MTC_HASH_SIZE * 2 + 1];
    int i;

    mtc_tree_root_hash(&store->tree, store->tree.size, root);
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

    for (i = 0; i < store->landmark_count; i++)
        json_object_array_add(lm_arr, json_object_new_int(store->landmarks[i]));
    json_object_object_add(obj, "landmarks", lm_arr);

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

    /* Compute entry hash */
    mtc_hash_leaf(store->tree.entries[index], store->tree.entry_sizes[index],
        entry_hash);

    /* Get inclusion proof */
    if (mtc_tree_inclusion_proof(&store->tree, index, start, end,
                                  &proof, &proof_count) != 0) {
        http_send_error(io, 500, "proof generation failed");
        return;
    }

    /* Get root hash */
    mtc_tree_subtree_hash(&store->tree, start, end, root);

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
    if (index < 0 || index >= store->cert_count || !store->certificates[index]) {
        http_send_error(io, 404, "certificate not found");
        return;
    }
    http_send_json_obj(io, 200, store->certificates[index]);
}

/* ------------------------------------------------------------------ */
/* DNS TXT validation for CA certificates                              */
/* ------------------------------------------------------------------ */

/******************************************************************************
 * Function:    validate_ca_dns_txt
 *
 * Description:
 *   Queries DNS for _mtc-ca.<domain> TXT records and validates against
 *   the expected fingerprint (and optionally a nonce).
 *
 *   Two TXT record formats are supported:
 *     v=mtc-ca1; fp=sha256:<hex>                   — legacy (fp-only)
 *     v=mtc-ca2; fp=sha256:<hex>; n=<nonce>        — nonce-bound
 *
 *   Field matching is exact (split on ';', trim whitespace) to prevent
 *   crafted records from bypassing validation.
 *
 * Input Arguments:
 *   domain          - Domain name (e.g. "example.com").  The query is
 *                     for _mtc-ca.<domain>.
 *   fp_hex          - Expected SHA-256 fingerprint (64 hex chars).
 *   expected_nonce  - If non-NULL, require v=mtc-ca2 with matching nonce.
 *                     If NULL, accept legacy v=mtc-ca1 (fp-only).
 *
 * Returns:
 *   1  if a matching TXT record is found.
 *   0  if no match, DNS query failed, or parse error.
 ******************************************************************************/
/* validate_ca_dns_txt — now in mtc_ca_validate.c (mtc_validate_ca_dns_txt) */

/******************************************************************************
 * Function:    validate_ca_cert_if_present
 *
 * Description:
 *   If the request extensions contain a ca_certificate_pem, parses the
 *   X.509 certificate, verifies CA:TRUE in Basic Constraints, extracts
 *   the SAN DNS name and SPKI SHA-256 fingerprint, and validates domain
 *   ownership via DNS TXT record.
 *
 *   Root CAs (pathlen absent or > 0) skip DNS validation — only
 *   intermediate CAs (pathlen == 0) require a _mtc-ca.<domain> record.
 *
 *   If no ca_certificate_pem is present, the request is not a CA
 *   enrollment and validation is trivially passed.
 *
 * Input Arguments:
 *   extensions       - Request extensions json_object (may be NULL).
 *   enrollment_nonce - Nonce for v=mtc-ca2 validation (NULL = legacy).
 *
 * Returns:
 *   1  if not a CA request, or CA validated successfully.
 *   0  if CA validation failed (rejected).
 ******************************************************************************/
/* validate_ca_cert_if_present — now in mtc_ca_validate.c (mtc_validate_ca_cert) */

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
    char fp_hex[65];
    char nonce[MTC_NONCE_HEX_LEN + 1];
    long expires;
    struct json_object *resp;
    int ret, ca_index = -1;
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
    domain = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "public_key_fingerprint", &val)) {
        http_send_error(io, 400, "missing 'public_key_fingerprint'");
        json_object_put(req);
        return;
    }
    fp_raw = json_object_get_string(val);

    /* Strip "sha256:" prefix and validate hex format */
    if (strncmp(fp_raw, "sha256:", 7) == 0)
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

    /* Check nonce type */
    nonce_type = "ca";
    if (json_object_object_get_ex(req, "type", &val))
        nonce_type = json_object_get_string(val);
    is_leaf = (strcmp(nonce_type, "leaf") == 0);

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
        LOG_INFO("leaf nonce requested for %s (authorized by CA index %d)",
                 domain, ca_index);
    }

    /* Create nonce in DB */
    ret = mtc_db_create_nonce(store->db, domain, fp_hex, ca_index,
                              nonce, &expires);
    if (ret == -1) {
        http_send_error(io, 409,
            "pending enrollment already exists for this domain and key");
        json_object_put(req);
        return;
    }
    if (ret < 0) {
        http_send_error(io, 500, "nonce generation failed");
        json_object_put(req);
        return;
    }

    LOG_INFO("%s nonce issued for %s (fp=%.16s..., expires=%ld)",
             is_leaf ? "leaf" : "CA", domain, fp_hex, expires);

    resp = json_object_new_object();
    json_object_object_add(resp, "nonce", json_object_new_string(nonce));
    json_object_object_add(resp, "expires", json_object_new_int64(expires));
    json_object_object_add(resp, "type",
                           json_object_new_string(is_leaf ? "leaf" : "ca"));
    if (ca_index >= 0)
        json_object_object_add(resp, "ca_index",
                               json_object_new_int(ca_index));

    if (!is_leaf) {
        /* CA nonce: include DNS record to create */
        char dns_name[256], dns_value[512];
        snprintf(dns_name, sizeof(dns_name), "_mtc-ca.%s.", domain);
        snprintf(dns_value, sizeof(dns_value),
                 "v=mtc-ca2; fp=sha256:%s; n=%s; exp=%ld",
                 fp_hex, nonce, expires);
        json_object_object_add(resp, "dns_record_name",
                               json_object_new_string(dns_name));
        json_object_object_add(resp, "dns_record_value",
                               json_object_new_string(dns_value));
    }

    http_send_json_obj(io, 200, resp);
    json_object_put(resp);
    json_object_put(req);
}

/* handle_certificate_request removed — enrollment now goes through the
 * DH bootstrap port (mtc_bootstrap.c).  See README-unsure.md. */

/******************************************************************************
 * Function:    handle_certificate_renew
 *
 * Description:
 *   POST /certificate/renew — renew a certificate by proving ownership
 *   of the current private key.  No nonce or CA operator involvement.
 *
 *   The client sends:
 *     - cert_index:          current certificate's log index
 *     - old_public_key_pem:  current public key (server verifies hash
 *                            matches the logged entry)
 *     - new_public_key_pem:  new public key for the renewed cert
 *     - signature:           hex-encoded signature over the string
 *                            "renew:<cert_index>:<new_public_key_pem>"
 *                            made with the old private key
 *
 *   The server:
 *     1. Looks up cert_index in the tree
 *     2. Hashes old_public_key_pem, verifies it matches the logged hash
 *     3. Verifies the signature using the old public key
 *     4. Checks the old cert is not revoked
 *     5. Issues a new certificate with the new public key
 *
 * Input Arguments:
 *   io        - Client I/O context.
 *   store     - MTC store (tree, certs, DB).
 *   body      - HTTP request body (JSON).
 *   body_len  - Length of body in bytes.
 ******************************************************************************/
static void handle_certificate_renew(client_io *io, MtcStore *store,
                                     const char *body, int body_len)
{
    struct json_object *req, *val, *old_cert, *old_sc, *old_tbs;
    const char *old_pub_pem, *new_pub_pem, *sig_hex;
    const char *old_subject, *old_algo;
    int cert_index, validity_days;
    char computed_hash[65];
    const char *logged_hash;
    (void)body_len;

    /* Enrollment-level AbuseIPDB gate */
    if (io->ip_str[0] != '\0') {
        int score = mtc_checkendpoint(io->ip_str);
        if (score >= ABUSEIPDB_ENROLL_THRESHOLD) {
            LOG_WARN("renew rejected for %s (abuse score %d >= %d)",
                     io->ip_str, score, ABUSEIPDB_ENROLL_THRESHOLD);
            http_send_error(io, 403, "renewal denied");
            return;
        }
    }

    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        return;
    }

    /* Parse required fields */
    if (!json_object_object_get_ex(req, "cert_index", &val)) {
        http_send_error(io, 400, "missing 'cert_index'");
        json_object_put(req);
        return;
    }
    cert_index = json_object_get_int(val);

    if (!json_object_object_get_ex(req, "old_public_key_pem", &val)) {
        http_send_error(io, 400, "missing 'old_public_key_pem'");
        json_object_put(req);
        return;
    }
    old_pub_pem = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "new_public_key_pem", &val)) {
        http_send_error(io, 400, "missing 'new_public_key_pem'");
        json_object_put(req);
        return;
    }
    new_pub_pem = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "signature", &val)) {
        http_send_error(io, 400, "missing 'signature'");
        json_object_put(req);
        return;
    }
    sig_hex = json_object_get_string(val);

    validity_days = 90;
    if (json_object_object_get_ex(req, "validity_days", &val)) {
        validity_days = json_object_get_int(val);
        if (validity_days < 1 || validity_days > 3650) {
            http_send_error(io, 400,
                "validity_days must be between 1 and 3650");
            json_object_put(req);
            return;
        }
    }

    /* --- Step 1: Look up existing certificate --- */
    if (cert_index < 0 || cert_index >= store->cert_count ||
        store->certificates[cert_index] == NULL) {
        http_send_error(io, 404, "certificate not found");
        json_object_put(req);
        return;
    }

    old_cert = store->certificates[cert_index];
    if (!json_object_object_get_ex(old_cert, "standalone_certificate", &old_sc) ||
        !json_object_object_get_ex(old_sc, "tbs_entry", &old_tbs)) {
        http_send_error(io, 500, "internal error: malformed stored cert");
        json_object_put(req);
        return;
    }

    if (!json_object_object_get_ex(old_tbs, "subject_public_key_hash", &val)) {
        http_send_error(io, 500, "internal error: no key hash in stored cert");
        json_object_put(req);
        return;
    }
    logged_hash = json_object_get_string(val);

    /* Get subject and algorithm from old cert for the renewal */
    if (!json_object_object_get_ex(old_tbs, "subject", &val)) {
        http_send_error(io, 500, "internal error: no subject in stored cert");
        json_object_put(req);
        return;
    }
    old_subject = json_object_get_string(val);

    old_algo = "EC-P256";
    if (json_object_object_get_ex(old_tbs, "subject_public_key_algorithm", &val))
        old_algo = json_object_get_string(val);

    /* --- Step 2: Verify old public key hash matches the log --- */
    {
        wc_Sha256 sha;
        uint8_t h[32];
        int fi;

        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, (const uint8_t *)old_pub_pem,
                        (word32)strlen(old_pub_pem));
        wc_Sha256Final(&sha, h);
        wc_Sha256Free(&sha);
        for (fi = 0; fi < 32; fi++)
            snprintf(computed_hash + fi * 2, 3, "%02x", h[fi]);
    }

    if (strcmp(computed_hash, logged_hash) != 0) {
        LOG_WARN("renew: key hash mismatch for index %d from %s",
                 cert_index, io->ip_str);
        http_send_error(io, 403, "public key does not match logged certificate");
        json_object_put(req);
        return;
    }

    /* --- Step 3: Verify signature --- */
    {
        ecc_key key;
        uint8_t sig_bytes[256];
        int sig_len;
        char sign_msg[MAX_PATH_SZ];
        uint8_t msg_hash[32];
        int verified = 0;
        int ret;

        /* Build the message that was signed */
        snprintf(sign_msg, sizeof(sign_msg), "renew:%d:%s",
                 cert_index, new_pub_pem);

        /* Hash the message */
        {
            wc_Sha256 sha;
            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, (const uint8_t *)sign_msg,
                            (word32)strlen(sign_msg));
            wc_Sha256Final(&sha, msg_hash);
            wc_Sha256Free(&sha);
        }

        /* Decode hex signature */
        sig_len = (int)strlen(sig_hex) / 2;
        if (sig_len <= 0 || sig_len > (int)sizeof(sig_bytes)) {
            http_send_error(io, 400, "invalid signature length");
            json_object_put(req);
            return;
        }
        {
            int si;
            for (si = 0; si < sig_len; si++) {
                unsigned int b;
                if (sscanf(sig_hex + si * 2, "%02x", &b) != 1) {
                    http_send_error(io, 400, "invalid signature hex");
                    json_object_put(req);
                    return;
                }
                sig_bytes[si] = (uint8_t)b;
            }
        }

        /* Import the old public key and verify */
        wc_ecc_init(&key);

        /* Decode PEM public key — convert PEM to DER first */
        {
            uint8_t der_buf[1024];
            int der_sz = (int)sizeof(der_buf);
            word32 idx = 0;

            ret = wc_PubKeyPemToDer((const unsigned char *)old_pub_pem,
                                    (int)strlen(old_pub_pem),
                                    der_buf, der_sz);
            if (ret < 0) {
                LOG_WARN("renew: PEM to DER failed: %d", ret);
                wc_ecc_free(&key);
                http_send_error(io, 400, "invalid old public key PEM");
                json_object_put(req);
                return;
            }
            der_sz = ret;

            ret = wc_EccPublicKeyDecode(der_buf, &idx, &key, (word32)der_sz);
            if (ret != 0) {
                LOG_WARN("renew: ECC key decode failed: %d", ret);
                wc_ecc_free(&key);
                http_send_error(io, 400, "invalid ECC public key");
                json_object_put(req);
                return;
            }
        }

        ret = wc_ecc_verify_hash(sig_bytes, (word32)sig_len,
                                  msg_hash, 32, &verified, &key);
        wc_ecc_free(&key);

        if (ret != 0 || !verified) {
            LOG_WARN("renew: signature verification failed for index %d",
                     cert_index);
            http_send_error(io, 403, "signature verification failed");
            json_object_put(req);
            return;
        }
    }

    LOG_INFO("renew: signature verified for '%s' (index %d)", old_subject,
             cert_index);

    /* --- Step 4: Check not revoked --- */
    if (mtc_store_is_revoked(store, cert_index)) {
        LOG_WARN("renew: cert %d is revoked", cert_index);
        http_send_error(io, 403, "certificate is revoked");
        json_object_put(req);
        return;
    }

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
        uint8_t sig[64];
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

        /* Add to log */
        new_index = mtc_store_add_entry(store, entry_buf, entry_sz);

        /* Checkpoint */
        checkpoint = mtc_store_checkpoint(store);

        /* Proof */
        start = 0;
        end = store->tree.size;
        mtc_tree_inclusion_proof(&store->tree, new_index, start, end,
            &proof, &proof_count);
        mtc_tree_subtree_hash(&store->tree, start, end, subtree_hash);

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
            char sig_hex_out[64 * 2 + 1];
            to_hex(sig, sig_sz, sig_hex_out);
            json_object_object_add(cosig, "signature",
                json_object_new_string(sig_hex_out));
        }
        json_object_object_add(cosig, "algorithm",
            json_object_new_string("Ed25519"));
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

        /* Store certificate */
        if (new_index >= store->cert_capacity) {
            store->cert_capacity *= 2;
            store->certificates = (struct json_object **)realloc(
                store->certificates,
                (size_t)store->cert_capacity * sizeof(struct json_object *));
        }
        while (store->cert_count <= new_index)
            store->certificates[store->cert_count++] = NULL;
        store->certificates[new_index] = json_object_get(result);

        /* Persist */
        mtc_store_save(store);
        if (store->use_db && store->db) {
            const char *cert_str = json_object_to_json_string(result);
            mtc_db_save_certificate(store->db, new_index, cert_str);
        }

        LOG_INFO("renew: issued new cert for '%s' at index %d (was %d)",
                 old_subject, new_index, cert_index);

        http_send_json_obj(io, 201, result);

        json_object_put(result);
        json_object_put(tbs);
        json_object_put(checkpoint);
        free(proof);
        free(entry_buf);
    }

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

    mtc_hash_leaf(store->tree.entries[index], store->tree.entry_sizes[index], lh);
    to_hex(lh, MTC_HASH_SIZE, hash_hex);

    obj = json_object_new_object();
    json_object_object_add(obj, "index", json_object_new_int(index));

    /* Entry type: first byte is 0x00 (null) or 0x01 (tbs) */
    if (store->tree.entry_sizes[index] > 0 &&
        store->tree.entries[index][0] == 0x01) {
        /* TBS entry — the JSON is after the 0x01 prefix */
        char *json_str = (char*)malloc((size_t)store->tree.entry_sizes[index]);
        memcpy(json_str, store->tree.entries[index] + 1,
            (size_t)(store->tree.entry_sizes[index] - 1));
        json_str[store->tree.entry_sizes[index] - 1] = 0;
        {
            struct json_object *data = json_tokener_parse(json_str);
            json_object_object_add(obj, "type", json_object_new_int(1));
            json_object_object_add(obj, "data",
                data ? data : json_object_new_null());
        }
        free(json_str);
    }
    else {
        json_object_object_add(obj, "type", json_object_new_int(0));
        json_object_object_add(obj, "data", json_object_new_null());
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

    if (store->checkpoint_count > 0) {
        http_send_json_obj(io, 200,
            store->checkpoints[store->checkpoint_count - 1]);
        return;
    }

    cp = mtc_store_checkpoint(store);
    http_send_json_obj(io, 200, cp);
    json_object_put(cp);
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

    if (mtc_tree_consistency_proof(&store->tree, old_size, new_size,
                                    &proof, &proof_count) != 0) {
        http_send_error(io, 500, "consistency proof failed");
        return;
    }

    mtc_tree_root_hash(&store->tree, old_size, old_root);
    mtc_tree_root_hash(&store->tree, new_size, new_root);

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
    int i;

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

    arr = json_object_new_array();
    for (i = 0; i < store->cert_count; i++) {
        struct json_object *cert, *sc, *tbs, *val;
        if (!store->certificates[i]) continue;

        cert = store->certificates[i];
        if (json_object_object_get_ex(cert, "standalone_certificate", &sc) &&
            json_object_object_get_ex(sc, "tbs_entry", &tbs) &&
            json_object_object_get_ex(tbs, "subject", &val)) {
            const char *subj = json_object_get_string(val);
            /* Case-insensitive substring match */
            if (strcasestr(subj, qval)) {
                struct json_object *result = json_object_new_object();
                json_object_object_add(result, "index",
                    json_object_new_int(i));
                json_object_object_add(result, "subject",
                    json_object_new_string(subj));
                json_object_array_add(arr, result);
            }
        }
    }

    json_object_object_add(obj, "results", arr);
    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /ca/public-key — CA Ed25519 public key in PEM format. */
static void handle_ca_public_key(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    char pem[1024];
    int pemSz;

    json_object_object_add(obj, "ca_name",
        json_object_new_string(store->ca_name));
    json_object_object_add(obj, "cosigner_id",
        json_object_new_string(store->cosigner_id));
    json_object_object_add(obj, "algorithm",
        json_object_new_string("Ed25519"));

    pemSz = mtc_store_get_public_key_pem(store, pem, (int)sizeof(pem));
    if (pemSz > 0) {
        pem[pemSz] = 0;
        json_object_object_add(obj, "public_key_pem",
            json_object_new_string(pem));
    }

    http_send_json_obj(io, 200, obj);
    json_object_put(obj);
}

/* GET /trust-anchors — list of trust anchors (standalone + landmarks). */
static void handle_trust_anchors(client_io *io, MtcStore *store)
{
    struct json_object *obj = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct json_object *anchor;
    int i;

    anchor = json_object_new_object();
    json_object_object_add(anchor, "id",
        json_object_new_string(store->log_id));
    json_object_object_add(anchor, "type",
        json_object_new_string("standalone"));
    json_object_array_add(arr, anchor);

    for (i = 0; i < store->landmark_count; i++) {
        char id[128];
        snprintf(id, sizeof(id), "%s.%d", store->log_id, i);
        anchor = json_object_new_object();
        json_object_object_add(anchor, "id",
            json_object_new_string(id));
        json_object_object_add(anchor, "type",
            json_object_new_string("landmark"));
        json_object_object_add(anchor, "tree_size",
            json_object_new_int(store->landmarks[i]));
        json_object_array_add(arr, anchor);
    }

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
 *   POST /revoke — revoke a certificate by log index.
 *   Gated by enrollment-level AbuseIPDB check (revocation is privileged).
 *   Body: {"cert_index": N, "reason": "..."}
 *
 * Input Arguments:
 *   io        - Client I/O context.
 *   store     - MTC store.
 *   body      - HTTP request body (JSON).
 *   body_len  - Length of body in bytes.
 ******************************************************************************/
static void handle_revoke(client_io *io, MtcStore *store,
                          const char *body, int body_len)
{
    struct json_object *req, *val;
    int cert_index;
    const char *reason = NULL;

    /* Enrollment-level AbuseIPDB gate (revocation is privileged) */
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

    if (!json_object_object_get_ex(req, "cert_index", &val)) {
        http_send_error(io, 400, "missing 'cert_index'");
        json_object_put(req);
        return;
    }
    cert_index = json_object_get_int(val);

    if (json_object_object_get_ex(req, "reason", &val))
        reason = json_object_get_string(val);

    if (mtc_store_revoke(store, cert_index, reason) != 0) {
        http_send_error(io, 500, "revocation failed");
        json_object_put(req);
        return;
    }

    {
        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, "revoked", json_object_new_boolean(1));
        json_object_object_add(resp, "cert_index",
            json_object_new_int(cert_index));
        json_object_object_add(resp, "reason",
            json_object_new_string(reason ? reason : "unspecified"));
        http_send_json_obj(io, 200, resp);
        json_object_put(resp);
    }
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

    /* Dispatch */
    LOG_DEBUG("%s %s from %s", method, path, io->ip_str);

    if (strcmp(method, "GET") == 0) {
        /* Rate limit all reads */
        if (!mtc_ratelimit_check(io->ip_str, RL_READ)) {
            http_send_error(io, 429, "rate limit exceeded");
            return;
        }
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
        else if (strcmp(path, "/ech/configs") == 0) {
            handle_ech_configs(io, store);
        }
        else {
            http_send_error(io, 404, "not found");
        }
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
        else if (strcmp(path, "/certificate/renew") == 0) {
            if (!mtc_ratelimit_check(io->ip_str, RL_ENROLL)) {
                http_send_error(io, 429, "rate limit exceeded");
                return;
            }
            handle_certificate_renew(io, store, body, body_len);
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
    printf("  Data dir: %s\n\n", store->data_dir);
    fflush(stdout);

    for (;;) {
        client_io cio;
        memset(&cio, 0, sizeof(cio));
        cio.fd = -1;

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
                    continue;
                }
            }
        }

        handle_request(&cio, store);
        cio_close(&cio);
    }

    close(listen_fd);
    if (ctx) {
        g_slc_ctx = NULL;
        slc_ctx_free(ctx);
    }
    return 0;
}
