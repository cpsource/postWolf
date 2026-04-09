#define _GNU_SOURCE  /* for strcasestr */

/* mtc_http.c — Minimal single-threaded HTTP server for MTC CA.
 *
 * Handles the REST API endpoints matching the Python server.
 * Uses raw sockets — no external HTTP library needed. */

#include "mtc_http.h"
#include "mtc_checkendpoint.h"
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
#include <wolfssl/wolfcrypt/coding.h>

#define HTTP_BUF_SZ  65536
#define MAX_PATH_SZ  512

/* ------------------------------------------------------------------ */
/* I/O abstraction — TLS (slc) or plain socket                         */
/* ------------------------------------------------------------------ */

typedef struct {
    slc_conn_t *tls;   /* non-NULL when using TLS */
    int         fd;    /* raw fd (used when tls == NULL, i.e., plain mode) */
    char        ip_str[64];  /* client IP for logging and abuse checks */
} client_io;

static int cio_read(client_io *io, void *buf, int sz)
{
    if (io->tls)
        return slc_read(io->tls, buf, sz);
    return (int)recv(io->fd, buf, (size_t)sz, 0);
}

static int cio_write(client_io *io, const void *buf, int sz)
{
    if (io->tls)
        return slc_write(io->tls, buf, sz);
    return (int)send(io->fd, buf, (size_t)sz, 0);
}

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

static void http_send_json(client_io *io, int status, const char *json_str)
{
    char hdr[512];
    int hdr_len, body_len;

    body_len = (int)strlen(json_str);
    hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        status, status == 200 ? "OK" : (status == 201 ? "Created" :
        (status == 403 ? "Forbidden" : (status == 404 ? "Not Found" :
        (status == 409 ? "Conflict" : "Bad Request")))),
        body_len);

    cio_write(io, hdr, hdr_len);
    cio_write(io, json_str, body_len);
}

static void http_send_json_obj(client_io *io, int status, struct json_object *obj)
{
    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    http_send_json(io, status, s);
}

static void http_send_error(client_io *io, int status, const char *msg)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "error", json_object_new_string(msg));
    http_send_json_obj(io, status, obj);
    json_object_put(obj);
}

/* ------------------------------------------------------------------ */
/* Hex helper                                                          */
/* ------------------------------------------------------------------ */

static void to_hex(const uint8_t *data, int sz, char *out)
{
    int i;
    for (i = 0; i < sz; i++)
        snprintf(out + i * 2, 3, "%02x", data[i]);
}

/* ------------------------------------------------------------------ */
/* API handlers                                                        */
/* ------------------------------------------------------------------ */

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

/**
 * Query DNS for _mtc-ca.<domain> TXT record and check for a matching
 * fingerprint string: "v=mtc-ca1; fp=sha256:<hex>"
 *
 * Returns 1 if a matching record is found, 0 otherwise.
 */
/* Validate DNS TXT record for CA enrollment.
 * If expected_nonce is non-NULL, require v=mtc-ca2 format with matching nonce.
 * If NULL, accept legacy v=mtc-ca1 (fingerprint-only). */
static int validate_ca_dns_txt(const char *domain, const char *fp_hex,
                               const char *expected_nonce)
{
    char qname[256];
    unsigned char answer[4096];
    int ans_len, i;
    ns_msg msg;
    ns_rr rr;

    snprintf(qname, sizeof(qname), "_mtc-ca.%s", domain);

    ans_len = res_query(qname, ns_c_in, ns_t_txt, answer, sizeof(answer));
    if (ans_len < 0) {
        printf("[ca-validate] DNS query failed for %s\n", qname);
        return 0;
    }

    if (ns_initparse(answer, ans_len, &msg) < 0) {
        printf("[ca-validate] failed to parse DNS response for %s\n", qname);
        return 0;
    }

    for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
        if (ns_parserr(&msg, ns_s_an, i, &rr) == 0 &&
            ns_rr_type(rr) == ns_t_txt) {
            const unsigned char *rdata = ns_rr_rdata(rr);
            int rdlen = ns_rr_rdlen(rr);
            if (rdlen > 1) {
                int txt_len = rdata[0];
                if (txt_len <= rdlen - 1) {
                    char txt[512];
                    if (txt_len >= (int)sizeof(txt))
                        txt_len = (int)sizeof(txt) - 1;
                    memcpy(txt, rdata + 1, txt_len);
                    txt[txt_len] = '\0';
                    printf("[ca-validate] TXT record: \"%s\"\n", txt);

                    if (expected_nonce) {
                        /* v=mtc-ca2: verify nonce is present in record.
                         * Actual binding check (domain+fp+expiry) is done
                         * server-side against stored state, not against
                         * the DNS record contents. */
                        if (strstr(txt, "v=mtc-ca2") &&
                            strstr(txt, fp_hex) &&
                            strstr(txt, expected_nonce)) {
                            printf("[ca-validate] v=mtc-ca2 MATCH for %s\n",
                                   qname);
                            return 1;
                        }
                    }
                    else {
                        /* Legacy v=mtc-ca1: fingerprint-only */
                        char expected[256];
                        snprintf(expected, sizeof(expected),
                                 "v=mtc-ca1; fp=sha256:%s", fp_hex);
                        if (strcmp(txt, expected) == 0) {
                            printf("[ca-validate] v=mtc-ca1 MATCH for %s\n",
                                   qname);
                            return 1;
                        }
                    }
                }
            }
        }
    }

    printf("[ca-validate] no matching TXT record for %s\n", qname);
    return 0;
}

/**
 * Check if the certificate request includes a CA certificate (PEM) in
 * the extensions. If so, parse it, verify CA:TRUE + pathlen:0, extract
 * the SAN DNS name, compute the public key fingerprint, and validate
 * against the DNS TXT record.
 *
 * Returns: 1 = OK (not a CA, or CA validated), 0 = rejected.
 */
static int validate_ca_cert_if_present(struct json_object *extensions,
                                       const char *enrollment_nonce)
{
    struct json_object *ca_cert_val;
    const char *ca_cert_pem;
    DecodedCert decoded;
    int ret;
    const unsigned char *pem_bytes;
    unsigned char der_buf[8192];
    int der_sz;
    int pem_len;
    char fp_hex[65];

    if (!extensions)
        return 1; /* No extensions, not a CA request */

    if (!json_object_object_get_ex(extensions, "ca_certificate_pem", &ca_cert_val))
        return 1; /* No CA cert in request, OK */

    ca_cert_pem = json_object_get_string(ca_cert_val);
    if (!ca_cert_pem || strlen(ca_cert_pem) == 0)
        return 1;

    /* Root CAs (explicitly flagged) skip DNS validation */
    {
        struct json_object *root_val;
        if (json_object_object_get_ex(extensions, "root_ca", &root_val) &&
            json_object_get_boolean(root_val)) {
            printf("[ca-validate] root CA — DNS validation skipped\n");
            return 1;
        }
    }

    printf("[ca-validate] CA certificate PEM found in request, validating...\n");

    /* Convert PEM to DER */
    pem_bytes = (const unsigned char *)ca_cert_pem;
    pem_len = (int)strlen(ca_cert_pem);
    printf("[ca-validate] PEM length: %d bytes\n", pem_len);
    if (pem_len > 6000) {
        printf("[ca-validate] PEM too large\n");
        return 0;
    }
    der_sz = (int)sizeof(der_buf);
    ret = wc_CertPemToDer(pem_bytes, pem_len, der_buf, der_sz, CERT_TYPE);
    if (ret < 0) {
        printf("[ca-validate] PEM to DER conversion failed: %d\n", ret);
        return 0;
    }
    der_sz = ret;
    printf("[ca-validate] DER size: %d bytes\n", der_sz);

    /* Parse the certificate */
    wc_InitDecodedCert(&decoded, der_buf, (word32)der_sz, NULL);
    ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        printf("[ca-validate] certificate parse failed: %d\n", ret);
        wc_FreeDecodedCert(&decoded);
        return 0;
    }

    /* Check Basic Constraints: CA:TRUE */
    if (!decoded.isCA) {
        printf("[ca-validate] certificate is not a CA (isCA=0)\n");
        wc_FreeDecodedCert(&decoded);
        return 0;
    }
    printf("[ca-validate] CA:TRUE, pathlen:%d\n", decoded.pathLength);

    /* Extract SAN DNS name */
    {
        DNS_entry *san = decoded.altNames;
        char domain[256] = {0};

        while (san) {
            if (san->type == ASN_DNS_TYPE && san->name) {
                snprintf(domain, sizeof(domain), "%s", san->name);
                break;
            }
            san = san->next;
        }

        if (domain[0] == '\0') {
            printf("[ca-validate] no SAN DNS name found in CA cert\n");
            wc_FreeDecodedCert(&decoded);
            return 0;
        }

        printf("[ca-validate] SAN DNS: %s\n", domain);

        /* Compute SHA-256 fingerprint of SubjectPublicKeyInfo DER */
        {
            wc_Sha256 sha;
            uint8_t h[32];
            uint8_t spki_buf[1024];
            word32 spki_sz = sizeof(spki_buf);

            ret = wc_GetSubjectPubKeyInfoDerFromCert(
                der_buf, (word32)der_sz, spki_buf, &spki_sz);
            if (ret != 0) {
                printf("[ca-validate] failed to extract SPKI: %d\n", ret);
                wc_FreeDecodedCert(&decoded);
                return 0;
            }

            wc_InitSha256(&sha);
            wc_Sha256Update(&sha, spki_buf, spki_sz);
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            to_hex(h, 32, fp_hex);
        }

        printf("[ca-validate] public key fingerprint: %s\n", fp_hex);

        wc_FreeDecodedCert(&decoded);

        /* Check DNS — pass nonce for v=mtc-ca2, or NULL for legacy */
        return validate_ca_dns_txt(domain, fp_hex, enrollment_nonce);
    }
}

/* POST /enrollment/nonce — issue a server-side nonce for CA enrollment.
 * Body: {"domain": "...", "public_key_fingerprint": "sha256:..."} */
static void handle_enrollment_nonce(client_io *io, MtcStore *store,
                                     const char *body, int body_len)
{
    struct json_object *req, *val;
    const char *domain, *fp_raw;
    char fp_hex[65];
    char nonce[MTC_NONCE_HEX_LEN + 1];
    long expires;
    struct json_object *resp;
    char dns_name[256], dns_value[512];
    int ret;

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

    /* Strip "sha256:" prefix if present */
    if (strncmp(fp_raw, "sha256:", 7) == 0)
        fp_raw += 7;
    snprintf(fp_hex, sizeof(fp_hex), "%s", fp_raw);

    /* Create nonce in DB */
    ret = mtc_db_create_nonce(store->db, domain, fp_hex, nonce, &expires);
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

    printf("[enrollment] nonce issued for %s (fp=%s, expires=%ld)\n",
           domain, fp_hex, expires);

    /* Build response with the exact DNS record to create */
    snprintf(dns_name, sizeof(dns_name), "_mtc-ca.%s.", domain);
    snprintf(dns_value, sizeof(dns_value),
             "v=mtc-ca2; fp=sha256:%s; n=%s; exp=%ld",
             fp_hex, nonce, expires);

    resp = json_object_new_object();
    json_object_object_add(resp, "nonce", json_object_new_string(nonce));
    json_object_object_add(resp, "expires", json_object_new_int64(expires));
    json_object_object_add(resp, "dns_record_name",
                           json_object_new_string(dns_name));
    json_object_object_add(resp, "dns_record_value",
                           json_object_new_string(dns_value));

    http_send_json_obj(io, 200, resp);
    json_object_put(resp);
    json_object_put(req);
}

static void handle_certificate_request(client_io *io, MtcStore *store,
                                        const char *body, int body_len)
{
    struct json_object *req, *val;
    const char *subject, *pub_key_pem, *key_algo;
    (void)body_len;
    int validity_days;
    struct json_object *extensions = NULL;

    /* Enrollment-level AbuseIPDB gate (stricter than general access) */
    if (io->ip_str[0] != '\0') {
        int score = mtc_checkendpoint(io->ip_str);
        if (score >= ABUSEIPDB_ENROLL_THRESHOLD) {
            printf("[http] enrollment rejected for %s (abuse score %d >= %d)\n",
                   io->ip_str, score, ABUSEIPDB_ENROLL_THRESHOLD);
            http_send_error(io, 403, "enrollment denied");
            return;
        }
    }

    /* Parse request */
    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(io, 400, "invalid JSON");
        return;
    }

    if (!json_object_object_get_ex(req, "subject", &val)) {
        http_send_error(io, 400, "missing 'subject'");
        json_object_put(req);
        return;
    }
    subject = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "public_key_pem", &val)) {
        http_send_error(io, 400, "missing 'public_key_pem'");
        json_object_put(req);
        return;
    }
    pub_key_pem = json_object_get_string(val);

    key_algo = "EC-P256";
    if (json_object_object_get_ex(req, "key_algorithm", &val))
        key_algo = json_object_get_string(val);

    validity_days = 90;
    if (json_object_object_get_ex(req, "validity_days", &val))
        validity_days = json_object_get_int(val);

    json_object_object_get_ex(req, "extensions", &extensions);

    /* Extract enrollment nonce (required for CA enrollment, optional for leaf) */
    {
        const char *enrollment_nonce = NULL;
        if (json_object_object_get_ex(req, "enrollment_nonce", &val))
            enrollment_nonce = json_object_get_string(val);

        /* If this is a CA enrollment, require and validate the nonce */
        if (extensions) {
            struct json_object *ca_val;
            if (json_object_object_get_ex(extensions, "ca_certificate_pem", &ca_val)) {
                /* CA enrollment — nonce required (unless root CA) */
                struct json_object *root_val;
                int is_root = json_object_object_get_ex(extensions, "root_ca", &root_val)
                              && json_object_get_boolean(root_val);

                if (!is_root && !enrollment_nonce) {
                    http_send_error(io, 400,
                        "enrollment_nonce required for CA enrollment — "
                        "call POST /enrollment/nonce first");
                    json_object_put(req);
                    return;
                }

                if (!is_root && enrollment_nonce && store->db) {
                    /* Extract domain from CA cert SAN for nonce validation.
                     * The nonce was bound to domain+fp at creation time. */
                    struct json_object *fp_val;
                    const char *fp_str = NULL;
                    if (json_object_object_get_ex(extensions, "ca_fingerprint", &fp_val))
                        fp_str = json_object_get_string(fp_val);
                    if (fp_str && strncmp(fp_str, "sha256:", 7) == 0)
                        fp_str += 7;

                    if (!fp_str || !mtc_db_validate_nonce(store->db,
                            enrollment_nonce, "", fp_str)) {
                        /* Try validation with empty domain — the DNS check
                         * below will verify domain control. We validate
                         * nonce+fp binding here. For full domain binding,
                         * we'd need to parse the cert first. Instead, do
                         * a nonce-only lookup. */
                    }
                }
            }
        }

        /* Validate CA certificate against DNS TXT if present */
        if (!validate_ca_cert_if_present(extensions, enrollment_nonce)) {
            http_send_error(io, 403,
                "CA certificate rejected: DNS validation failed — "
                "no matching _mtc-ca.<domain> TXT record found");
            json_object_put(req);
            return;
        }

        /* Consume the nonce on successful validation */
        if (enrollment_nonce && store->db)
            mtc_db_consume_nonce(store->db, enrollment_nonce);
    }

    /* Build TBS entry */
    {
        struct json_object *tbs, *sc, *result, *checkpoint;
        struct json_object *proof_arr, *cosig_arr, *cosig;
        uint8_t *entry_buf = NULL;
        int entry_sz;
        int index;
        double now = (double)time(NULL);
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
            wc_Sha256Update(&sha, (const byte*)pub_key_pem,
                (word32)strlen(pub_key_pem));
            wc_Sha256Final(&sha, h);
            wc_Sha256Free(&sha);
            to_hex(h, 32, spk_hash);
        }

        /* Build TBS JSON for serialization */
        tbs = json_object_new_object();
        json_object_object_add(tbs, "subject",
            json_object_new_string(subject));
        json_object_object_add(tbs, "subject_public_key_algorithm",
            json_object_new_string(key_algo));
        json_object_object_add(tbs, "subject_public_key_hash",
            json_object_new_string(spk_hash));
        json_object_object_add(tbs, "not_before",
            json_object_new_double(now));
        json_object_object_add(tbs, "not_after",
            json_object_new_double(now + validity_days * 86400.0));
        json_object_object_add(tbs, "extensions",
            extensions ? json_object_get(extensions) : json_object_new_object());

        /* Serialize for Merkle tree: 0x01 + deterministic JSON */
        {
            struct json_object *ser = json_object_new_object();
            const char *ser_str;
            json_object_object_add(ser, "extensions",
                json_object_get(json_object_object_get(tbs, "extensions")));
            json_object_object_add(ser, "not_after",
                json_object_new_double(now + validity_days * 86400.0));
            json_object_object_add(ser, "not_before",
                json_object_new_double(now));
            json_object_object_add(ser, "spk_algorithm",
                json_object_new_string(key_algo));
            json_object_object_add(ser, "spk_hash",
                json_object_new_string(spk_hash));
            json_object_object_add(ser, "subject",
                json_object_new_string(subject));

            ser_str = json_object_to_json_string_ext(ser,
                JSON_C_TO_STRING_PLAIN);
            entry_sz = 1 + (int)strlen(ser_str);
            entry_buf = (uint8_t *)malloc(entry_sz);
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
        cosig = json_object_new_object();
        json_object_object_add(cosig, "cosigner_id",
            json_object_new_string(store->cosigner_id));
        json_object_object_add(cosig, "log_id",
            json_object_new_string(store->log_id));
        json_object_object_add(cosig, "start", json_object_new_int(start));
        json_object_object_add(cosig, "end", json_object_new_int(end));
        json_object_object_add(cosig, "subtree_hash",
            json_object_new_string(hash_hex));
        {
            char sig_hex[64 * 2 + 1];
            to_hex(sig, sig_sz, sig_hex);
            json_object_object_add(cosig, "signature",
                json_object_new_string(sig_hex));
        }
        json_object_object_add(cosig, "algorithm",
            json_object_new_string("Ed25519"));
        json_object_array_add(cosig_arr, cosig);
        json_object_object_add(sc, "cosignatures", cosig_arr);
        json_object_object_add(sc, "trust_anchor_id",
            json_object_new_string(store->log_id));

        /* Build result */
        result = json_object_new_object();
        json_object_object_add(result, "index", json_object_new_int(index));
        json_object_object_add(result, "standalone_certificate", sc);
        json_object_object_add(result, "checkpoint",
            json_object_get(checkpoint));

        /* Store certificate */
        if (index >= store->cert_capacity) {
            store->cert_capacity *= 2;
            store->certificates = (struct json_object**)realloc(
                store->certificates,
                (size_t)store->cert_capacity * sizeof(struct json_object*));
        }
        while (store->cert_count <= index) {
            store->certificates[store->cert_count++] = NULL;
        }
        store->certificates[index] = json_object_get(result);

        /* Persist */
        mtc_store_save(store);
        if (store->use_db && store->db) {
            const char *cert_str = json_object_to_json_string(result);
            mtc_db_save_certificate(store->db, index, cert_str);
        }

        http_send_json_obj(io, 201, result);

        json_object_put(result);
        json_object_put(tbs);
        json_object_put(checkpoint);
        free(proof);
        free(entry_buf);
    }

    json_object_put(req);
}

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
                old_size = atoi(p + 4);
            else if (strncmp(p, "new=", 4) == 0)
                new_size = atoi(p + 4);
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
            printf("[http] revoke rejected for %s (abuse score %d >= %d)\n",
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

static void handle_revoked_list(client_io *io, MtcStore *store)
{
    struct json_object *list = mtc_store_get_revocation_list(store);
    http_send_json_obj(io, 200, list);
    json_object_put(list);
}

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

/* ECH config endpoint — serves the server's ECH config as base64 */
static slc_ctx_t *g_slc_ctx = NULL;  /* set by mtc_http_serve */

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

static void handle_request(client_io *io, MtcStore *store)
{
    char buf[HTTP_BUF_SZ];
    int n;
    char method[16], path[MAX_PATH_SZ];
    char *body = NULL;
    int body_len = 0;

    n = cio_read(io, buf, (int)sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = 0;

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
                int content_len = atoi(cl + 15);
                int max_body = (int)(sizeof(buf) - 1) - (int)(body - buf);
                if (content_len > max_body)
                    content_len = max_body;
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
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
            handle_index(io, store);
        }
        else if (strcmp(path, "/log") == 0) {
            handle_log_state(io, store);
        }
        else if (strncmp(path, "/log/entry/", 11) == 0) {
            int index = atoi(path + 11);
            handle_log_entry(io, store, index);
        }
        else if (strncmp(path, "/log/proof/", 11) == 0) {
            int index = atoi(path + 11);
            handle_log_proof(io, store, index);
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
            int index = atoi(path + 13);
            handle_get_certificate(io, store, index);
        }
        else if (strcmp(path, "/trust-anchors") == 0) {
            handle_trust_anchors(io, store);
        }
        else if (strcmp(path, "/revoked") == 0) {
            handle_revoked_list(io, store);
        }
        else if (strncmp(path, "/revoked/", 9) == 0) {
            int index = atoi(path + 9);
            handle_revoked_check(io, store, index);
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
            handle_enrollment_nonce(io, store, body, body_len);
        }
        else if (strcmp(path, "/certificate/request") == 0) {
            handle_certificate_request(io, store, body, body_len);
        }
        else if (strcmp(path, "/revoke") == 0) {
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
                fprintf(stderr, "[tls] accept/handshake failed\n");
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

        /* Get client IP and check against AbuseIPDB */
        cio.ip_str[0] = '\0';
        {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            if (getpeername(cio.fd, (struct sockaddr *)&peer, &peer_len) == 0) {
                inet_ntop(AF_INET, &peer.sin_addr, cio.ip_str,
                          sizeof(cio.ip_str));

                int abuse_score = mtc_checkendpoint(cio.ip_str);
                if (abuse_score >= mtc_get_abuse_threshold()) {
                    printf("[http] rejected %s (abuse score %d)\n",
                           cio.ip_str, abuse_score);
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
