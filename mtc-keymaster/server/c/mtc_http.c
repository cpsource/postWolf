/* mtc_http.c — Minimal single-threaded HTTP server for MTC CA.
 *
 * Handles the REST API endpoints matching the Python server.
 * Uses raw sockets — no external HTTP library needed. */

#include "mtc_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#define HTTP_BUF_SZ  65536
#define MAX_PATH_SZ  512

/* ------------------------------------------------------------------ */
/* HTTP response helpers                                               */
/* ------------------------------------------------------------------ */

static void http_send_json(int fd, int status, const char *json_str)
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
        (status == 404 ? "Not Found" : "Bad Request")),
        body_len);

    send(fd, hdr, (size_t)hdr_len, 0);
    send(fd, json_str, (size_t)body_len, 0);
}

static void http_send_json_obj(int fd, int status, struct json_object *obj)
{
    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    http_send_json(fd, status, s);
}

static void http_send_error(int fd, int status, const char *msg)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "error", json_object_new_string(msg));
    http_send_json_obj(fd, status, obj);
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

static void handle_index(int fd, MtcStore *store)
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
    http_send_json_obj(fd, 200, obj);
    json_object_put(obj);
}

static void handle_log_state(int fd, MtcStore *store)
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

    http_send_json_obj(fd, 200, obj);
    json_object_put(obj);
}

static void handle_log_proof(int fd, MtcStore *store, int index)
{
    struct json_object *obj;
    uint8_t *proof = NULL;
    int proof_count = 0;
    uint8_t entry_hash[MTC_HASH_SIZE], root[MTC_HASH_SIZE];
    char hash_hex[MTC_HASH_SIZE * 2 + 1];
    struct json_object *proof_arr;
    int i, start = 0, end = store->tree.size;

    if (index < 0 || index >= store->tree.size) {
        http_send_error(fd, 404, "entry not found");
        return;
    }

    /* Compute entry hash */
    mtc_hash_leaf(store->tree.entries[index], store->tree.entry_sizes[index],
        entry_hash);

    /* Get inclusion proof */
    if (mtc_tree_inclusion_proof(&store->tree, index, start, end,
                                  &proof, &proof_count) != 0) {
        http_send_error(fd, 500, "proof generation failed");
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

    http_send_json_obj(fd, 200, obj);
    json_object_put(obj);
    free(proof);
}

static void handle_get_certificate(int fd, MtcStore *store, int index)
{
    if (index < 0 || index >= store->cert_count || !store->certificates[index]) {
        http_send_error(fd, 404, "certificate not found");
        return;
    }
    http_send_json_obj(fd, 200, store->certificates[index]);
}

static void handle_certificate_request(int fd, MtcStore *store,
                                        const char *body, int body_len)
{
    struct json_object *req, *val;
    const char *subject, *pub_key_pem, *key_algo;
    int validity_days;
    struct json_object *extensions = NULL;

    /* Parse request */
    req = json_tokener_parse(body);
    if (!req) {
        http_send_error(fd, 400, "invalid JSON");
        return;
    }

    if (!json_object_object_get_ex(req, "subject", &val)) {
        http_send_error(fd, 400, "missing 'subject'");
        json_object_put(req);
        return;
    }
    subject = json_object_get_string(val);

    if (!json_object_object_get_ex(req, "public_key_pem", &val)) {
        http_send_error(fd, 400, "missing 'public_key_pem'");
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

    /* Build TBS entry */
    {
        struct json_object *tbs, *sc, *result, *checkpoint;
        struct json_object *proof_arr, *cosig_arr, *cosig;
        uint8_t entry_buf[4096];
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
            entry_buf[0] = 0x01;
            memcpy(entry_buf + 1, ser_str, strlen(ser_str));
            entry_sz = 1 + (int)strlen(ser_str);
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

        http_send_json_obj(fd, 201, result);

        json_object_put(result);
        json_object_put(tbs);
        json_object_put(checkpoint);
        free(proof);
    }

    json_object_put(req);
}

static void handle_ca_public_key(int fd, MtcStore *store)
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

    http_send_json_obj(fd, 200, obj);
    json_object_put(obj);
}

static void handle_trust_anchors(int fd, MtcStore *store)
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
    http_send_json_obj(fd, 200, obj);
    json_object_put(obj);
}

/* ------------------------------------------------------------------ */
/* Request parsing and dispatch                                        */
/* ------------------------------------------------------------------ */

static void handle_request(int fd, MtcStore *store)
{
    char buf[HTTP_BUF_SZ];
    int n;
    char method[16], path[MAX_PATH_SZ];
    char *body = NULL;
    int body_len = 0;

    n = (int)recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return;
    buf[n] = 0;

    /* Parse method and path */
    if (sscanf(buf, "%15s %511s", method, path) != 2) {
        http_send_error(fd, 400, "bad request");
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

    /* Dispatch */
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
            handle_index(fd, store);
        }
        else if (strcmp(path, "/log") == 0) {
            handle_log_state(fd, store);
        }
        else if (strncmp(path, "/log/proof/", 11) == 0) {
            int index = atoi(path + 11);
            handle_log_proof(fd, store, index);
        }
        else if (strncmp(path, "/certificate/", 13) == 0) {
            int index = atoi(path + 13);
            handle_get_certificate(fd, store, index);
        }
        else if (strcmp(path, "/trust-anchors") == 0) {
            handle_trust_anchors(fd, store);
        }
        else if (strcmp(path, "/ca/public-key") == 0) {
            handle_ca_public_key(fd, store);
        }
        else {
            http_send_error(fd, 404, "not found");
        }
    }
    else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/certificate/request") == 0) {
            handle_certificate_request(fd, store, body, body_len);
        }
        else {
            http_send_error(fd, 404, "not found");
        }
    }
    else {
        http_send_error(fd, 405, "method not allowed");
    }
}

/* ------------------------------------------------------------------ */
/* Server main loop                                                    */
/* ------------------------------------------------------------------ */

int mtc_http_serve(const char *host, int port, MtcStore *store)
{
    int srv_fd, cli_fd;
    struct sockaddr_in addr;
    int opt = 1;

    srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return -1; }

    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (host && strcmp(host, "0.0.0.0") != 0)
        inet_pton(AF_INET, host, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return -1;
    }

    if (listen(srv_fd, 5) < 0) {
        perror("listen"); close(srv_fd); return -1;
    }

    printf("MTC CA/Log Server (C) listening on %s:%d\n",
           host ? host : "0.0.0.0", port);
    printf("  CA Name:  %s\n", store->ca_name);
    printf("  Log ID:   %s\n", store->log_id);
    printf("  Log size: %d entries\n", store->tree.size);
    printf("  Data dir: %s\n\n", store->data_dir);

    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);

        cli_fd = accept(srv_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            perror("accept");
            continue;
        }

        handle_request(cli_fd, store);
        close(cli_fd);
    }

    close(srv_fd);
    return 0;
}
