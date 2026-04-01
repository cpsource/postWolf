/* examples/quic-mtc/server.c
 *
 * QUIC echo server with MTC (Merkle Tree Certificate) support.
 *
 * When an MTC CA is available (--ca-url), the server:
 *   1. Enrolls with the MTC CA to get a certificate
 *   2. Uses the enrolled key for TLS in the QUIC handshake
 *   3. Sends the MTC certificate index to the client for verification
 *
 * Falls back to traditional X.509 certs when no MTC CA is reachable.
 *
 * Build:
 *   gcc -o quic_mtc_server server.c \
 *       $(pkg-config --cflags --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl) \
 *       -DWOLFSSL_USE_OPTIONS_H -ljson-c -lcurl
 *
 * Usage:
 *   ./quic_mtc_server [-p port] [-c cert] [-k key] [--ca-url url] [--subject name]
 */

#include "quic_mtc_common.h"

/* ------------------------------------------------------------------ */
/*  Server callbacks                                                   */
/* ------------------------------------------------------------------ */

static int srv_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    QmtcPeer *s = (QmtcPeer*)user_data;
    size_t end = (size_t)offset + datalen;
    (void)conn; (void)stream_user_data;

    if (datalen > 0) {
        if (s->stream_buf == NULL || end > s->stream_buf_cap) {
            size_t newcap = end > 256 ? end * 2 : 256;
            uint8_t *tmp = (uint8_t*)realloc(s->stream_buf, newcap);
            if (!tmp) return NGTCP2_ERR_CALLBACK_FAILURE;
            s->stream_buf = tmp;
            s->stream_buf_cap = newcap;
        }
        memcpy(s->stream_buf + (size_t)offset, data, datalen);
        if (end > s->stream_len)
            s->stream_len = end;
    }
    s->stream_id = stream_id;

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        s->stream_fin_recv = 1;
        printf("[server] received %zu bytes on stream %ld (FIN)\n",
               s->stream_len, (long)stream_id);
    }
    return 0;
}

static int srv_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    QmtcPeer *s = (QmtcPeer*)user_data;
    (void)conn;
    s->handshake_done = 1;
    printf("[server] QUIC handshake complete\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Server init                                                        */
/* ------------------------------------------------------------------ */

static int server_init(QmtcPeer *s, const uint8_t *initial_pkt, size_t pktlen,
                       struct sockaddr *client_addr, socklen_t client_addrlen,
                       int fd, struct sockaddr_in *bind_addr,
                       const char *cert_file, const char *key_file,
                       const char *mtc_store)
{
    ngtcp2_pkt_hd hd;
    ngtcp2_callbacks cb;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid scid;
    ngtcp2_path path;
    int rv;

    memset(&cb, 0, sizeof(cb));

    s->name = "server";
    s->stream_id = -1;
    s->fd = fd;
    memcpy(&s->local_addr, bind_addr, sizeof(*bind_addr));
    s->local_addrlen = sizeof(struct sockaddr_in);
    memcpy(&s->remote_addr, client_addr, client_addrlen);
    s->remote_addrlen = client_addrlen;

    rv = ngtcp2_accept(&hd, initial_pkt, pktlen);
    if (rv < 0) {
        fprintf(stderr, "ngtcp2_accept: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    /* wolfSSL TLS context */
    s->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (s->ssl_ctx == NULL) return -1;

    ngtcp2_crypto_wolfssl_configure_server_context(s->ssl_ctx);

    if (mtc_store != NULL) {
        /* Load MTC certificate directly from ~/.TPM store */
        printf("[server] loading MTC cert from: %s\n", mtc_store);
        if (wolfSSL_CTX_use_MTC_certificate(s->ssl_ctx, mtc_store)
                != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_CTX_use_MTC_certificate failed\n");
            return -1;
        }
    }
    else {
        wolfSSL_CTX_use_certificate_file(s->ssl_ctx, cert_file,
            WOLFSSL_FILETYPE_PEM);
        wolfSSL_CTX_use_PrivateKey_file(s->ssl_ctx, key_file,
            WOLFSSL_FILETYPE_PEM);
    }

    s->ssl = wolfSSL_new(s->ssl_ctx);
    if (s->ssl == NULL) return -1;

    wolfSSL_set_accept_state(s->ssl);
    wolfSSL_SSLSetIORecv(s->ssl, NULL);
    wolfSSL_SSLSetIOSend(s->ssl, NULL);
    wolfSSL_set_alpn_protos(s->ssl, qmtc_alpn, sizeof(qmtc_alpn));

    s->conn_ref.get_conn = qmtc_get_conn_cb;
    s->conn_ref.user_data = s;
    wolfSSL_set_app_data(s->ssl, &s->conn_ref);

    /* ngtcp2 callbacks */
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.get_new_connection_id2 = qmtc_get_new_cid_cb;
    cb.rand = qmtc_rand_cb;
    cb.recv_stream_data = srv_recv_stream_data;
    cb.handshake_completed = srv_handshake_completed;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = qmtc_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = QMTC_MAX_STREAMS;
    params.initial_max_stream_data_bidi_local = QMTC_MAX_STREAM_DATA;
    params.initial_max_stream_data_bidi_remote = QMTC_MAX_STREAM_DATA;
    params.initial_max_data = QMTC_MAX_DATA;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    scid.datalen = 8;
    qmtc_rand_cb(scid.data, scid.datalen, NULL);

    path.local.addr = (struct sockaddr *)&s->local_addr;
    path.local.addrlen = s->local_addrlen;
    path.remote.addr = client_addr;
    path.remote.addrlen = client_addrlen;

    rv = ngtcp2_conn_server_new(&s->conn, &hd.scid, &scid, &path,
                                hd.version, &cb, &settings, &params,
                                NULL, s);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(s->conn, s->ssl);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("QUIC options:\n");
    printf("  -p <port>        UDP port (default: %d)\n", QMTC_DEFAULT_PORT);
    printf("  -c <cert>        Server cert PEM (fallback: %s)\n", QMTC_DEF_CERT);
    printf("  -k <key>         Server key PEM  (fallback: %s)\n", QMTC_DEF_KEY);
    printf("\nMTC options:\n");
    printf("  --ca-url <url>   MTC CA/Log server URL (default: %s)\n",
           QMTC_DEFAULT_CA_URL);
    printf("  --subject <name> MTC certificate subject\n");
    printf("  --store <path>   MTC cert store path (default: ~/.TPM)\n");
    printf("  --mtc-store <dir> Load MTC cert+key from ~/.TPM/<subject> dir\n");
    printf("                   (uses wolfSSL_CTX_use_MTC_certificate)\n");
    printf("  --no-mtc         Disable MTC, use X.509 only\n");
    printf("  -h               Show this help\n");
}

int main(int argc, char *argv[])
{
    QmtcPeer server;
    int srv_fd, rv;
    int port = QMTC_DEFAULT_PORT;
    const char *cert_file = QMTC_DEF_CERT;
    const char *key_file = QMTC_DEF_KEY;
    const char *ca_url = QMTC_DEFAULT_CA_URL;
    const char *subject = "urn:quic-mtc:server";
    const char *store_path = NULL;
    const char *mtc_store_dir = NULL;
    int no_mtc = 0;
    int use_mtc = 0;
    struct sockaddr_in bind_addr;
    uint8_t buf[QMTC_BUF_SZ];
    ssize_t nread;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    int sockopt = 1;
    int loops, i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
            cert_file = argv[++i];
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
            key_file = argv[++i];
        else if (strcmp(argv[i], "--ca-url") == 0 && i + 1 < argc)
            ca_url = argv[++i];
        else if (strcmp(argv[i], "--subject") == 0 && i + 1 < argc)
            subject = argv[++i];
        else if (strcmp(argv[i], "--store") == 0 && i + 1 < argc)
            store_path = argv[++i];
        else if (strcmp(argv[i], "--mtc-store") == 0 && i + 1 < argc)
            mtc_store_dir = argv[++i];
        else if (strcmp(argv[i], "--no-mtc") == 0)
            no_mtc = 1;
        else if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 0;
        }
    }

    wolfSSL_Init();

    printf("========================================\n");
    printf("  QUIC + MTC Echo Server\n");
    printf("========================================\n\n");

    memset(&server, 0, sizeof(server));
    server.fd = -1;

    /* --- MTC enrollment phase --- */
    if (!no_mtc) {
        if (qmtc_enroll(&server, ca_url, subject, store_path) == 0) {
            use_mtc = 1;
            /* Use MTC-enrolled key for TLS.
             * The key was stored by MTC_Enroll at:
             *   {store}/urn_quic-mtc_server/private_key.pem
             *   {store}/urn_quic-mtc_server/certificate.json
             *
             * For TLS, we still need a traditional X.509 cert for the
             * handshake. The MTC proof is verified out-of-band.
             * In a full implementation, the MTC proof would be carried
             * in the Certificate message via the id-alg-mtcProof OID.
             */
            printf("[server] MTC enrolled — using MTC trust alongside X.509\n");
            printf("[server] MTC cert index: %d (client can verify this)\n",
                   server.mtc_cert->index);
        }
    }

    if (!use_mtc) {
        printf("[server] using X.509 certs: %s / %s\n", cert_file, key_file);
    }

    /* --- QUIC transport setup --- */
    srv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons((unsigned short)port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }

    printf("[server] listening on UDP 0.0.0.0:%d\n", port);

    /* Wait for Initial */
    client_addrlen = sizeof(client_addr);
    nread = recvfrom(srv_fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&client_addr, &client_addrlen);
    if (nread < 0) { perror("recvfrom"); close(srv_fd); return 1; }

    printf("[server] received Initial (%zd bytes)\n", nread);

    if (server_init(&server, buf, (size_t)nread,
                    (struct sockaddr *)&client_addr, client_addrlen,
                    srv_fd, &bind_addr, cert_file, key_file,
                    mtc_store_dir) != 0) {
        fprintf(stderr, "server_init failed\n");
        close(srv_fd);
        return 1;
    }

    /* Feed Initial packet */
    {
        ngtcp2_path path;
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));
        path.local.addr = (struct sockaddr *)&server.local_addr;
        path.local.addrlen = server.local_addrlen;
        path.remote.addr = (struct sockaddr *)&client_addr;
        path.remote.addrlen = client_addrlen;

        rv = ngtcp2_conn_read_pkt(server.conn, &path, &pi,
                                  buf, (size_t)nread, qmtc_timestamp());
        if (rv != 0) {
            fprintf(stderr, "server read_pkt: %s\n", ngtcp2_strerror(rv));
            qmtc_peer_free(&server);
            return 1;
        }
    }

    /* Event loop */
    for (loops = 0; loops < 200; loops++) {
        struct pollfd pfd;

        qmtc_send_packets(&server);

        pfd.fd = srv_fd;
        pfd.events = POLLIN;
        poll(&pfd, 1, 50);

        if (pfd.revents & POLLIN)
            qmtc_recv_packets(&server);

        ngtcp2_conn_handle_expiry(server.conn, qmtc_timestamp());

        if (server.stream_fin_sent && server.stream_sent >= server.stream_len)
            break;
    }

    printf("[server] connection complete\n");

    if (use_mtc) {
        printf("\n--- MTC Summary ---\n");
        printf("  Subject:      %s\n", subject);
        printf("  Cert index:   %d\n", server.mtc_cert->index);
        printf("  Trust anchor: %s\n",
               server.mtc_cert->trust_anchor_id ?
               server.mtc_cert->trust_anchor_id : "n/a");
        printf("  Has landmark: %s\n",
               server.mtc_cert->has_landmark ? "yes" : "no");
    }

    qmtc_peer_free(&server);
    wolfSSL_Cleanup();
    return 0;
}
