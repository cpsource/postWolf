/* examples/quic/server.c
 *
 * QUIC echo server using ngtcp2 + wolfSSL.
 * Listens on UDP, accepts one QUIC connection, echoes received stream
 * data back to the client.
 *
 * Build:
 *   gcc -o quic_server server.c \
 *       $(pkg-config --cflags --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl) \
 *       -DWOLFSSL_USE_OPTIONS_H
 *
 * Usage:
 *   ./quic_server [-p port] [-c cert] [-k key]
 */

#include "quic_common.h"

/* ------------------------------------------------------------------ */
/*  Server callbacks                                                   */
/* ------------------------------------------------------------------ */

static int srv_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    QuicPeer *s = (QuicPeer*)user_data;
    size_t end = (size_t)offset + datalen;
    (void)conn; (void)stream_user_data;

    if (datalen > 0) {
        /* Grow buffer to fit offset + datalen */
        if (s->stream_buf == NULL || end > s->stream_buf_cap) {
            size_t newcap = end > 256 ? end * 2 : 256;
            uint8_t *tmp = (uint8_t*)realloc(s->stream_buf, newcap);
            if (!tmp) return NGTCP2_ERR_CALLBACK_FAILURE;
            s->stream_buf = tmp;
            s->stream_buf_cap = newcap;
        }
        /* Write at offset to handle retransmissions/reordering */
        memcpy(s->stream_buf + (size_t)offset, data, datalen);
        if (end > s->stream_len)
            s->stream_len = end;
    }
    s->stream_id = stream_id;

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        s->stream_fin_recv = 1;
        printf("[server] received %zu bytes total on stream %ld (FIN)\n",
               s->stream_len, (long)stream_id);
    }

    return 0;
}

static int srv_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    QuicPeer *s = (QuicPeer*)user_data;
    (void)conn;
    s->handshake_done = 1;
    printf("[server] QUIC handshake complete\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Server init                                                        */
/* ------------------------------------------------------------------ */

static int server_init(QuicPeer *s, const uint8_t *initial_pkt, size_t pktlen,
                       struct sockaddr *client_addr, socklen_t client_addrlen,
                       int fd, struct sockaddr_in *bind_addr,
                       const char *cert_file, const char *key_file)
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
    wolfSSL_CTX_use_certificate_file(s->ssl_ctx, cert_file,
        WOLFSSL_FILETYPE_PEM);
    wolfSSL_CTX_use_PrivateKey_file(s->ssl_ctx, key_file,
        WOLFSSL_FILETYPE_PEM);

    s->ssl = wolfSSL_new(s->ssl_ctx);
    if (s->ssl == NULL) return -1;

    wolfSSL_set_accept_state(s->ssl);
    wolfSSL_SSLSetIORecv(s->ssl, NULL);
    wolfSSL_SSLSetIOSend(s->ssl, NULL);
    wolfSSL_set_alpn_protos(s->ssl, quic_echo_alpn, sizeof(quic_echo_alpn));

    s->conn_ref.get_conn = quic_get_conn_cb;
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
    cb.get_new_connection_id2 = quic_get_new_cid_cb;
    cb.rand = quic_rand_cb;
    cb.recv_stream_data = srv_recv_stream_data;
    cb.handshake_completed = srv_handshake_completed;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = QUIC_MAX_STREAMS;
    params.initial_max_stream_data_bidi_local = QUIC_MAX_STREAM_DATA;
    params.initial_max_stream_data_bidi_remote = QUIC_MAX_STREAM_DATA;
    params.initial_max_data = QUIC_MAX_DATA;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    scid.datalen = 8;
    quic_rand_cb(scid.data, scid.datalen, NULL);

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
    printf("Usage: %s [options]\n", prog);
    printf("  -p <port>    UDP port to listen on (default: %d)\n",
           QUIC_DEFAULT_PORT);
    printf("  -c <cert>    Server certificate PEM file (default: %s)\n",
           QUIC_DEF_CERT);
    printf("  -k <key>     Server private key PEM file (default: %s)\n",
           QUIC_DEF_KEY);
    printf("  -h           Show this help\n");
}

int main(int argc, char *argv[])
{
    QuicPeer server;
    int srv_fd, opt, rv;
    int port = QUIC_DEFAULT_PORT;
    const char *cert_file = QUIC_DEF_CERT;
    const char *key_file = QUIC_DEF_KEY;
    struct sockaddr_in bind_addr;
    uint8_t buf[QUIC_BUF_SZ];
    ssize_t nread;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    int sockopt = 1;
    int loops;

    while ((opt = getopt(argc, argv, "p:c:k:h")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'c': cert_file = optarg; break;
            case 'k': key_file = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    wolfSSL_Init();

    printf("wolfSSL QUIC Echo Server (ngtcp2)\n");
    printf("  port: %d\n  cert: %s\n  key:  %s\n\n", port, cert_file, key_file);

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

    /* Wait for Initial packet from client */
    client_addrlen = sizeof(client_addr);
    nread = recvfrom(srv_fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&client_addr, &client_addrlen);
    if (nread < 0) { perror("recvfrom"); close(srv_fd); return 1; }

    printf("[server] received Initial (%zd bytes)\n", nread);

    /* Initialize server QUIC connection */
    memset(&server, 0, sizeof(server));
    server.fd = -1;

    if (server_init(&server, buf, (size_t)nread,
                    (struct sockaddr *)&client_addr, client_addrlen,
                    srv_fd, &bind_addr, cert_file, key_file) != 0) {
        fprintf(stderr, "server_init failed\n");
        close(srv_fd);
        return 1;
    }

    /* Feed the Initial packet */
    {
        ngtcp2_path path;
        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));
        path.local.addr = (struct sockaddr *)&server.local_addr;
        path.local.addrlen = server.local_addrlen;
        path.remote.addr = (struct sockaddr *)&client_addr;
        path.remote.addrlen = client_addrlen;

        rv = ngtcp2_conn_read_pkt(server.conn, &path, &pi,
                                  buf, (size_t)nread, quic_timestamp());
        if (rv != 0) {
            fprintf(stderr, "server read_pkt: %s\n", ngtcp2_strerror(rv));
            quic_peer_free(&server);
            return 1;
        }
    }

    /* Event loop: echo received data back */
    for (loops = 0; loops < 200 && !server.closed; loops++) {
        struct pollfd pfd;

        quic_send_packets(&server);

        pfd.fd = srv_fd;
        pfd.events = POLLIN;
        poll(&pfd, 1, 50);

        if (pfd.revents & POLLIN)
            quic_recv_packets(&server);

        ngtcp2_conn_handle_expiry(server.conn, quic_timestamp());

        /* Done when we've echoed everything */
        if (server.stream_fin_sent && server.stream_sent >= server.stream_len)
            break;
    }

    printf("[server] connection complete\n");
    quic_peer_free(&server);
    wolfSSL_Cleanup();
    return 0;
}
