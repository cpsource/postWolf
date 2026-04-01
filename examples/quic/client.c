/* examples/quic/client.c
 *
 * QUIC echo client using ngtcp2 + wolfSSL.
 * Connects to a QUIC server, sends a message, receives the echo.
 *
 * Build:
 *   gcc -o quic_client client.c \
 *       $(pkg-config --cflags --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl) \
 *       -DWOLFSSL_USE_OPTIONS_H
 *
 * Usage:
 *   ./quic_client [-h host] [-p port] [-A ca_cert] [-m message]
 */

#include "quic_common.h"

/* ------------------------------------------------------------------ */
/*  Client callbacks                                                   */
/* ------------------------------------------------------------------ */

static int cli_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    QuicPeer *c = (QuicPeer*)user_data;
    size_t end = (size_t)offset + datalen;
    (void)conn; (void)stream_id; (void)stream_user_data;

    if (datalen > 0) {
        /* Grow buffer to fit offset + datalen */
        if (c->stream_buf == NULL || end > c->stream_buf_cap) {
            size_t newcap = end > 256 ? end * 2 : 256;
            uint8_t *tmp = (uint8_t*)realloc(c->stream_buf, newcap);
            if (!tmp) return NGTCP2_ERR_CALLBACK_FAILURE;
            c->stream_buf = tmp;
            c->stream_buf_cap = newcap;
        }
        /* Write at the correct offset to handle retransmissions */
        memcpy(c->stream_buf + (size_t)offset, data, datalen);
        if (end > c->stream_len)
            c->stream_len = end;
    }

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
        c->data_received = 1;

    return 0;
}

static int cli_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    QuicPeer *c = (QuicPeer*)user_data;
    (void)conn;
    c->handshake_done = 1;
    printf("[client] QUIC handshake complete\n");
    return 0;
}

static int cli_extend_max_streams(ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data)
{
    QuicPeer *c = (QuicPeer*)user_data;
    (void)max_streams;

    if (c->stream_id == -1)
        ngtcp2_conn_open_bidi_stream(conn, &c->stream_id, NULL);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Client init                                                        */
/* ------------------------------------------------------------------ */

static int client_init(QuicPeer *c, const char *host, int port,
                       const char *ca_file)
{
    ngtcp2_callbacks cb;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid, scid;
    ngtcp2_path path;
    struct sockaddr_in remote;
    int rv;

    memset(c, 0, sizeof(*c));
    memset(&cb, 0, sizeof(cb));
    c->name = "client";
    c->stream_id = -1;
    c->fd = -1;

    /* UDP socket */
    c->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (c->fd < 0) return -1;

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &remote.sin_addr) != 1) {
        fprintf(stderr, "Invalid host: %s\n", host);
        return -1;
    }

    if (connect(c->fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        perror("connect");
        return -1;
    }

    memcpy(&c->remote_addr, &remote, sizeof(remote));
    c->remote_addrlen = sizeof(remote);
    c->local_addrlen = sizeof(c->local_addr);
    getsockname(c->fd, (struct sockaddr *)&c->local_addr, &c->local_addrlen);

    /* wolfSSL TLS context */
    c->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (c->ssl_ctx == NULL) return -1;

    ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx);
    wolfSSL_CTX_load_verify_locations(c->ssl_ctx, ca_file, NULL);

    c->ssl = wolfSSL_new(c->ssl_ctx);
    if (c->ssl == NULL) return -1;

    wolfSSL_set_connect_state(c->ssl);
    wolfSSL_set_alpn_protos(c->ssl, quic_echo_alpn, sizeof(quic_echo_alpn));
    wolfSSL_set_verify(c->ssl, SSL_VERIFY_NONE, NULL);
    wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME,
        host, (unsigned short)strlen(host));

    c->conn_ref.get_conn = quic_get_conn_cb;
    c->conn_ref.user_data = c;
    wolfSSL_set_app_data(c->ssl, &c->conn_ref);

    /* ngtcp2 callbacks */
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.get_new_connection_id2 = quic_get_new_cid_cb;
    cb.rand = quic_rand_cb;
    cb.recv_stream_data = cli_recv_stream_data;
    cb.handshake_completed = cli_handshake_completed;
    cb.extend_max_local_streams_bidi = cli_extend_max_streams;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = QUIC_MAX_STREAMS;
    params.initial_max_stream_data_bidi_local = QUIC_MAX_STREAM_DATA;
    params.initial_max_stream_data_bidi_remote = QUIC_MAX_STREAM_DATA;
    params.initial_max_data = QUIC_MAX_DATA;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    quic_rand_cb(dcid.data, dcid.datalen, NULL);
    scid.datalen = 8;
    quic_rand_cb(scid.data, scid.datalen, NULL);

    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.local.addrlen = c->local_addrlen;
    path.remote.addr = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = c->remote_addrlen;

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1, &cb, &settings,
                                &params, NULL, c);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("  -h <host>    Server host (default: 127.0.0.1)\n");
    printf("  -p <port>    Server port (default: %d)\n", QUIC_DEFAULT_PORT);
    printf("  -A <ca>      CA certificate PEM file (default: %s)\n",
           QUIC_DEF_CA);
    printf("  -m <msg>     Message to send (default: \"Hello QUIC!\")\n");
    printf("  -?           Show this help\n");
}

int main(int argc, char *argv[])
{
    QuicPeer client;
    int opt, rv = 0;
    const char *host = "127.0.0.1";
    int port = QUIC_DEFAULT_PORT;
    const char *ca_file = QUIC_DEF_CA;
    const char *message = "Hello QUIC!";
    int loops;
    int msg_loaded = 0;

    while ((opt = getopt(argc, argv, "h:p:A:m:?")) != -1) {
        switch (opt) {
            case 'h': host = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'A': ca_file = optarg; break;
            case 'm': message = optarg; break;
            case '?': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    wolfSSL_Init();

    printf("wolfSSL QUIC Echo Client (ngtcp2)\n");
    printf("  host: %s:%d\n  ca:   %s\n  msg:  \"%s\"\n\n",
           host, port, ca_file, message);

    if (client_init(&client, host, port, ca_file) != 0) {
        fprintf(stderr, "client_init failed\n");
        wolfSSL_Cleanup();
        return 1;
    }

    /* Send Initial packet */
    quic_send_packets(&client);
    printf("[client] sent Initial packet\n");

    /* Event loop: handshake, send message, receive echo */
    for (loops = 0; loops < 200; loops++) {
        struct pollfd pfd;

        pfd.fd = client.fd;
        pfd.events = POLLIN;
        poll(&pfd, 1, 50);

        if (pfd.revents & POLLIN)
            quic_recv_packets(&client);

        /* Load message once stream is open */
        if (client.handshake_done && client.stream_id >= 0 && !msg_loaded) {
            size_t msglen = strlen(message);
            client.stream_buf = (uint8_t*)malloc(msglen);
            memcpy(client.stream_buf, message, msglen);
            client.stream_buf_cap = msglen;
            client.stream_len = msglen;
            client.stream_sent = 0;
            client.stream_fin_recv = 1; /* Signal FIN on send */
            msg_loaded = 1;
            printf("[client] sending %zu bytes on stream %ld\n",
                   msglen, (long)client.stream_id);
        }

        quic_send_packets(&client);
        ngtcp2_conn_handle_expiry(client.conn, quic_timestamp());

        if (client.data_received)
            break;
    }

    /* Show result */
    printf("\n");
    if (client.data_received && client.stream_len > 0) {
        printf("[client] received echo: \"%.*s\"\n",
               (int)client.stream_len, client.stream_buf);
        if (client.stream_len == strlen(message) &&
            memcmp(client.stream_buf, message, client.stream_len) == 0) {
            printf("\n=== QUIC echo verified OK ===\n");
        }
        else {
            printf("\n=== QUIC echo mismatch ===\n");
            rv = 1;
        }
    }
    else {
        fprintf(stderr, "[client] no echo received\n");
        rv = 1;
    }

    quic_peer_free(&client);
    wolfSSL_Cleanup();
    return rv;
}
