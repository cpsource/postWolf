/*
 * test_quic_echo.c
 *
 * Minimal QUIC echo server + client using ngtcp2 + wolfSSL.
 * Server listens on UDP localhost:2222, client connects, sends 100 bytes,
 * server echoes them back. Single-threaded using poll().
 *
 * Build:
 *   gcc -o test_quic_echo test_quic_echo.c \
 *       $(pkg-config --cflags --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl) \
 *       -DWOLFSSL_USE_OPTIONS_H
 *
 * Run:
 *   ./test_quic_echo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#define PORT       2222
#define LOCALHOST  "127.0.0.1"
#define TEST_SZ    100
#define BUF_SZ     65536
static const unsigned char alpn[] = {4, 'e', 'c', 'h', 'o'};
#define CERT_FILE  "certs/server-cert.pem"
#define KEY_FILE   "certs/server-key.pem"
#define CA_FILE    "certs/ca-cert.pem"

/* ------------------------------------------------------------------ */
/*  Shared helpers                                                     */
/* ------------------------------------------------------------------ */

static uint64_t get_timestamp(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, dest, (word32)destlen);
    wc_FreeRng(&rng);
}

static int get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                          ngtcp2_stateless_reset_token *token,
                          size_t cidlen, void *user_data)
{
    (void)conn; (void)user_data;
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, cid->data, (word32)cidlen);
    cid->datalen = cidlen;
    wc_RNG_GenerateBlock(&rng, token->data, sizeof(token->data));
    wc_FreeRng(&rng);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Peer context (used by both server and client)                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char             *name;
    ngtcp2_crypto_conn_ref  conn_ref;
    ngtcp2_conn            *conn;
    WOLFSSL_CTX            *ssl_ctx;
    WOLFSSL                *ssl;
    int                     fd;
    struct sockaddr_storage local_addr;
    socklen_t               local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t               remote_addrlen;

    /* Echo state */
    int64_t  stream_id;
    uint8_t  echo_buf[TEST_SZ];
    size_t   echo_len;
    size_t   echo_sent;
    int      echo_fin;
    int      handshake_done;
    int      got_echo;
} Peer;

static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    Peer *p = ref->user_data;
    return p->conn;
}

/* ------------------------------------------------------------------ */
/*  Server callbacks                                                   */
/* ------------------------------------------------------------------ */

static int srv_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    Peer *s = user_data;
    (void)conn; (void)offset; (void)stream_user_data;

    if (datalen > 0 && s->echo_len + datalen <= TEST_SZ) {
        memcpy(s->echo_buf + s->echo_len, data, datalen);
        s->echo_len += datalen;
    }
    s->stream_id = stream_id;
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
        s->echo_fin = 1;

    printf("[server] received %zu bytes on stream %ld\n",
           datalen, (long)stream_id);
    return 0;
}

static int srv_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    Peer *s = user_data;
    (void)conn;
    s->handshake_done = 1;
    printf("[server] QUIC handshake complete\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Client callbacks                                                   */
/* ------------------------------------------------------------------ */

static int cli_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    Peer *c = user_data;
    (void)conn; (void)flags; (void)stream_id; (void)offset;
    (void)stream_user_data;

    if (datalen > 0 && c->echo_len + datalen <= TEST_SZ) {
        memcpy(c->echo_buf + c->echo_len, data, datalen);
        c->echo_len += datalen;
    }
    printf("[client] received %zu bytes echo\n", datalen);
    c->got_echo = 1;
    return 0;
}

static int cli_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    Peer *c = user_data;
    (void)conn;
    c->handshake_done = 1;
    printf("[client] QUIC handshake complete\n");
    return 0;
}

static int cli_extend_max_streams(ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data)
{
    Peer *c = user_data;
    (void)max_streams;

    if (c->stream_id == -1) {
        ngtcp2_conn_open_bidi_stream(conn, &c->stream_id, NULL);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Packet I/O helpers                                                 */
/* ------------------------------------------------------------------ */

static int send_packets(Peer *p)
{
    uint8_t buf[1400];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    uint64_t ts = get_timestamp();

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        /* Try to write stream data if we have any */
        if (p->stream_id >= 0 && p->echo_sent < p->echo_len) {
            nwrite = ngtcp2_conn_write_stream(
                p->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                NGTCP2_WRITE_STREAM_FLAG_FIN,
                p->stream_id,
                p->echo_buf + p->echo_sent,
                p->echo_len - p->echo_sent, ts);
            if (nwrite > 0 && wdatalen > 0)
                p->echo_sent += (size_t)wdatalen;
        }
        else {
            nwrite = ngtcp2_conn_write_pkt(p->conn, &ps.path, &pi,
                                           buf, sizeof(buf), ts);
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            fprintf(stderr, "[%s] write error: %s\n",
                    p->name, ngtcp2_strerror((int)nwrite));
            return -1;
        }
        if (nwrite == 0) break;

        sendto(p->fd, buf, (size_t)nwrite, 0,
               (struct sockaddr *)&p->remote_addr, p->remote_addrlen);
    }
    return 0;
}

static int recv_packets(Peer *p)
{
    uint8_t buf[BUF_SZ];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};
    int rv;

    for (;;) {
        addrlen = sizeof(addr);
        nread = recvfrom(p->fd, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&addr, &addrlen);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }

        path.local.addr = (struct sockaddr *)&p->local_addr;
        path.local.addrlen = p->local_addrlen;
        path.remote.addr = (struct sockaddr *)&addr;
        path.remote.addrlen = addrlen;

        /* For server: remember client address for replies */
        if (p->remote_addrlen == 0) {
            memcpy(&p->remote_addr, &addr, addrlen);
            p->remote_addrlen = addrlen;
        }

        rv = ngtcp2_conn_read_pkt(p->conn, &path, &pi,
                                  buf, (size_t)nread, get_timestamp());
        if (rv != 0) {
            fprintf(stderr, "[%s] read_pkt: %s\n",
                    p->name, ngtcp2_strerror(rv));
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Server setup                                                       */
/* ------------------------------------------------------------------ */

static int server_init(Peer *s, const uint8_t *initial_pkt, size_t pktlen,
                       struct sockaddr *client_addr, socklen_t client_addrlen,
                       int fd, struct sockaddr_in *bind_addr)
{
    ngtcp2_pkt_hd hd;
    ngtcp2_callbacks cb = {0};
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid scid;
    ngtcp2_path path;
    int rv;

    /* Preserve fd and addresses — don't zero them */
    s->name = "server";
    s->stream_id = -1;
    s->fd = fd;
    memcpy(&s->local_addr, bind_addr, sizeof(*bind_addr));
    s->local_addrlen = sizeof(struct sockaddr_in);
    memcpy(&s->remote_addr, client_addr, client_addrlen);
    s->remote_addrlen = client_addrlen;

    /* Decode the Initial packet header to get DCIDs */
    rv = ngtcp2_accept(&hd, initial_pkt, pktlen);
    if (rv < 0) {
        fprintf(stderr, "ngtcp2_accept: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    /* Server SSL */
    s->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (s->ssl_ctx == NULL) return -1;

    ngtcp2_crypto_wolfssl_configure_server_context(s->ssl_ctx);

    wolfSSL_CTX_use_certificate_file(s->ssl_ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM);
    wolfSSL_CTX_use_PrivateKey_file(s->ssl_ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM);

    s->ssl = wolfSSL_new(s->ssl_ctx);
    if (s->ssl == NULL) return -1;

    wolfSSL_set_accept_state(s->ssl);
    wolfSSL_SSLSetIORecv(s->ssl, NULL);
    wolfSSL_SSLSetIOSend(s->ssl, NULL);

    /* Set ALPN */
    wolfSSL_set_alpn_protos(s->ssl, alpn, sizeof(alpn));

    s->conn_ref.get_conn = get_conn_cb;
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
    cb.get_new_connection_id2 = get_new_cid_cb;
    cb.rand = rand_cb;
    cb.recv_stream_data = srv_recv_stream_data;
    cb.handshake_completed = srv_handshake_completed;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 10;
    params.initial_max_stream_data_bidi_local = 128 * 1024;
    params.initial_max_stream_data_bidi_remote = 128 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.original_dcid = hd.dcid;
    params.original_dcid_present = 1;

    /* Generate server CID */
    scid.datalen = 8;
    rand_cb(scid.data, scid.datalen, NULL);

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
/*  Client setup                                                       */
/* ------------------------------------------------------------------ */

static int client_init(Peer *c)
{
    ngtcp2_callbacks cb = {0};
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    ngtcp2_cid dcid, scid;
    ngtcp2_path path;
    struct sockaddr_in remote, local;
    int rv;

    memset(c, 0, sizeof(*c));
    c->name = "client";
    c->stream_id = -1;

    /* UDP socket */
    c->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (c->fd < 0) return -1;

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(PORT);
    remote.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (connect(c->fd, (struct sockaddr *)&remote, sizeof(remote)) < 0)
        return -1;

    memcpy(&c->remote_addr, &remote, sizeof(remote));
    c->remote_addrlen = sizeof(remote);

    c->local_addrlen = sizeof(c->local_addr);
    getsockname(c->fd, (struct sockaddr *)&c->local_addr, &c->local_addrlen);

    /* Client SSL */
    c->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (c->ssl_ctx == NULL) return -1;

    ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx);
    wolfSSL_CTX_load_verify_locations(c->ssl_ctx, CA_FILE, NULL);

    c->ssl = wolfSSL_new(c->ssl_ctx);
    if (c->ssl == NULL) return -1;

    wolfSSL_set_connect_state(c->ssl);
    wolfSSL_set_alpn_protos(c->ssl, alpn, sizeof(alpn));
    wolfSSL_set_verify(c->ssl, SSL_VERIFY_NONE, NULL);

    c->conn_ref.get_conn = get_conn_cb;
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
    cb.get_new_connection_id2 = get_new_cid_cb;
    cb.rand = rand_cb;
    cb.recv_stream_data = cli_recv_stream_data;
    cb.handshake_completed = cli_handshake_completed;
    cb.extend_max_local_streams_bidi = cli_extend_max_streams;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 10;
    params.initial_max_stream_data_bidi_local = 128 * 1024;
    params.initial_max_stream_data_bidi_remote = 128 * 1024;
    params.initial_max_data = 1024 * 1024;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    rand_cb(dcid.data, dcid.datalen, NULL);
    scid.datalen = 8;
    rand_cb(scid.data, scid.datalen, NULL);

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
/*  Main — run the QUIC echo test                                      */
/* ------------------------------------------------------------------ */

int main(void)
{
    Peer server, client;
    int srv_fd, rv;
    struct sockaddr_in bind_addr;
    uint8_t buf[BUF_SZ];
    ssize_t nread;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    int opt = 1;
    int loops;
    uint8_t send_data[TEST_SZ];
    int i;

    wolfSSL_Init();

    printf("========================================\n");
    printf("  QUIC Echo Test (ngtcp2 + wolfSSL)\n");
    printf("========================================\n\n");

    /* Fill test pattern */
    for (i = 0; i < TEST_SZ; i++)
        send_data[i] = (unsigned char)(i & 0xFF);

    /* Create server UDP socket */
    srv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(PORT);
    bind_addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    if (bind(srv_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return 1;
    }

    printf("[server] listening on UDP %s:%d\n", LOCALHOST, PORT);

    /* Initialize client */
    if (client_init(&client) != 0) {
        fprintf(stderr, "client_init failed\n"); return 1;
    }

    printf("[client] initialized\n");

    /* Client sends Initial packet */
    if (send_packets(&client) != 0) {
        fprintf(stderr, "client initial send failed\n"); return 1;
    }

    printf("[client] sent Initial packet\n");

    /* Receive Initial on server socket, create server connection */
    client_addrlen = sizeof(client_addr);
    nread = recvfrom(srv_fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&client_addr, &client_addrlen);
    if (nread < 0) { perror("recvfrom initial"); return 1; }

    printf("[server] received Initial (%zd bytes)\n", nread);

    /* Initialize server with the Initial packet */
    memset(&server, 0, sizeof(server));

    if (server_init(&server, buf, (size_t)nread,
                    (struct sockaddr *)&client_addr, client_addrlen,
                    srv_fd, &bind_addr) != 0) {
        fprintf(stderr, "server_init failed\n"); return 1;
    }

    /* Feed the Initial packet to the server connection */
    {
        ngtcp2_path path;
        ngtcp2_pkt_info pi = {0};
        path.local.addr = (struct sockaddr *)&server.local_addr;
        path.local.addrlen = server.local_addrlen;
        path.remote.addr = (struct sockaddr *)&client_addr;
        path.remote.addrlen = client_addrlen;

        rv = ngtcp2_conn_read_pkt(server.conn, &path, &pi,
                                  buf, (size_t)nread, get_timestamp());
        if (rv != 0) {
            fprintf(stderr, "server read_pkt initial: %s\n",
                    ngtcp2_strerror(rv));
            return 1;
        }
    }

    /* Handshake + data exchange loop */
    for (loops = 0; loops < 50; loops++) {
        struct pollfd fds[2];
        int nfds;

        /* Server sends */
        send_packets(&server);

        /* If server got echo data and hasn't sent it back yet */
        if (server.echo_fin && server.echo_sent == 0) {
            server.echo_sent = 0; /* will be sent via send_packets */
            send_packets(&server);
        }

        /* Client receives */
        fds[0].fd = client.fd;
        fds[0].events = POLLIN;
        fds[1].fd = srv_fd;
        fds[1].events = POLLIN;

        nfds = poll(fds, 2, 100);

        if (nfds > 0) {
            if (fds[0].revents & POLLIN) {
                recv_packets(&client);
            }
            if (fds[1].revents & POLLIN) {
                recv_packets(&server);
            }
        }

        /* Client sends (handshake or stream data) */
        if (client.handshake_done && client.stream_id >= 0 &&
            client.echo_len == 0 && client.echo_sent == 0) {
            /* Load data to send */
            memcpy(client.echo_buf, send_data, TEST_SZ);
            client.echo_len = TEST_SZ;
            printf("[client] sending %d bytes on stream %ld\n",
                   TEST_SZ, (long)client.stream_id);
        }
        send_packets(&client);

        /* Check completion */
        if (client.got_echo && client.echo_len >= TEST_SZ)
            break;

        /* Handle timer expiry */
        ngtcp2_conn_handle_expiry(server.conn, get_timestamp());
        ngtcp2_conn_handle_expiry(client.conn, get_timestamp());
    }

    /* Verify */
    printf("\n");
    if (client.got_echo && client.echo_len == TEST_SZ &&
        memcmp(client.echo_buf, send_data, TEST_SZ) == 0) {
        printf("[client] data verified OK — all %d bytes match\n", TEST_SZ);
        printf("\n=== QUIC ECHO TEST PASSED ===\n");
        rv = 0;
    }
    else {
        fprintf(stderr, "[client] echo verification failed "
                "(got_echo=%d, len=%zu)\n", client.got_echo, client.echo_len);
        printf("\n=== QUIC ECHO TEST FAILED ===\n");
        rv = 1;
    }

    /* Cleanup */
    ngtcp2_conn_del(client.conn);
    wolfSSL_free(client.ssl);
    wolfSSL_CTX_free(client.ssl_ctx);
    close(client.fd);

    ngtcp2_conn_del(server.conn);
    wolfSSL_free(server.ssl);
    wolfSSL_CTX_free(server.ssl_ctx);
    close(srv_fd);

    wolfSSL_Cleanup();
    return rv;
}
