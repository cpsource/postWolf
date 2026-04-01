/* examples/quic/quic_common.h
 *
 * Common definitions for wolfSSL QUIC examples (ngtcp2 transport).
 */

#ifndef WOLFSSL_QUIC_COMMON_H
#define WOLFSSL_QUIC_COMMON_H

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
#include <wolfssl/wolfcrypt/random.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#define QUIC_BUF_SZ         65536
#define QUIC_MAX_PKT_SZ     1400
#define QUIC_DEFAULT_PORT    4433
#define QUIC_MAX_STREAMS     100
#define QUIC_MAX_STREAM_DATA (256 * 1024)
#define QUIC_MAX_DATA        (1024 * 1024)

/* Default ALPN for the echo protocol */
static const unsigned char quic_echo_alpn[] = {4, 'e', 'c', 'h', 'o'};

/* Default certificate paths (relative to wolfSSL root) */
#define QUIC_DEF_CERT "certs/server-cert.pem"
#define QUIC_DEF_KEY  "certs/server-key.pem"
#define QUIC_DEF_CA   "certs/ca-cert.pem"

/* ------------------------------------------------------------------ */
/*  Peer context                                                       */
/* ------------------------------------------------------------------ */

typedef struct QuicPeer {
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

    /* Stream state */
    int64_t  stream_id;
    uint8_t *stream_buf;
    size_t   stream_buf_cap;
    size_t   stream_len;
    size_t   stream_sent;
    int      stream_fin_recv;
    int      stream_fin_sent;
    int      handshake_done;
    int      data_received;
    int      closed;
} QuicPeer;

/* ------------------------------------------------------------------ */
/*  Shared helpers                                                     */
/* ------------------------------------------------------------------ */

static uint64_t quic_timestamp(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen,
                          const ngtcp2_rand_ctx *rand_ctx)
{
    WC_RNG rng;
    (void)rand_ctx;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, dest, (word32)destlen);
    wc_FreeRng(&rng);
}

static int quic_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                ngtcp2_stateless_reset_token *token,
                                size_t cidlen, void *user_data)
{
    WC_RNG rng;
    (void)conn; (void)user_data;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, cid->data, (word32)cidlen);
    cid->datalen = cidlen;
    wc_RNG_GenerateBlock(&rng, token->data, sizeof(token->data));
    wc_FreeRng(&rng);
    return 0;
}

static ngtcp2_conn *quic_get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    QuicPeer *p = (QuicPeer*)ref->user_data;
    return p->conn;
}

/* ------------------------------------------------------------------ */
/*  Packet I/O                                                         */
/* ------------------------------------------------------------------ */

static int quic_send_packets(QuicPeer *p)
{
    uint8_t buf[QUIC_MAX_PKT_SZ];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    uint64_t ts = quic_timestamp();

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        if (p->stream_id >= 0 && p->stream_sent < p->stream_len &&
            !p->stream_fin_sent) {
            {
            ngtcp2_vec datav;
            datav.base = p->stream_buf + p->stream_sent;
            datav.len = p->stream_len - p->stream_sent;
            wdatalen = 0;
            nwrite = ngtcp2_conn_writev_stream(
                p->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen,
                NGTCP2_WRITE_STREAM_FLAG_FIN, p->stream_id,
                &datav, 1, ts);
            if (wdatalen > 0)
                p->stream_sent += (size_t)wdatalen;
            /* FIN accepted once data + FIN are written */
            if (p->stream_sent >= p->stream_len)
                p->stream_fin_sent = 1;
            }
        }
        else {
            nwrite = ngtcp2_conn_write_pkt(p->conn, &ps.path, &pi,
                                           buf, sizeof(buf), ts);
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                /* Data was accepted but packet not full yet, continue */
                continue;
            }
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

static int quic_recv_packets(QuicPeer *p)
{
    uint8_t buf[QUIC_BUF_SZ];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    int rv;

    memset(&pi, 0, sizeof(pi));

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

        if (p->remote_addrlen == 0) {
            memcpy(&p->remote_addr, &addr, addrlen);
            p->remote_addrlen = addrlen;
        }

        rv = ngtcp2_conn_read_pkt(p->conn, &path, &pi,
                                  buf, (size_t)nread, quic_timestamp());
        if (rv != 0) {
            fprintf(stderr, "[%s] read_pkt: %s\n",
                    p->name, ngtcp2_strerror(rv));
            return -1;
        }
    }
    return 0;
}

static void quic_peer_free(QuicPeer *p)
{
    if (p->conn) ngtcp2_conn_del(p->conn);
    if (p->ssl) wolfSSL_free(p->ssl);
    if (p->ssl_ctx) wolfSSL_CTX_free(p->ssl_ctx);
    if (p->fd >= 0) close(p->fd);
    if (p->stream_buf) free(p->stream_buf);
}

#endif /* WOLFSSL_QUIC_COMMON_H */
