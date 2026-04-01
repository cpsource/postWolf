/* examples/quic-mtc/quic_mtc_common.h
 *
 * Common definitions for QUIC + MTC examples.
 * Uses ngtcp2 for QUIC transport and the MTC C API for Merkle Tree
 * Certificate enrollment/verification.
 */

#ifndef WOLFSSL_QUIC_MTC_COMMON_H
#define WOLFSSL_QUIC_MTC_COMMON_H

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
#include <wolfssl/wolfcrypt/mtc_api.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#define QMTC_BUF_SZ         65536
#define QMTC_MAX_PKT_SZ     1400
#define QMTC_DEFAULT_PORT    4500
#define QMTC_MAX_STREAMS     100
#define QMTC_MAX_STREAM_DATA (256 * 1024)
#define QMTC_MAX_DATA        (1024 * 1024)
#define QMTC_DEFAULT_CA_URL  "http://localhost:8443"

/* Default ALPN */
static const unsigned char qmtc_alpn[] = {8, 'q', 'm', 't', 'c', 'e', 'c', 'h', 'o'};

/* Fallback traditional certs (when MTC CA is unavailable) */
#define QMTC_DEF_CERT "certs/server-cert.pem"
#define QMTC_DEF_KEY  "certs/server-key.pem"
#define QMTC_DEF_CA   "certs/ca-cert.pem"

/* ------------------------------------------------------------------ */
/*  Peer context                                                       */
/* ------------------------------------------------------------------ */

typedef struct QmtcPeer {
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

    /* MTC state */
    mtc_conn_t  *mtc;
    mtc_cert_t  *mtc_cert;
    const char  *mtc_subject;
} QmtcPeer;

/* ------------------------------------------------------------------ */
/*  Shared helpers                                                     */
/* ------------------------------------------------------------------ */

static uint64_t qmtc_timestamp(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void qmtc_rand_cb(uint8_t *dest, size_t destlen,
                          const ngtcp2_rand_ctx *rand_ctx)
{
    WC_RNG rng;
    (void)rand_ctx;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, dest, (word32)destlen);
    wc_FreeRng(&rng);
}

static int qmtc_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
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

static ngtcp2_conn *qmtc_get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    QmtcPeer *p = (QmtcPeer*)ref->user_data;
    return p->conn;
}

/* ------------------------------------------------------------------ */
/*  Packet I/O                                                         */
/* ------------------------------------------------------------------ */

static int qmtc_send_packets(QmtcPeer *p)
{
    uint8_t buf[QMTC_MAX_PKT_SZ];
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    uint64_t ts = qmtc_timestamp();

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        if (p->stream_id >= 0 && p->stream_sent < p->stream_len &&
            !p->stream_fin_sent) {
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
            if (p->stream_sent >= p->stream_len)
                p->stream_fin_sent = 1;
        }
        else {
            nwrite = ngtcp2_conn_write_pkt(p->conn, &ps.path, &pi,
                                           buf, sizeof(buf), ts);
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE)
                continue;
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

static int qmtc_recv_packets(QmtcPeer *p)
{
    uint8_t buf[QMTC_BUF_SZ];
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
                                  buf, (size_t)nread, qmtc_timestamp());
        if (rv != 0) {
            fprintf(stderr, "[%s] read_pkt: %s\n",
                    p->name, ngtcp2_strerror(rv));
            return -1;
        }
    }
    return 0;
}

static void qmtc_peer_free(QmtcPeer *p)
{
    if (p->conn) ngtcp2_conn_del(p->conn);
    if (p->ssl) wolfSSL_free(p->ssl);
    if (p->ssl_ctx) wolfSSL_CTX_free(p->ssl_ctx);
    if (p->fd >= 0) close(p->fd);
    if (p->stream_buf) free(p->stream_buf);
    if (p->mtc_cert) MTC_Free_Cert(p->mtc_cert);
    if (p->mtc) MTC_Disconnect(p->mtc);
}

/* ------------------------------------------------------------------ */
/*  MTC helpers                                                        */
/* ------------------------------------------------------------------ */

/* Attempt to connect to MTC CA and enroll.
 * Returns 0 on success, -1 if CA unavailable. */
static int qmtc_enroll(QmtcPeer *p, const char *ca_url,
                        const char *subject, const char *store_path)
{
    printf("[%s] connecting to MTC CA at %s ...\n", p->name, ca_url);
    p->mtc = MTC_Connect(ca_url);
    if (p->mtc == NULL) {
        printf("[%s] MTC CA unavailable (%s), using fallback X.509 certs\n",
               p->name, MTC_Last_Error() ? MTC_Last_Error() : "connection failed");
        return -1;
    }

    if (store_path)
        MTC_Conn_SetStorePath(p->mtc, store_path);

    printf("[%s] MTC CA: %s  log: %s  tree_size: %d\n", p->name,
           MTC_Conn_CA_Name(p->mtc), MTC_Conn_Log_ID(p->mtc),
           MTC_Conn_Tree_Size(p->mtc));

    printf("[%s] enrolling subject: %s\n", p->name, subject);
    p->mtc_cert = MTC_Enroll(p->mtc, subject, "EC-P256", 90, NULL);
    if (p->mtc_cert == NULL) {
        printf("[%s] MTC enrollment failed: %s\n", p->name,
               MTC_Last_Error() ? MTC_Last_Error() : "unknown");
        return -1;
    }

    printf("[%s] enrolled: index=%d  trust_anchor=%s\n", p->name,
           p->mtc_cert->index,
           p->mtc_cert->trust_anchor_id ? p->mtc_cert->trust_anchor_id : "n/a");
    p->mtc_subject = subject;
    return 0;
}

/* Verify an MTC certificate by index.
 * Returns 0 if valid, -1 otherwise. */
static int qmtc_verify(QmtcPeer *p, int index)
{
    mtc_verify_t *result;

    if (p->mtc == NULL) {
        printf("[%s] no MTC connection, skipping verification\n", p->name);
        return -1;
    }

    printf("[%s] verifying MTC certificate index=%d ...\n", p->name, index);
    result = MTC_Verify(p->mtc, index);
    if (result == NULL) {
        printf("[%s] MTC verify failed: %s\n", p->name,
               MTC_Last_Error() ? MTC_Last_Error() : "unknown");
        return -1;
    }

    printf("[%s] MTC verify results:\n", p->name);
    printf("[%s]   valid:            %d\n", p->name, result->valid);
    printf("[%s]   inclusion_proof:  %d\n", p->name, result->inclusion_proof);
    printf("[%s]   cosignature:      %d\n", p->name, result->cosignature_valid);
    printf("[%s]   not_expired:      %d\n", p->name, result->not_expired);
    printf("[%s]   landmark_valid:   %d\n", p->name, result->landmark_valid);
    printf("[%s]   subject:          %s\n", p->name,
           result->subject ? result->subject : "(null)");

    if (result->error)
        printf("[%s]   error:            %s\n", p->name, result->error);

    {
        int ok = result->valid;
        MTC_Free_Verify(result);
        return ok ? 0 : -1;
    }
}

#endif /* WOLFSSL_QUIC_MTC_COMMON_H */
