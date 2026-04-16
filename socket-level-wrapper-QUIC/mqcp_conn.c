/* mqcp_conn.c — Connection lifecycle, event processing, read/write */

#include "mqcp_conn.h"
#include "mqcp_timer.h"
#include "mqcp_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* --- Logging --- */

static int s_verbose = 0;
void mqcp_set_verbose(int level) { s_verbose = level; }
int  mqcp_get_verbose(void) { return s_verbose; }

/* --- Context --- */

/* Load certificate.json to get cert_index (reuse MQC pattern) */
static int load_cert_index(const char *tpm_path) {
    char path[512];
    snprintf(path, sizeof(path), "%s/certificate.json", tpm_path);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    /* Simple parse: find "index": <number> */
    const char *p = strstr(buf, "\"index\"");
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    return atoi(p + 1);
}

static int load_privkey(const char *tpm_path, uint8_t **der_out, int *der_sz) {
    char path[512];
    snprintf(path, sizeof(path), "%s/private_key.pem", tpm_path);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *pem = (char *)malloc((size_t)sz + 1);
    if (!pem) { fclose(f); return -1; }
    if (fread(pem, 1, (size_t)sz, f) != (size_t)sz) {
        free(pem); fclose(f); return -1;
    }
    fclose(f);
    pem[sz] = '\0';

    /* PEM to DER conversion */
    uint8_t *der = (uint8_t *)malloc((size_t)sz);
    if (!der) { free(pem); return -1; }

    int der_len = wc_KeyPemToDer((const unsigned char *)pem, (int)sz,
                                 der, (int)sz, NULL);
    free(pem);
    if (der_len <= 0) { free(der); return -1; }

    *der_out = der;
    *der_sz = der_len;
    return 0;
}

mqcp_ctx_t *mqcp_ctx_new(const mqcp_cfg_t *cfg) {
    mqcp_ctx_t *ctx = (mqcp_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->role = cfg->role;
    ctx->tpm_path = strdup(cfg->tpm_path);
    ctx->mtc_server = cfg->mtc_server ? strdup(cfg->mtc_server) : NULL;
    ctx->encrypt_identity = cfg->encrypt_identity;
    ctx->idle_timeout_us = cfg->idle_timeout_ms > 0
        ? cfg->idle_timeout_ms * 1000
        : MQCP_DEFAULT_IDLE_TIMEOUT_US;
    ctx->max_recv_window = cfg->max_recv_window > 0
        ? cfg->max_recv_window
        : MQCP_DEFAULT_MAX_DATA;

    if (cfg->ca_pubkey && cfg->ca_pubkey_sz > 0) {
        ctx->ca_pubkey = (uint8_t *)malloc((size_t)cfg->ca_pubkey_sz);
        if (ctx->ca_pubkey) {
            memcpy(ctx->ca_pubkey, cfg->ca_pubkey, (size_t)cfg->ca_pubkey_sz);
            ctx->ca_pubkey_sz = cfg->ca_pubkey_sz;
        }
    }

    ctx->our_cert_index = load_cert_index(cfg->tpm_path);
    if (ctx->our_cert_index < 0) {
        fprintf(stderr, "[MQCP] Failed to load cert_index from %s\n",
                cfg->tpm_path);
        mqcp_ctx_free(ctx);
        return NULL;
    }

    if (load_privkey(cfg->tpm_path, &ctx->privkey_der,
                     &ctx->privkey_der_sz) != 0) {
        fprintf(stderr, "[MQCP] Failed to load private key from %s\n",
                cfg->tpm_path);
        mqcp_ctx_free(ctx);
        return NULL;
    }

    MQCP_LOG("Context created: cert_index=%d", ctx->our_cert_index);
    return ctx;
}

void mqcp_ctx_free(mqcp_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->tpm_path);
    free(ctx->mtc_server);
    free(ctx->ca_pubkey);
    if (ctx->privkey_der) {
        mqcp_secure_zero(ctx->privkey_der, (size_t)ctx->privkey_der_sz);
        free(ctx->privkey_der);
    }
    free(ctx);
}

/* --- Connection creation --- */

static mqcp_conn_t *conn_new(mqcp_ctx_t *ctx) {
    mqcp_conn_t *conn = (mqcp_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->ctx = ctx;
    conn->role = ctx->role;
    conn->state = MQCP_STATE_IDLE;
    conn->fd = -1;
    conn->peer_cert_index = -1;
    conn->idle_timeout_us = ctx->idle_timeout_us;
    conn->max_data_local = (uint64_t)ctx->max_recv_window;
    conn->max_data_remote = MQCP_DEFAULT_MAX_DATA; /* assume default until peer says otherwise */

    conn->hs = mqcp_handshake_new();
    if (!conn->hs) { free(conn); return NULL; }
    mqcp_rtt_init(&conn->rtt);
    mqcp_rtb_init(&conn->rtb);
    mqcp_ack_tracker_init(&conn->ack_tracker);
    mqcp_cc_init(&conn->cc);

    if (mqcp_send_stream_init(&conn->send_stream, 256 * 1024) != 0) {
        free(conn);
        return NULL;
    }
    if (mqcp_recv_stream_init(&conn->recv_stream, ctx->max_recv_window) != 0) {
        mqcp_send_stream_free(&conn->send_stream);
        free(conn);
        return NULL;
    }

    return conn;
}

mqcp_conn_t *mqcp_connect(mqcp_ctx_t *ctx, const char *host, int port) {
    mqcp_conn_t *conn = conn_new(ctx);
    if (!conn) return NULL;

    /* Resolve address */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct udp_addr remote;
    udp_addr_init(&remote);
    if (udp_addr_resolve(&remote, host, port_str, AF_UNSPEC) != 0) {
        fprintf(stderr, "[MQCP] Failed to resolve %s:%d\n", host, port);
        mqcp_conn_free(conn);
        return NULL;
    }

    conn->family = udp_addr_family(&remote);
    conn->remote_addr = remote;

    /* Create UDP socket */
    conn->fd = udp_socket_create(conn->family);
    if (conn->fd < 0) {
        mqcp_conn_free(conn);
        return NULL;
    }
    conn->owns_fd = 1;

    udp_socket_enable_ecn(conn->fd, conn->family);

    /* Start handshake */
    conn->last_activity_us = mqcp_now_us();
    if (mqcp_handshake_client_start(conn->hs, ctx, conn) != 0) {
        mqcp_conn_free(conn);
        return NULL;
    }

    conn->state = MQCP_STATE_HANDSHAKE_SENT;
    return conn;
}

int mqcp_listen(mqcp_ctx_t *ctx, const char *host, int port) {
    (void)ctx;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct udp_addr bind_addr;
    udp_addr_init(&bind_addr);

    const char *bind_host = host ? host : "::";
    int family = AF_INET6;
    if (udp_addr_resolve(&bind_addr, bind_host, port_str, family) != 0) {
        bind_host = "0.0.0.0";
        family = AF_INET;
        if (udp_addr_resolve(&bind_addr, bind_host, port_str, family) != 0) {
            return -1;
        }
    }

    int fd = udp_server_socket(&bind_addr,
                               UDP_FLAG_ECN | UDP_FLAG_PKTINFO);
    if (fd < 0) return -1;

    MQCP_LOG("Listening on %s:%d (fd=%d)", bind_host, port, fd);
    return fd;
}

mqcp_conn_t *mqcp_accept(mqcp_ctx_t *ctx, int listen_fd) {
    /* Read a datagram */
    uint8_t buf[MQCP_MAX_DATAGRAM + 100];
    struct udp_msg_info mi;
    int family = AF_INET6; /* TODO: detect from listen_fd */

    ssize_t n = udp_recv(listen_fd, buf, sizeof(buf), family, &mi);
    if (n <= 0) return NULL;

    /* Must be a long header (handshake) */
    if (n < MQCP_LONG_HEADER_LEN || !mqcp_is_long_header(buf[0])) {
        return NULL;
    }

    /* Create new connection for this client */
    mqcp_conn_t *conn = conn_new(ctx);
    if (!conn) return NULL;

    conn->fd = listen_fd;
    conn->owns_fd = 0;
    conn->family = udp_addr_family(&mi.remote_addr);
    conn->remote_addr = mi.remote_addr;
    if (mi.have_local_addr) {
        conn->local_addr = mi.local_addr;
    }

    conn->last_activity_us = mqcp_now_us();

    /* Feed the packet to the handshake */
    int ret = mqcp_handshake_on_recv(conn->hs, ctx, conn,
                                     buf, (size_t)n, mqcp_now_us());
    if (ret < 0) {
        mqcp_conn_free(conn);
        return NULL;
    }

    if (ret == 1) {
        /* Handshake complete in one shot (unlikely for fragmented) */
        conn->state = MQCP_STATE_ESTABLISHED;
    } else {
        conn->state = MQCP_STATE_HANDSHAKE_RECEIVED;
    }

    return conn;
}

/* --- Derive session keys after handshake --- */

static int derive_session_keys(mqcp_conn_t *conn) {
    uint8_t ck[MQCP_AES_KEY_SZ], sk[MQCP_AES_KEY_SZ];
    uint8_t cpm[MQCP_PN_MASK_SZ], spm[MQCP_PN_MASK_SZ];

    if (mqcp_derive_keys(mqcp_handshake_shared_secret(conn->hs), ck, sk, cpm, spm) != 0) {
        return -1;
    }

    if (conn->role == MQCP_CLIENT) {
        memcpy(conn->tx_key, ck, MQCP_AES_KEY_SZ);
        memcpy(conn->rx_key, sk, MQCP_AES_KEY_SZ);
        memcpy(conn->tx_pn_mask, cpm, MQCP_PN_MASK_SZ);
        memcpy(conn->rx_pn_mask, spm, MQCP_PN_MASK_SZ);
    } else {
        memcpy(conn->tx_key, sk, MQCP_AES_KEY_SZ);
        memcpy(conn->rx_key, ck, MQCP_AES_KEY_SZ);
        memcpy(conn->tx_pn_mask, spm, MQCP_PN_MASK_SZ);
        memcpy(conn->rx_pn_mask, cpm, MQCP_PN_MASK_SZ);
    }

    mqcp_secure_zero(ck, sizeof(ck));
    mqcp_secure_zero(sk, sizeof(sk));
    conn->keys_ready = 1;
    conn->peer_cert_index = mqcp_handshake_peer_index(conn->hs);

    MQCP_LOG("Session keys derived (peer_index=%d)", conn->peer_cert_index);
    return 0;
}

/* Forward declarations */
static void on_pkt_lost(uint64_t stream_offset, size_t stream_len, void *ctx);

/* --- Packet encryption/decryption --- */

/* Build, encrypt, and send a short-header packet containing frames.
 * frames/frames_len is the plaintext frame payload.
 * Returns 0 on success, -1 on error, MQCP_ERR_AGAIN if blocked. */
static int send_short_packet(mqcp_conn_t *conn,
                             const uint8_t *frames, size_t frames_len,
                             int ack_eliciting,
                             uint64_t stream_offset, size_t stream_len) {
    if (conn->next_pn >= MQCP_MAX_PACKET_NUMBER) {
        MQCP_SECURITY("Key exhaustion: PN limit reached");
        return -1;
    }

    uint64_t pn = conn->next_pn;
    int pn_len = mqcp_pn_encoding_len(pn, conn->rtb.largest_acked_pn);

    /* Build header */
    uint8_t pkt[MQCP_MAX_DATAGRAM];
    int hdr_len = mqcp_short_header_encode(pkt, sizeof(pkt), pn, pn_len);
    if (hdr_len < 0) return -1;

    /* Encrypt: plaintext = frames, AAD = header */
    uint8_t nonce[MQCP_GCM_IV_SZ];
    mqcp_make_nonce(pn, conn->tx_pn_mask, nonce);

    uint8_t *ct = pkt + hdr_len;
    uint8_t tag[MQCP_GCM_TAG_SZ];

    size_t max_ct = sizeof(pkt) - (size_t)hdr_len - MQCP_GCM_TAG_SZ;
    if (frames_len > max_ct) return -1;

    if (mqcp_aes_gcm_encrypt(conn->tx_key, nonce,
                             frames, frames_len,
                             pkt, (size_t)hdr_len,
                             ct, tag) != 0) {
        return -1;
    }

    memcpy(ct + frames_len, tag, MQCP_GCM_TAG_SZ);
    size_t pkt_len = (size_t)hdr_len + frames_len + MQCP_GCM_TAG_SZ;

    /* Send */
    struct udp_send_info si;
    memset(&si, 0, sizeof(si));
    si.remote_addr = &conn->remote_addr;

    ssize_t rv = udp_send(conn->fd, pkt, pkt_len, &si);
    if (rv == UDP_SEND_BLOCKED) return MQCP_ERR_AGAIN;
    if (rv < 0) return -1;

    conn->next_pn++;

    /* Track for retransmission */
    if (ack_eliciting) {
        mqcp_sent_pkt_t *sp = (mqcp_sent_pkt_t *)calloc(1, sizeof(*sp));
        if (sp) {
            sp->pn = pn;
            sp->sent_time_us = mqcp_now_us();
            sp->stream_offset = stream_offset;
            sp->stream_len = stream_len;
            sp->pkt_len = pkt_len;
            sp->ack_eliciting = 1;
            sp->in_flight = 1;
            mqcp_rtb_add(&conn->rtb, sp);
            mqcp_cc_on_sent(&conn->cc, pkt_len);
        }
    }

    conn->last_activity_us = mqcp_now_us();
    return 0;
}

/* Decrypt and process a received short-header packet. */
static int recv_short_packet(mqcp_conn_t *conn,
                             const uint8_t *data, size_t len,
                             uint64_t now_us) {
    uint64_t truncated_pn;
    int pn_len;

    int hdr_len = mqcp_short_header_decode(data, len, &truncated_pn, &pn_len);
    if (hdr_len < 0) return -1;

    uint64_t pn = mqcp_pn_decode(truncated_pn, pn_len, conn->largest_recv_pn);

    /* Anti-replay check */
    if (pn + MQCP_PN_WINDOW <= conn->largest_recv_pn) {
        return 0; /* too old, silently drop */
    }

    size_t payload_len = len - (size_t)hdr_len;
    if (payload_len < MQCP_GCM_TAG_SZ) return -1;

    size_t ct_len = payload_len - MQCP_GCM_TAG_SZ;
    const uint8_t *ct = data + hdr_len;
    const uint8_t *tag = ct + ct_len;

    /* Decrypt */
    uint8_t nonce[MQCP_GCM_IV_SZ];
    mqcp_make_nonce(pn, conn->rx_pn_mask, nonce);

    uint8_t pt[MQCP_MAX_DATAGRAM];
    if (mqcp_aes_gcm_decrypt(conn->rx_key, nonce,
                             ct, ct_len,
                             data, (size_t)hdr_len,
                             tag, pt) != 0) {
        MQCP_SECURITY("GCM auth failed (pn=%lu)", (unsigned long)pn);
        return -1;
    }

    /* Update largest received PN */
    if (pn > conn->largest_recv_pn) {
        conn->largest_recv_pn = pn;
    }

    conn->last_activity_us = now_us;

    /* Process frames */
    size_t pos = 0;
    while (pos < ct_len) {
        uint8_t frame_type = pt[pos];

        switch (frame_type) {
        case MQCP_FRAME_STREAM: {
            uint64_t offset;
            uint16_t data_len;
            int fhdr = mqcp_frame_stream_decode(pt + pos, ct_len - pos,
                                                &offset, &data_len);
            if (fhdr < 0) return -1;
            pos += (size_t)fhdr;
            if (pos + data_len > ct_len) return -1;

            mqcp_recv_stream_insert(&conn->recv_stream, offset,
                                    pt + pos, data_len);
            pos += data_len;

            mqcp_ack_tracker_add(&conn->ack_tracker, pn, 1, now_us);
            break;
        }

        case MQCP_FRAME_ACK: {
            uint32_t largest_ack;
            uint16_t ack_delay;
            uint64_t ranges[MQCP_MAX_ACK_RANGES * 2 + 1];
            int range_count;

            int flen = mqcp_frame_ack_decode(pt + pos, ct_len - pos,
                                             &largest_ack, &ack_delay,
                                             ranges, &range_count,
                                             MQCP_MAX_ACK_RANGES);
            if (flen < 0) return -1;
            pos += (size_t)flen;

            uint64_t bytes_acked = 0;
            mqcp_rtb_on_ack(&conn->rtb, &conn->rtt,
                            largest_ack, ack_delay,
                            ranges, range_count, now_us,
                            &bytes_acked, on_pkt_lost, conn);

            if (bytes_acked > 0) {
                mqcp_cc_on_ack(&conn->cc, bytes_acked);
            }

            /* ACK frames are not ack-eliciting */
            break;
        }

        case MQCP_FRAME_CLOSE: {
            conn->state = MQCP_STATE_CLOSED;
            return 0;
        }

        case MQCP_FRAME_PING: {
            pos++;
            mqcp_ack_tracker_add(&conn->ack_tracker, pn, 1, now_us);
            break;
        }

        case MQCP_FRAME_MAX_DATA: {
            if (pos + 9 > ct_len) return -1;
            uint64_t max_bytes = 0;
            for (int i = 0; i < 8; i++) {
                max_bytes = (max_bytes << 8) | pt[pos + 1 + i];
            }
            pos += 9;
            if (max_bytes > conn->max_data_remote) {
                conn->max_data_remote = max_bytes;
            }
            break;
        }

        case MQCP_FRAME_DATA_BLOCKED: {
            pos += 9;
            /* Peer is blocked — send MAX_DATA update */
            conn->send_max_data = 1;
            break;
        }

        default:
            /* Unknown frame type — skip to end */
            pos = ct_len;
            break;
        }
    }

    return 0;
}

/* --- lost_cb for stream retransmission --- */

static void on_pkt_lost(uint64_t stream_offset, size_t stream_len, void *ctx) {
    mqcp_conn_t *conn = (mqcp_conn_t *)ctx;
    mqcp_send_stream_retransmit(&conn->send_stream, stream_offset, stream_len);
}

/* --- Event processing --- */

int mqcp_process(mqcp_conn_t *conn) {
    uint64_t now = mqcp_now_us();

    /* Read available datagrams */
    for (int i = 0; i < 64; i++) {
        uint8_t buf[MQCP_MAX_DATAGRAM + 100];
        struct udp_msg_info mi;

        ssize_t n = udp_recv(conn->fd, buf, sizeof(buf), conn->family, &mi);
        if (n <= 0) break;

        now = mqcp_now_us();

        if (conn->state == MQCP_STATE_HANDSHAKE_SENT ||
            conn->state == MQCP_STATE_HANDSHAKE_RECEIVED) {
            /* Feed to handshake */
            int ret = mqcp_handshake_on_recv(conn->hs, conn->ctx, conn,
                                             buf, (size_t)n, now);
            if (ret == 1) {
                /* Handshake complete */
                if (derive_session_keys(conn) != 0) {
                    conn->state = MQCP_STATE_FAILED;
                    return MQCP_ERR_CRYPTO;
                }
                conn->state = MQCP_STATE_ESTABLISHED;
            } else if (ret < 0) {
                conn->state = MQCP_STATE_FAILED;
                return MQCP_ERR_CRYPTO;
            }
        } else if (conn->state == MQCP_STATE_ESTABLISHED ||
                   conn->state == MQCP_STATE_CLOSING) {
            /* Decrypt and process data packet */
            if (!mqcp_is_long_header(buf[0])) {
                recv_short_packet(conn, buf, (size_t)n, now);
            } else {
                /* Late handshake packet (e.g. retransmitted ACK) — ignore */
            }
        }
    }

    /* Check handshake timers */
    if (conn->state == MQCP_STATE_HANDSHAKE_SENT ||
        conn->state == MQCP_STATE_HANDSHAKE_RECEIVED) {
        int ret = mqcp_handshake_check_timers(conn->hs, conn, now);
        if (ret != 0) {
            conn->state = MQCP_STATE_FAILED;
            return ret;
        }
    }

    /* For server: handshake may complete after receiving more fragments */
    if (conn->state == MQCP_STATE_HANDSHAKE_RECEIVED &&
        mqcp_handshake_state(conn->hs) == MQCP_HS_SERVER_RESPONDING) {
        /* Derive keys if not already done, treat first data packet as implicit ACK */
        if (mqcp_handshake_has_secret(conn->hs) && !conn->keys_ready) {
            if (derive_session_keys(conn) != 0) {
                conn->state = MQCP_STATE_FAILED;
                return MQCP_ERR_CRYPTO;
            }
            conn->state = MQCP_STATE_ESTABLISHED;
        }
    }

    if (conn->state != MQCP_STATE_ESTABLISHED) return MQCP_OK;

    /* Send ACKs if needed */
    if (mqcp_ack_tracker_should_ack(&conn->ack_tracker, now)) {
        uint32_t largest_ack;
        uint16_t ack_delay;
        uint64_t ranges[MQCP_MAX_ACK_RANGES * 2 + 1];
        int range_count = mqcp_ack_tracker_build_ranges(
            &conn->ack_tracker, &largest_ack, &ack_delay,
            ranges, MQCP_MAX_ACK_RANGES, now);

        if (range_count > 0) {
            uint8_t frame[256];
            int flen = mqcp_frame_ack_encode(frame, sizeof(frame),
                                             largest_ack, ack_delay,
                                             ranges, range_count);
            if (flen > 0) {
                send_short_packet(conn, frame, (size_t)flen,
                                  0, 0, 0); /* ACK is not ack-eliciting */
                mqcp_ack_tracker_on_ack_sent(&conn->ack_tracker);
            }
        }
    }

    /* Send MAX_DATA update if needed */
    if (conn->send_max_data) {
        uint64_t new_max = conn->recv_stream.read_offset + conn->max_data_local;
        if (new_max > conn->max_data_sent) {
            uint8_t frame[16];
            int flen = mqcp_frame_max_data_encode(frame, sizeof(frame), new_max);
            if (flen > 0) {
                send_short_packet(conn, frame, (size_t)flen, 1, 0, 0);
                conn->max_data_sent = new_max;
                conn->send_max_data = 0;
            }
        }
    }

    /* Send stream data */
    mqcp_flush(conn);

    /* PTO check */
    uint64_t pto_deadline = mqcp_rtb_pto_deadline(&conn->rtb, &conn->rtt,
                                                  conn->pto_count);
    if (pto_deadline > 0 && now >= pto_deadline) {
        /* Send a PING as PTO probe */
        uint8_t frame[1];
        int flen = mqcp_frame_ping_encode(frame, sizeof(frame));
        send_short_packet(conn, frame, (size_t)flen, 1, 0, 0);
        conn->pto_count++;
    }

    /* Idle timeout */
    if (now - conn->last_activity_us > conn->idle_timeout_us) {
        MQCP_LOG("Idle timeout");
        conn->state = MQCP_STATE_CLOSED;
        return MQCP_ERR_TIMEOUT;
    }

    /* Closing timeout */
    if (conn->state == MQCP_STATE_CLOSING &&
        conn->close_deadline > 0 && now >= conn->close_deadline) {
        conn->state = MQCP_STATE_CLOSED;
    }

    return MQCP_OK;
}

/* --- Public I/O --- */

int mqcp_write(mqcp_conn_t *conn, const void *buf, size_t len) {
    if (conn->state != MQCP_STATE_ESTABLISHED) return MQCP_ERR;

    size_t written = mqcp_send_stream_write(&conn->send_stream, buf, len);
    if (written == 0) return MQCP_ERR_AGAIN;
    return (int)written;
}

int mqcp_flush(mqcp_conn_t *conn) {
    if (conn->state != MQCP_STATE_ESTABLISHED || !conn->keys_ready) {
        return MQCP_OK;
    }

    /* Max stream frame payload per packet */
    size_t max_frame_data = MQCP_MAX_DATAGRAM - 5 /* short header max */
                            - 11 /* STREAM frame header */
                            - MQCP_GCM_TAG_SZ;

    while (mqcp_send_stream_pending(&conn->send_stream) > 0) {
        /* Check congestion window */
        uint64_t avail = mqcp_cc_available(&conn->cc);
        if (avail < MQCP_MTU) break;

        /* Check flow control */
        uint64_t fc_avail = conn->max_data_remote - conn->send_stream.send_offset;
        if (fc_avail == 0) {
            /* Send DATA_BLOCKED */
            uint8_t frame[16];
            frame[0] = MQCP_FRAME_DATA_BLOCKED;
            /* put offset */
            uint64_t v = conn->send_stream.send_offset;
            for (int i = 7; i >= 0; i--) { frame[1 + i] = (uint8_t)(v & 0xFF); v >>= 8; }
            send_short_packet(conn, frame, 9, 1, 0, 0);
            break;
        }

        const uint8_t *data;
        size_t chunk = mqcp_send_stream_peek(&conn->send_stream, &data,
                                             max_frame_data);
        if (chunk == 0) break;
        if (chunk > fc_avail) chunk = (size_t)fc_avail;

        /* Build STREAM frame */
        uint8_t frame[MQCP_MAX_DATAGRAM];
        int fhdr = mqcp_frame_stream_encode(frame, sizeof(frame),
                                            conn->send_stream.send_offset,
                                            (uint16_t)chunk);
        if (fhdr < 0) break;
        memcpy(frame + fhdr, data, chunk);

        uint64_t offset = conn->send_stream.send_offset;
        int ret = send_short_packet(conn, frame, (size_t)fhdr + chunk,
                                    1, offset, chunk);
        if (ret != 0) break;

        mqcp_send_stream_advance(&conn->send_stream, chunk);
    }

    return MQCP_OK;
}

int mqcp_read(mqcp_conn_t *conn, void *buf, size_t len) {
    if (conn->state == MQCP_STATE_CLOSED) return MQCP_ERR_CLOSED;

    size_t n = mqcp_recv_stream_read(&conn->recv_stream, buf, len);

    /* Check if we should send a MAX_DATA update */
    if (n > 0) {
        uint64_t remaining = conn->max_data_sent -
                             conn->recv_stream.read_offset;
        if (remaining < conn->max_data_local / 2) {
            conn->send_max_data = 1;
        }
    }

    return (int)n;
}

int mqcp_close(mqcp_conn_t *conn) {
    if (conn->state != MQCP_STATE_ESTABLISHED) return MQCP_ERR;

    /* Send CLOSE frame */
    uint8_t frame[64];
    int flen = mqcp_frame_close_encode(frame, sizeof(frame), 0, NULL, 0);
    if (flen > 0) {
        send_short_packet(conn, frame, (size_t)flen, 1, 0, 0);
    }

    conn->state = MQCP_STATE_CLOSING;
    conn->close_deadline = mqcp_now_us() + 3 * conn->rtt.smoothed_us;
    return MQCP_OK;
}

void mqcp_conn_free(mqcp_conn_t *conn) {
    if (!conn) return;

    mqcp_handshake_free(conn->hs);
    mqcp_rtb_free(&conn->rtb);
    mqcp_send_stream_free(&conn->send_stream);
    mqcp_recv_stream_free(&conn->recv_stream);

    mqcp_secure_zero(conn->tx_key, sizeof(conn->tx_key));
    mqcp_secure_zero(conn->rx_key, sizeof(conn->rx_key));

    if (conn->owns_fd && conn->fd >= 0) {
        close(conn->fd);
    }

    free(conn);
}

/* --- Queries --- */

int mqcp_is_established(mqcp_conn_t *conn) {
    return conn->state == MQCP_STATE_ESTABLISHED;
}

mqcp_state_t mqcp_get_state(mqcp_conn_t *conn) {
    return conn->state;
}

int mqcp_get_fd(mqcp_conn_t *conn) {
    return conn->fd;
}

uint64_t mqcp_next_timer(mqcp_conn_t *conn) {
    uint64_t next = 0;

    /* Handshake timer */
    if (conn->state == MQCP_STATE_HANDSHAKE_SENT ||
        conn->state == MQCP_STATE_HANDSHAKE_RECEIVED) {
        uint64_t hs = mqcp_handshake_next_timer(conn->hs);
        if (hs > 0 && (next == 0 || hs < next)) next = hs;
    }

    /* ACK delay timer */
    uint64_t ack = conn->ack_tracker.ack_timer_deadline;
    if (ack > 0 && (next == 0 || ack < next)) next = ack;

    /* PTO timer */
    uint64_t pto = mqcp_rtb_pto_deadline(&conn->rtb, &conn->rtt,
                                          conn->pto_count);
    if (pto > 0 && (next == 0 || pto < next)) next = pto;

    /* Idle timeout */
    uint64_t idle = conn->last_activity_us + conn->idle_timeout_us;
    if (next == 0 || idle < next) next = idle;

    return next;
}

int mqcp_get_peer_index(mqcp_conn_t *conn) {
    return conn->peer_cert_index;
}
