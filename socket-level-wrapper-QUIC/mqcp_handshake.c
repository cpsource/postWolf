/* mqcp_handshake.c — Handshake state machine over UDP
 *
 * Implements the MQCP handshake using ML-KEM-768 key exchange and
 * ML-DSA-87 authentication, fragmented across UDP datagrams.
 */

#include "mqcp_handshake.h"
#include "mqcp_crypto.h"
#include "mqcp_timer.h"
#include "mqcp_conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <udp/udp.h>

#include "mqcp_peer.h"

/* --- Full handshake struct definition (contains wolfSSL types) --- */

struct mqcp_handshake {
    mqcp_hs_state_t state;

    /* Our ephemeral ML-KEM key */
    MlKemKey mlkem;
    int      mlkem_init;
    WC_RNG   rng;
    int      rng_init;

    /* Reassembly for incoming handshake message */
    mqcp_reassembly_t reassembly;

    /* Our sent handshake fragments (for retransmission) */
    struct {
        uint8_t  data[MQCP_MAX_DATAGRAM];
        size_t   len;
        uint64_t pn;
        int      acked;
    } sent_frags[MQCP_MAX_HS_FRAGMENTS];
    int sent_frag_count;

    /* Retransmission */
    uint64_t retransmit_deadline;
    uint64_t retransmit_interval;
    int      retransmit_count;

    /* Handshake timeout */
    uint64_t deadline;

    /* Connection ID */
    uint32_t conn_id;

    /* Packet numbering for handshake */
    uint32_t next_hs_pn;

    /* Shared secret (output) */
    uint8_t  shared_secret[32];
    int      has_shared_secret;

    /* Peer cert_index (output) */
    int      peer_cert_index;
};

/* --- Logging --- */

#define HS_LOG(fmt, ...) do { if (mqcp_get_verbose()) \
    fprintf(stderr, "[MQCP-HS %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__); } while(0)

#define HS_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQCP-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__)

/* --- Helpers --- */

static int send_fragment(struct mqcp_conn *conn, const uint8_t *pkt,
                         size_t pkt_len) {
    struct udp_send_info si;
    memset(&si, 0, sizeof(si));
    si.remote_addr = &conn->remote_addr;

    ssize_t rv = udp_send(conn->fd, pkt, pkt_len, &si);
    if (rv < 0 && rv != UDP_SEND_BLOCKED) {
        return -1;
    }
    return 0;
}

static int send_hs_message(mqcp_handshake_t *hs, struct mqcp_conn *conn,
                           int pkt_type, uint8_t msg_type,
                           const uint8_t *msg, uint32_t msg_len) {
    hs->sent_frag_count = 0;

    uint32_t offset = 0;
    while (offset < msg_len && hs->sent_frag_count < MQCP_MAX_HS_FRAGMENTS) {
        uint16_t frag_len = (uint16_t)(msg_len - offset);
        if (frag_len > MQCP_HS_FRAGMENT_PAYLOAD) {
            frag_len = MQCP_HS_FRAGMENT_PAYLOAD;
        }

        uint8_t pkt[MQCP_MAX_DATAGRAM];
        int hdr_len = mqcp_long_header_encode(
            pkt, sizeof(pkt), pkt_type, hs->conn_id,
            hs->next_hs_pn, msg_type, (uint16_t)offset, msg_len, frag_len);
        if (hdr_len < 0) return -1;

        memcpy(pkt + hdr_len, msg + offset, frag_len);
        size_t total = (size_t)hdr_len + frag_len;

        int idx = hs->sent_frag_count;
        memcpy(hs->sent_frags[idx].data, pkt, total);
        hs->sent_frags[idx].len = total;
        hs->sent_frags[idx].pn = hs->next_hs_pn;
        hs->sent_frags[idx].acked = 0;

        send_fragment(conn, pkt, total);
        hs->next_hs_pn++;
        hs->sent_frag_count++;
        offset += frag_len;
    }

    return 0;
}

static int retransmit_fragments(mqcp_handshake_t *hs,
                                struct mqcp_conn *conn) {
    int sent = 0;
    for (int i = 0; i < hs->sent_frag_count; i++) {
        if (!hs->sent_frags[i].acked) {
            if (send_fragment(conn, hs->sent_frags[i].data,
                              hs->sent_frags[i].len) == 0) {
                sent++;
            }
        }
    }
    return sent;
}

static int send_hs_ack(mqcp_handshake_t *hs, struct mqcp_conn *conn,
                       uint32_t largest_pn) {
    uint8_t pkt[MQCP_MAX_DATAGRAM];
    int hdr_len = mqcp_long_header_encode(
        pkt, sizeof(pkt), MQCP_PKT_HS_ACK, hs->conn_id,
        hs->next_hs_pn, 0, 0, 0, 0);
    if (hdr_len < 0) return -1;

    size_t pos = (size_t)hdr_len;
    pkt[pos++] = 1;
    pkt[pos++] = (uint8_t)(largest_pn >> 24);
    pkt[pos++] = (uint8_t)(largest_pn >> 16);
    pkt[pos++] = (uint8_t)(largest_pn >> 8);
    pkt[pos++] = (uint8_t)(largest_pn);
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;

    hs->next_hs_pn++;
    return send_fragment(conn, pkt, pos);
}

/* --- Client Hello --- */

static int build_client_hello(mqcp_handshake_t *hs, struct mqcp_ctx *ctx,
                              uint8_t **msg_out, uint32_t *msg_len_out) {
    int ret;
    word32 idx;

    /* Init ML-KEM-768 */
    ret = wc_MlKemKey_Init(&hs->mlkem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) return -1;
    hs->mlkem_init = 1;

    ret = wc_InitRng(&hs->rng);
    if (ret != 0) return -1;
    hs->rng_init = 1;

    ret = wc_MlKemKey_MakeKey(&hs->mlkem, &hs->rng);
    if (ret != 0) return -1;

    /* Export encapsulation key */
    word32 encaps_key_sz = 0;
    wc_MlKemKey_PublicKeySize(&hs->mlkem, &encaps_key_sz);
    uint8_t *encaps_key = (uint8_t *)malloc(encaps_key_sz);
    if (!encaps_key) return -1;

    ret = wc_MlKemKey_EncodePublicKey(&hs->mlkem, encaps_key, encaps_key_sz);
    if (ret != 0) { free(encaps_key); return -1; }

    /* Sign encaps_key with our ML-DSA-87 private key */
    dilithium_key dsa;
    wc_dilithium_init(&dsa);
    wc_dilithium_set_level(&dsa, WC_ML_DSA_87);

    idx = 0;
    ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &idx,
                                        &dsa, (word32)ctx->privkey_der_sz);
    if (ret != 0) {
        wc_dilithium_free(&dsa);
        free(encaps_key);
        return -1;
    }

    uint8_t sig[8192];
    word32 sig_sz = sizeof(sig);
    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                                    encaps_key, encaps_key_sz,
                                    sig, &sig_sz, &dsa, &hs->rng);
    wc_dilithium_free(&dsa);
    if (ret != 0) { free(encaps_key); return -1; }

    /* Build message: cert_index(4) + encaps_key + signature */
    uint32_t total = 4 + encaps_key_sz + sig_sz;
    uint8_t *msg = (uint8_t *)malloc(total);
    if (!msg) { free(encaps_key); return -1; }

    uint32_t ci = (uint32_t)ctx->our_cert_index;
    msg[0] = (uint8_t)(ci >> 24); msg[1] = (uint8_t)(ci >> 16);
    msg[2] = (uint8_t)(ci >> 8);  msg[3] = (uint8_t)(ci);
    memcpy(msg + 4, encaps_key, encaps_key_sz);
    memcpy(msg + 4 + encaps_key_sz, sig, sig_sz);

    free(encaps_key);
    *msg_out = msg;
    *msg_len_out = total;
    return 0;
}

/* --- Process ServerHello --- */

static int process_server_hello(mqcp_handshake_t *hs, struct mqcp_ctx *ctx,
                                const uint8_t *msg, uint32_t msg_len) {
    (void)ctx;

    word32 ct_sz = 0;
    wc_MlKemKey_CipherTextSize(&hs->mlkem, &ct_sz);

    if (msg_len < 4 + ct_sz) {
        HS_SECURITY("ServerHello too short: %u", msg_len);
        return -1;
    }

    int peer_index = (int)((msg[0] << 24) | (msg[1] << 16) |
                           (msg[2] << 8) | msg[3]);
    hs->peer_cert_index = peer_index;

    const uint8_t *ciphertext = msg + 4;
    const uint8_t *sig = msg + 4 + ct_sz;
    word32 sig_len = msg_len - 4 - ct_sz;

    /* Verify peer */
    unsigned char *peer_pubkey = NULL;
    int peer_pubkey_sz = 0;
    if (mqcp_peer_get_pubkey(peer_index, &peer_pubkey, &peer_pubkey_sz) != 0) {
        HS_SECURITY("Peer verification failed for cert_index=%d", peer_index);
        return -1;
    }

    /* Verify signature */
    dilithium_key peer_dsa;
    wc_dilithium_init(&peer_dsa);
    wc_dilithium_set_level(&peer_dsa, WC_ML_DSA_87);

    word32 pi = 0;
    int ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi,
                                           &peer_dsa, (word32)peer_pubkey_sz);
    free(peer_pubkey);
    if (ret != 0) { wc_dilithium_free(&peer_dsa); return -1; }

    int verified = 0;
    ret = wc_dilithium_verify_ctx_msg(sig, sig_len,
                                      NULL, 0,
                                      ciphertext, ct_sz,
                                      &verified, &peer_dsa);
    wc_dilithium_free(&peer_dsa);
    if (ret != 0 || !verified) {
        HS_SECURITY("Sig verify failed for peer=%d", peer_index);
        return -1;
    }

    /* ML-KEM decapsulate */
    uint8_t ss[WC_ML_KEM_SS_SZ];
    ret = wc_MlKemKey_Decapsulate(&hs->mlkem, ss, ciphertext, ct_sz);
    if (ret != 0) {
        HS_SECURITY("ML-KEM decapsulation failed");
        return -1;
    }

    memcpy(hs->shared_secret, ss, 32);
    hs->has_shared_secret = 1;
    mqcp_secure_zero(ss, sizeof(ss));

    HS_LOG("Client handshake complete, peer=%d", peer_index);
    return 0;
}

/* --- Process ClientHello (server side) --- */

static int process_client_hello(mqcp_handshake_t *hs, struct mqcp_ctx *ctx,
                                struct mqcp_conn *conn,
                                const uint8_t *msg, uint32_t msg_len) {
    /* Figure out encaps key size for ML-KEM-768 */
    MlKemKey tmp_kem;
    wc_MlKemKey_Init(&tmp_kem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    word32 ek_sz = 0;
    wc_MlKemKey_PublicKeySize(&tmp_kem, &ek_sz);
    wc_MlKemKey_Free(&tmp_kem);

    if (msg_len < 4 + ek_sz) {
        HS_SECURITY("ClientHello too short: %u", msg_len);
        return -1;
    }

    int peer_index = (int)((msg[0] << 24) | (msg[1] << 16) |
                           (msg[2] << 8) | msg[3]);
    hs->peer_cert_index = peer_index;

    const uint8_t *encaps_key = msg + 4;
    const uint8_t *sig = msg + 4 + ek_sz;
    word32 sig_len = msg_len - 4 - ek_sz;

    /* Verify peer */
    unsigned char *peer_pubkey = NULL;
    int peer_pubkey_sz = 0;
    if (mqcp_peer_get_pubkey(peer_index, &peer_pubkey, &peer_pubkey_sz) != 0) {
        HS_SECURITY("Peer verification failed for cert_index=%d", peer_index);
        return -1;
    }

    dilithium_key peer_dsa;
    wc_dilithium_init(&peer_dsa);
    wc_dilithium_set_level(&peer_dsa, WC_ML_DSA_87);

    word32 pi = 0;
    int ret = wc_Dilithium_PublicKeyDecode(peer_pubkey, &pi,
                                           &peer_dsa, (word32)peer_pubkey_sz);
    free(peer_pubkey);
    if (ret != 0) { wc_dilithium_free(&peer_dsa); return -1; }

    int verified = 0;
    ret = wc_dilithium_verify_ctx_msg(sig, sig_len,
                                      NULL, 0,
                                      encaps_key, ek_sz,
                                      &verified, &peer_dsa);
    wc_dilithium_free(&peer_dsa);
    if (ret != 0 || !verified) {
        HS_SECURITY("Sig verify failed for peer=%d", peer_index);
        return -1;
    }

    /* ML-KEM encapsulate */
    MlKemKey kem;
    ret = wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) return -1;

    ret = wc_MlKemKey_DecodePublicKey(&kem, encaps_key, ek_sz);
    if (ret != 0) { wc_MlKemKey_Free(&kem); return -1; }

    word32 ct_sz = 0;
    wc_MlKemKey_CipherTextSize(&kem, &ct_sz);
    uint8_t *ct = (uint8_t *)malloc(ct_sz);
    if (!ct) { wc_MlKemKey_Free(&kem); return -1; }

    uint8_t ss[WC_ML_KEM_SS_SZ];
    WC_RNG rng;
    wc_InitRng(&rng);
    ret = wc_MlKemKey_Encapsulate(&kem, ct, ss, &rng);
    wc_FreeRng(&rng);
    wc_MlKemKey_Free(&kem);
    if (ret != 0) { free(ct); return -1; }

    memcpy(hs->shared_secret, ss, 32);
    hs->has_shared_secret = 1;
    mqcp_secure_zero(ss, sizeof(ss));

    /* Sign ciphertext */
    dilithium_key our_dsa;
    wc_dilithium_init(&our_dsa);
    wc_dilithium_set_level(&our_dsa, WC_ML_DSA_87);

    word32 idx = 0;
    ret = wc_Dilithium_PrivateKeyDecode(ctx->privkey_der, &idx,
                                        &our_dsa, (word32)ctx->privkey_der_sz);
    if (ret != 0) { wc_dilithium_free(&our_dsa); free(ct); return -1; }

    WC_RNG sig_rng;
    wc_InitRng(&sig_rng);
    uint8_t our_sig[8192];
    word32 our_sig_sz = sizeof(our_sig);
    ret = wc_dilithium_sign_ctx_msg(NULL, 0,
                                    ct, ct_sz,
                                    our_sig, &our_sig_sz, &our_dsa, &sig_rng);
    wc_FreeRng(&sig_rng);
    wc_dilithium_free(&our_dsa);
    if (ret != 0) { free(ct); return -1; }

    /* Build ServerHello: cert_index(4) + ciphertext + signature */
    uint32_t sh_len = 4 + ct_sz + our_sig_sz;
    uint8_t *sh_msg = (uint8_t *)malloc(sh_len);
    if (!sh_msg) { free(ct); return -1; }

    uint32_t ci = (uint32_t)ctx->our_cert_index;
    sh_msg[0] = (uint8_t)(ci >> 24); sh_msg[1] = (uint8_t)(ci >> 16);
    sh_msg[2] = (uint8_t)(ci >> 8);  sh_msg[3] = (uint8_t)(ci);
    memcpy(sh_msg + 4, ct, ct_sz);
    memcpy(sh_msg + 4 + ct_sz, our_sig, our_sig_sz);
    free(ct);

    ret = send_hs_message(hs, conn, MQCP_PKT_SERVER_HELLO,
                          MQCP_HS_SERVER_HELLO, sh_msg, sh_len);
    free(sh_msg);
    if (ret != 0) return -1;

    HS_LOG("Server handshake complete, peer=%d", peer_index);
    return 0;
}

/* --- Public API --- */

mqcp_handshake_t *mqcp_handshake_new(void) {
    mqcp_handshake_t *hs = (mqcp_handshake_t *)calloc(1, sizeof(*hs));
    if (!hs) return NULL;
    hs->state = MQCP_HS_IDLE;
    hs->peer_cert_index = -1;
    hs->retransmit_interval = MQCP_HS_INITIAL_TIMEOUT_US;
    return hs;
}

void mqcp_handshake_free(mqcp_handshake_t *hs) {
    if (!hs) return;
    if (hs->mlkem_init) {
        wc_MlKemKey_Free(&hs->mlkem);
    }
    if (hs->rng_init) {
        wc_FreeRng(&hs->rng);
    }
    mqcp_reassembly_free(&hs->reassembly);
    mqcp_secure_zero(hs->shared_secret, sizeof(hs->shared_secret));
    free(hs);
}

int mqcp_handshake_client_start(mqcp_handshake_t *hs,
                                struct mqcp_ctx *ctx,
                                struct mqcp_conn *conn) {
    uint64_t now = mqcp_now_us();
    hs->deadline = now + MQCP_HS_TIMEOUT_US;

    /* Random connection ID */
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) return -1;
    wc_RNG_GenerateBlock(&rng, (byte *)&hs->conn_id, sizeof(hs->conn_id));
    wc_FreeRng(&rng);

    uint8_t *msg = NULL;
    uint32_t msg_len = 0;
    if (build_client_hello(hs, ctx, &msg, &msg_len) != 0) {
        return -1;
    }

    int ret = send_hs_message(hs, conn, MQCP_PKT_INITIAL,
                              MQCP_HS_CLIENT_HELLO, msg, msg_len);
    free(msg);
    if (ret != 0) return -1;

    hs->state = MQCP_HS_CLIENT_INITIAL_SENT;
    hs->retransmit_deadline = now + hs->retransmit_interval;

    HS_LOG("Client sent ClientHello (%d frags)", hs->sent_frag_count);
    return 0;
}

int mqcp_handshake_on_recv(mqcp_handshake_t *hs,
                           struct mqcp_ctx *ctx,
                           struct mqcp_conn *conn,
                           const uint8_t *data, size_t len,
                           uint64_t now_us) {
    if (!mqcp_is_long_header(data[0])) return 0;

    int pkt_type;
    uint32_t conn_id, pkt_num;
    uint8_t msg_type;
    uint16_t frag_offset, frag_len;
    uint32_t total_len;

    int hdr_len = mqcp_long_header_decode(data, len, &pkt_type, &conn_id,
                                          &pkt_num, &msg_type,
                                          &frag_offset, &total_len,
                                          &frag_len);
    if (hdr_len < 0) return -1;
    if ((size_t)hdr_len + frag_len > len) return -1;

    const uint8_t *payload = data + hdr_len;

    /* HandshakeACK */
    if (pkt_type == MQCP_PKT_HS_ACK) {
        for (int i = 0; i < hs->sent_frag_count; i++) {
            hs->sent_frags[i].acked = 1;
        }
        if (hs->state == MQCP_HS_CLIENT_INITIAL_SENT) {
            hs->state = MQCP_HS_CLIENT_WAIT_SERVER;
        } else if (hs->state == MQCP_HS_SERVER_RESPONDING) {
            hs->state = MQCP_HS_COMPLETE;
            return 1;
        }
        return 0;
    }

    /* Client receiving ServerHello */
    if (hs->state == MQCP_HS_CLIENT_INITIAL_SENT ||
        hs->state == MQCP_HS_CLIENT_WAIT_SERVER) {
        if (pkt_type != MQCP_PKT_SERVER_HELLO) return 0;

        if (!hs->reassembly.buf && total_len > 0) {
            if (mqcp_reassembly_init(&hs->reassembly, total_len) != 0)
                return -1;
        }

        int complete = mqcp_reassembly_add(&hs->reassembly, frag_offset,
                                           payload, frag_len);
        if (complete < 0) return -1;

        send_hs_ack(hs, conn, pkt_num);

        if (complete == 1) {
            hs->conn_id = conn_id;
            int ret = process_server_hello(hs, ctx,
                                           hs->reassembly.buf,
                                           hs->reassembly.total_len);
            if (ret != 0) { hs->state = MQCP_HS_FAILED; return -1; }
            hs->state = MQCP_HS_COMPLETE;
            return 1;
        }
        return 0;
    }

    /* Server receiving ClientHello */
    if (hs->state == MQCP_HS_IDLE || hs->state == MQCP_HS_SERVER_ASSEMBLING) {
        if (pkt_type != MQCP_PKT_INITIAL) return 0;

        if (hs->state == MQCP_HS_IDLE) {
            hs->deadline = now_us + MQCP_HS_TIMEOUT_US;
            hs->conn_id = conn_id;
            hs->state = MQCP_HS_SERVER_ASSEMBLING;
        }

        if (!hs->reassembly.buf && total_len > 0) {
            if (mqcp_reassembly_init(&hs->reassembly, total_len) != 0)
                return -1;
        }

        int complete = mqcp_reassembly_add(&hs->reassembly, frag_offset,
                                           payload, frag_len);
        if (complete < 0) return -1;

        send_hs_ack(hs, conn, pkt_num);

        if (complete == 1) {
            hs->state = MQCP_HS_SERVER_PROCESSING;
            int ret = process_client_hello(hs, ctx, conn,
                                           hs->reassembly.buf,
                                           hs->reassembly.total_len);
            if (ret != 0) { hs->state = MQCP_HS_FAILED; return -1; }
            hs->state = MQCP_HS_SERVER_RESPONDING;
            hs->retransmit_deadline = now_us + hs->retransmit_interval;
            return 0;
        }
        return 0;
    }

    return 0;
}

int mqcp_handshake_check_timers(mqcp_handshake_t *hs,
                                struct mqcp_conn *conn,
                                uint64_t now_us) {
    if (now_us >= hs->deadline) {
        hs->state = MQCP_HS_FAILED;
        return MQCP_ERR_TIMEOUT;
    }

    if (hs->retransmit_deadline > 0 && now_us >= hs->retransmit_deadline) {
        if (hs->retransmit_count >= MQCP_HS_MAX_RETRIES) {
            hs->state = MQCP_HS_FAILED;
            return MQCP_ERR_TIMEOUT;
        }

        HS_LOG("Retransmit handshake (attempt %d)", hs->retransmit_count + 1);
        retransmit_fragments(hs, conn);
        hs->retransmit_count++;
        hs->retransmit_interval *= 2;
        hs->retransmit_deadline = now_us + hs->retransmit_interval;
    }

    return 0;
}

uint64_t mqcp_handshake_next_timer(mqcp_handshake_t *hs) {
    if (hs->state == MQCP_HS_COMPLETE || hs->state == MQCP_HS_FAILED) {
        return 0;
    }

    uint64_t next = hs->deadline;
    if (hs->retransmit_deadline > 0 && hs->retransmit_deadline < next) {
        next = hs->retransmit_deadline;
    }
    return next;
}

/* --- Accessors --- */

mqcp_hs_state_t mqcp_handshake_state(mqcp_handshake_t *hs) {
    return hs->state;
}

int mqcp_handshake_has_secret(mqcp_handshake_t *hs) {
    return hs->has_shared_secret;
}

const uint8_t *mqcp_handshake_shared_secret(mqcp_handshake_t *hs) {
    return hs->shared_secret;
}

int mqcp_handshake_peer_index(mqcp_handshake_t *hs) {
    return hs->peer_cert_index;
}
