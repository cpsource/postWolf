/* mqcp_conn.h — Connection internals (private to library) */

#ifndef MQCP_CONN_H
#define MQCP_CONN_H

#include "mqcp.h"
#include "mqcp_handshake.h"
#include "mqcp_reliability.h"
#include "mqcp_cc.h"
#include "mqcp_stream.h"
#include "mqcp_crypto.h"

#include <udp/udp.h>

/* Internal context structure */
struct mqcp_ctx {
    mqcp_role_t  role;
    char        *tpm_path;
    int          our_cert_index;
    char        *mtc_server;
    uint8_t     *ca_pubkey;
    int          ca_pubkey_sz;
    uint8_t     *privkey_der;     /* ML-DSA-87 private key DER */
    int          privkey_der_sz;
    int          encrypt_identity;
    uint64_t     idle_timeout_us;
    size_t       max_recv_window;
};

/* Internal connection structure */
struct mqcp_conn {
    /* Back-reference */
    mqcp_ctx_t *ctx;
    mqcp_role_t role;
    mqcp_state_t state;

    /* Socket */
    int fd;
    int family;
    struct udp_addr local_addr;
    struct udp_addr remote_addr;
    int owns_fd;                  /* 1 if we created the fd (client) */

    /* Handshake */
    mqcp_handshake_t *hs;

    /* Session keys */
    uint8_t tx_key[MQCP_AES_KEY_SZ];
    uint8_t rx_key[MQCP_AES_KEY_SZ];
    uint8_t tx_pn_mask[MQCP_PN_MASK_SZ];
    uint8_t rx_pn_mask[MQCP_PN_MASK_SZ];
    int     keys_ready;

    /* Packet numbers */
    uint64_t next_pn;
    uint64_t largest_recv_pn;

    /* Anti-replay: bitfield for received PNs in window */
    uint8_t  recv_pn_bitmap[MQCP_PN_WINDOW / 8];

    /* Reliability */
    mqcp_rtb_t rtb;
    mqcp_rtt_t rtt;
    mqcp_ack_tracker_t ack_tracker;
    int pto_count;

    /* Congestion control */
    mqcp_cc_t cc;

    /* Stream */
    mqcp_send_stream_t send_stream;
    mqcp_recv_stream_t recv_stream;

    /* Flow control */
    uint64_t max_data_local;      /* our receive window */
    uint64_t max_data_remote;     /* peer's advertised limit */
    uint64_t max_data_sent;       /* last MAX_DATA we advertised to peer */
    int      send_max_data;       /* 1 if we need to send MAX_DATA update */

    /* Peer identity */
    int peer_cert_index;

    /* Timers */
    uint64_t idle_timeout_us;
    uint64_t last_activity_us;

    /* Close state */
    int      close_sent;
    uint64_t close_deadline;      /* when to transition to CLOSED */
};

/* Logging helpers */
extern int mqcp_get_verbose(void);

#define MQCP_LOG(fmt, ...) do { if (mqcp_get_verbose()) \
    fprintf(stderr, "[MQCP %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__); } while(0)

#define MQCP_SECURITY(fmt, ...) \
    fprintf(stderr, "[MQCP-SECURITY %s:%d] " fmt "\n", __func__, __LINE__, \
            ##__VA_ARGS__)

#endif /* MQCP_CONN_H */
