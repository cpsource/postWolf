/* mqcp_types.h — MQCP public types, error codes, and constants
 *
 * Part of MQCP (Merkle Quantum Connect Protocol):
 *   QUIC-inspired reliable transport over UDP with MQC post-quantum crypto.
 *
 * Copyright (C) 2026 Cal Page. All rights reserved.
 */

#ifndef MQCP_TYPES_H
#define MQCP_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Error codes --- */

#define MQCP_OK             0
#define MQCP_ERR           -1   /* generic error */
#define MQCP_ERR_AGAIN     -2   /* would block, call mqcp_process() and retry */
#define MQCP_ERR_CLOSED    -3   /* connection closed by peer */
#define MQCP_ERR_TIMEOUT   -4   /* handshake or idle timeout */
#define MQCP_ERR_CRYPTO    -5   /* crypto verification failed */
#define MQCP_ERR_PEER      -6   /* peer verification failed (Merkle/revocation) */

/* --- Roles --- */

typedef enum {
    MQCP_CLIENT,
    MQCP_SERVER
} mqcp_role_t;

/* --- Connection states --- */

typedef enum {
    MQCP_STATE_IDLE,
    MQCP_STATE_HANDSHAKE_SENT,
    MQCP_STATE_HANDSHAKE_RECEIVED,
    MQCP_STATE_HANDSHAKE_PROCESSING,
    MQCP_STATE_HANDSHAKE_RESPONDING,
    MQCP_STATE_ESTABLISHED,
    MQCP_STATE_CLOSING,
    MQCP_STATE_CLOSED,
    MQCP_STATE_FAILED
} mqcp_state_t;

/* --- Packet constants --- */

#define MQCP_VERSION            0x00000001u
#define MQCP_MAX_DATAGRAM       1200       /* PMTU-safe max datagram size */
#define MQCP_LONG_HEADER_LEN    17         /* fixed portion of long header */
#define MQCP_SHORT_HEADER_MIN   2          /* 1 header byte + 1 PN byte */
#define MQCP_GCM_TAG_SZ         16
#define MQCP_AES_KEY_SZ         32
#define MQCP_GCM_IV_SZ          12
#define MQCP_PN_MASK_SZ         4

/* Long header packet types (bits 6-4 of byte 0) */
#define MQCP_PKT_INITIAL        0
#define MQCP_PKT_SERVER_HELLO   1
#define MQCP_PKT_HS_DATA        2
#define MQCP_PKT_HS_ACK         3
#define MQCP_PKT_RETRY          4

/* Handshake message types */
#define MQCP_HS_CLIENT_HELLO          1
#define MQCP_HS_SERVER_HELLO          2
#define MQCP_HS_CLIENT_HELLO_ENC      3
#define MQCP_HS_SERVER_HELLO_ENC      4
#define MQCP_HS_CLIENT_IDENTITY       5
#define MQCP_HS_SERVER_IDENTITY       6
#define MQCP_HS_FINISHED              7

/* Frame types */
#define MQCP_FRAME_STREAM       0x01
#define MQCP_FRAME_ACK          0x02
#define MQCP_FRAME_CLOSE        0x03
#define MQCP_FRAME_PING         0x04
#define MQCP_FRAME_MAX_DATA     0x06
#define MQCP_FRAME_DATA_BLOCKED 0x07

/* --- Reliability constants --- */

#define MQCP_INITIAL_RTT_US     333000     /* 333ms initial RTT estimate */
#define MQCP_MAX_ACK_DELAY_US   25000      /* 25ms max ACK delay */
#define MQCP_PKT_THRESHOLD      3          /* loss: 3-packet reordering */
#define MQCP_TIME_THRESHOLD_NUM 9          /* loss: 9/8 * max_rtt */
#define MQCP_TIME_THRESHOLD_DEN 8
#define MQCP_TIMER_GRANULARITY_US 1000     /* 1ms timer granularity */
#define MQCP_ACK_ELICITING_THRESHOLD 2     /* send ACK after 2 ack-eliciting */
#define MQCP_MAX_ACK_RANGES     32         /* max ACK ranges in one frame */

/* --- Congestion control constants --- */

#define MQCP_INITIAL_CWND       14720      /* 10 * 1200 + overhead */
#define MQCP_MIN_CWND           2400       /* 2 * 1200 */
#define MQCP_MTU                1200

/* --- Flow control defaults --- */

#define MQCP_DEFAULT_MAX_DATA   (1024 * 1024)  /* 1MB initial receive window */

/* --- Handshake constants --- */

#define MQCP_HS_INITIAL_TIMEOUT_US  1000000    /* 1s initial retransmit timer */
#define MQCP_HS_MAX_RETRIES         5
#define MQCP_HS_TIMEOUT_US          30000000   /* 30s total handshake timeout */
#define MQCP_MAX_HS_FRAGMENTS       8          /* max fragments per HS message */
#define MQCP_HS_FRAGMENT_PAYLOAD    (MQCP_MAX_DATAGRAM - MQCP_LONG_HEADER_LEN)

/* --- Idle timeout --- */

#define MQCP_DEFAULT_IDLE_TIMEOUT_US 30000000  /* 30s */

/* --- Anti-replay --- */

#define MQCP_PN_WINDOW          1024           /* reject PN below largest-1024 */

/* --- Key exhaustion --- */

#define MQCP_MAX_PACKET_NUMBER  0xFFFFFFFFULL  /* 2^32 - enforce key update */

#ifdef __cplusplus
}
#endif

#endif /* MQCP_TYPES_H */
