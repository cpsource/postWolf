/* mqcp_handshake.h — Handshake state machine over UDP */

#ifndef MQCP_HANDSHAKE_H
#define MQCP_HANDSHAKE_H

#include "mqcp_types.h"
#include "mqcp_packet.h"

/* Forward declarations */
struct mqcp_conn;
struct mqcp_ctx;

typedef enum {
    MQCP_HS_IDLE,
    MQCP_HS_CLIENT_INITIAL_SENT,
    MQCP_HS_CLIENT_WAIT_SERVER,
    MQCP_HS_CLIENT_PROCESSING,
    MQCP_HS_SERVER_ASSEMBLING,
    MQCP_HS_SERVER_PROCESSING,
    MQCP_HS_SERVER_RESPONDING,
    MQCP_HS_COMPLETE,
    MQCP_HS_FAILED
} mqcp_hs_state_t;

/* Opaque handshake state — defined in mqcp_handshake.c because
 * it contains wolfSSL types (MlKemKey, WC_RNG) whose size is
 * not available from the public headers alone. */
typedef struct mqcp_handshake mqcp_handshake_t;

/* Allocate and initialize handshake state. Returns NULL on failure. */
mqcp_handshake_t *mqcp_handshake_new(void);

/* Free handshake resources. */
void mqcp_handshake_free(mqcp_handshake_t *hs);

/* Client: start handshake by sending ClientHello.
 * Returns 0 on success, -1 on error. */
int mqcp_handshake_client_start(mqcp_handshake_t *hs,
                                struct mqcp_ctx *ctx,
                                struct mqcp_conn *conn);

/* Process a received handshake packet.
 * Returns 0 if handshake still in progress, 1 if complete, -1 on error. */
int mqcp_handshake_on_recv(mqcp_handshake_t *hs,
                           struct mqcp_ctx *ctx,
                           struct mqcp_conn *conn,
                           const uint8_t *data, size_t len,
                           uint64_t now_us);

/* Check for timeouts and retransmissions.
 * Returns 0 on success, MQCP_ERR_TIMEOUT if handshake timed out. */
int mqcp_handshake_check_timers(mqcp_handshake_t *hs,
                                struct mqcp_conn *conn,
                                uint64_t now_us);

/* Get next handshake timer deadline. Returns 0 if none. */
uint64_t mqcp_handshake_next_timer(mqcp_handshake_t *hs);

/* --- Accessors for opaque handshake fields --- */

mqcp_hs_state_t mqcp_handshake_state(mqcp_handshake_t *hs);
int  mqcp_handshake_has_secret(mqcp_handshake_t *hs);
const uint8_t *mqcp_handshake_shared_secret(mqcp_handshake_t *hs);
int  mqcp_handshake_peer_index(mqcp_handshake_t *hs);

#endif /* MQCP_HANDSHAKE_H */
