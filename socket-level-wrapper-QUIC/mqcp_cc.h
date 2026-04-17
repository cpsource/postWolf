/* mqcp_cc.h — RENO congestion control */

#ifndef MQCP_CC_H
#define MQCP_CC_H

#include "mqcp_types.h"

typedef enum {
    MQCP_CC_SLOW_START,
    MQCP_CC_CONGESTION_AVOIDANCE,
    MQCP_CC_RECOVERY
} mqcp_cc_state_t;

typedef struct {
    uint64_t cwnd;                /* congestion window (bytes) */
    uint64_t ssthresh;            /* slow start threshold */
    uint64_t bytes_in_flight;     /* bytes of sent unacked packets */
    uint64_t bytes_acked_accum;   /* accumulator for CA phase */
    mqcp_cc_state_t state;
    uint64_t recovery_start_pn;   /* PN at which recovery started */
} mqcp_cc_t;

/* Initialize to slow start with initial cwnd. */
void mqcp_cc_init(mqcp_cc_t *cc);

/* Called when bytes are newly acknowledged. */
void mqcp_cc_on_ack(mqcp_cc_t *cc, uint64_t bytes_acked);

/* Called when packet loss is detected. pn = lost packet number. */
void mqcp_cc_on_loss(mqcp_cc_t *cc, uint64_t lost_pn, uint64_t bytes_lost);

/* Called when ECN congestion experienced. */
void mqcp_cc_on_ecn_ce(mqcp_cc_t *cc, uint64_t sent_pn);

/* Called when a packet is sent (update bytes_in_flight). */
void mqcp_cc_on_sent(mqcp_cc_t *cc, size_t pkt_len);

/* Called when a packet is acknowledged (update bytes_in_flight). */
void mqcp_cc_on_pkt_acked(mqcp_cc_t *cc, size_t pkt_len);

/* Returns available send window (cwnd - bytes_in_flight), clamped to 0. */
uint64_t mqcp_cc_available(mqcp_cc_t *cc);

#endif /* MQCP_CC_H */
