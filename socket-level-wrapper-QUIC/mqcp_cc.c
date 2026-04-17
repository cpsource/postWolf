/* mqcp_cc.c — RENO congestion control */

#include "mqcp_cc.h"

void mqcp_cc_init(mqcp_cc_t *cc) {
    cc->cwnd = MQCP_INITIAL_CWND;
    cc->ssthresh = UINT64_MAX;
    cc->bytes_in_flight = 0;
    cc->bytes_acked_accum = 0;
    cc->state = MQCP_CC_SLOW_START;
    cc->recovery_start_pn = 0;
}

void mqcp_cc_on_ack(mqcp_cc_t *cc, uint64_t bytes_acked) {
    switch (cc->state) {
    case MQCP_CC_SLOW_START:
        cc->cwnd += bytes_acked;
        if (cc->cwnd >= cc->ssthresh) {
            cc->state = MQCP_CC_CONGESTION_AVOIDANCE;
            cc->bytes_acked_accum = 0;
        }
        break;

    case MQCP_CC_CONGESTION_AVOIDANCE:
        cc->bytes_acked_accum += bytes_acked;
        if (cc->bytes_acked_accum >= cc->cwnd) {
            cc->cwnd += MQCP_MTU;
            cc->bytes_acked_accum -= cc->cwnd;
        }
        break;

    case MQCP_CC_RECOVERY:
        /* Do not increase cwnd during recovery */
        break;
    }
}

void mqcp_cc_on_loss(mqcp_cc_t *cc, uint64_t lost_pn, uint64_t bytes_lost) {
    (void)bytes_lost;

    /* Only enter recovery once per event */
    if (cc->state == MQCP_CC_RECOVERY && lost_pn <= cc->recovery_start_pn) {
        return;
    }

    cc->ssthresh = cc->cwnd / 2;
    if (cc->ssthresh < MQCP_MIN_CWND) {
        cc->ssthresh = MQCP_MIN_CWND;
    }
    cc->cwnd = cc->ssthresh;
    cc->state = MQCP_CC_RECOVERY;
    cc->recovery_start_pn = lost_pn;
    cc->bytes_acked_accum = 0;
}

void mqcp_cc_on_ecn_ce(mqcp_cc_t *cc, uint64_t sent_pn) {
    /* Treat ECN congestion experienced same as loss */
    mqcp_cc_on_loss(cc, sent_pn, 0);
}

void mqcp_cc_on_sent(mqcp_cc_t *cc, size_t pkt_len) {
    cc->bytes_in_flight += pkt_len;
}

void mqcp_cc_on_pkt_acked(mqcp_cc_t *cc, size_t pkt_len) {
    if (cc->bytes_in_flight >= pkt_len) {
        cc->bytes_in_flight -= pkt_len;
    } else {
        cc->bytes_in_flight = 0;
    }

    /* Exit recovery if all recovery packets are acked */
    if (cc->state == MQCP_CC_RECOVERY && cc->bytes_in_flight == 0) {
        cc->state = MQCP_CC_CONGESTION_AVOIDANCE;
        cc->bytes_acked_accum = 0;
    }
}

uint64_t mqcp_cc_available(mqcp_cc_t *cc) {
    if (cc->bytes_in_flight >= cc->cwnd) return 0;
    return cc->cwnd - cc->bytes_in_flight;
}
