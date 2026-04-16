/* mqcp_reliability.h — ACK processing, retransmission, loss detection, RTT */

#ifndef MQCP_RELIABILITY_H
#define MQCP_RELIABILITY_H

#include "mqcp_types.h"

/* Sent packet entry for retransmission tracking. */
typedef struct mqcp_sent_pkt {
    uint64_t pn;                  /* packet number */
    uint64_t sent_time_us;        /* when sent (monotonic us) */
    uint64_t stream_offset;       /* stream byte offset of STREAM frame */
    size_t   stream_len;          /* bytes of stream data in this packet */
    size_t   pkt_len;             /* total datagram size (for CC) */
    int      ack_eliciting;       /* 1 if STREAM/PING (not pure ACK) */
    int      in_flight;           /* 1 if counts toward bytes_in_flight */
    struct mqcp_sent_pkt *next;
} mqcp_sent_pkt_t;

/* RTT estimator state. */
typedef struct {
    uint64_t smoothed_us;         /* smoothed RTT */
    uint64_t variance_us;         /* RTT variance */
    uint64_t min_us;              /* minimum RTT seen */
    uint64_t latest_us;           /* most recent sample */
    int      has_sample;          /* 1 after first sample */
} mqcp_rtt_t;

/* Retransmission buffer: linked list of sent packets. */
typedef struct {
    mqcp_sent_pkt_t *head;        /* oldest first */
    size_t count;                 /* number of entries */
    uint64_t largest_acked_pn;    /* largest PN ACKed by peer */
    uint64_t largest_acked_sent_time; /* sent_time of largest_acked_pn */
} mqcp_rtb_t;

/* Received PN tracker for ACK generation. */
typedef struct {
    uint64_t pns[256];            /* ring buffer of received PNs */
    int      count;
    int      head;
    uint64_t largest_recv_pn;     /* largest PN received */
    uint64_t largest_recv_time;   /* when largest was received */
    int      ack_eliciting_since_ack; /* count of ack-eliciting since last ACK sent */
    uint64_t ack_timer_deadline;  /* delayed ACK timer deadline (0 = not set) */
} mqcp_ack_tracker_t;

/* --- RTT --- */

void mqcp_rtt_init(mqcp_rtt_t *rtt);
void mqcp_rtt_update(mqcp_rtt_t *rtt, uint64_t sample_us, uint64_t ack_delay_us);

/* --- Retransmission buffer --- */

void mqcp_rtb_init(mqcp_rtb_t *rtb);
void mqcp_rtb_add(mqcp_rtb_t *rtb, mqcp_sent_pkt_t *pkt);

/* Process an ACK. Removes acknowledged packets, updates RTT.
 * Calls back with lost packets via lost_cb(stream_offset, stream_len, ctx).
 * Returns number of newly acknowledged packets, or -1 on error. */
typedef void (*mqcp_lost_cb)(uint64_t stream_offset, size_t stream_len,
                             void *ctx);
int mqcp_rtb_on_ack(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                    uint32_t largest_ack, uint16_t ack_delay_us8,
                    const uint64_t *ranges, int range_count,
                    uint64_t now_us,
                    uint64_t *bytes_acked_out,
                    mqcp_lost_cb lost_cb, void *lost_ctx);

/* Detect lost packets based on time and packet thresholds.
 * Returns number of packets declared lost. */
int mqcp_rtb_detect_lost(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                         uint64_t now_us,
                         uint64_t *bytes_lost_out,
                         mqcp_lost_cb lost_cb, void *lost_ctx);

/* Compute PTO deadline. Returns 0 if no ack-eliciting in flight. */
uint64_t mqcp_rtb_pto_deadline(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                               int pto_count);

/* Free all entries. */
void mqcp_rtb_free(mqcp_rtb_t *rtb);

/* --- ACK tracker --- */

void mqcp_ack_tracker_init(mqcp_ack_tracker_t *at);

/* Record a received packet number. */
void mqcp_ack_tracker_add(mqcp_ack_tracker_t *at, uint64_t pn,
                          int ack_eliciting, uint64_t now_us);

/* Returns 1 if an ACK should be sent now. */
int mqcp_ack_tracker_should_ack(mqcp_ack_tracker_t *at, uint64_t now_us);

/* Build ACK ranges from tracked PNs. Returns range count. */
int mqcp_ack_tracker_build_ranges(mqcp_ack_tracker_t *at,
                                  uint32_t *largest_ack,
                                  uint16_t *ack_delay_us8,
                                  uint64_t *ranges, int max_ranges,
                                  uint64_t now_us);

/* Mark that an ACK was sent. */
void mqcp_ack_tracker_on_ack_sent(mqcp_ack_tracker_t *at);

#endif /* MQCP_RELIABILITY_H */
