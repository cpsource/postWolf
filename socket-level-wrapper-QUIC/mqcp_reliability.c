/* mqcp_reliability.c — ACK processing, retransmission, loss detection, RTT */

#include "mqcp_reliability.h"

#include <stdlib.h>
#include <string.h>

/* --- RTT --- */

void mqcp_rtt_init(mqcp_rtt_t *rtt) {
    memset(rtt, 0, sizeof(*rtt));
    rtt->smoothed_us = MQCP_INITIAL_RTT_US;
    rtt->variance_us = MQCP_INITIAL_RTT_US / 2;
    rtt->min_us = UINT64_MAX;
}

void mqcp_rtt_update(mqcp_rtt_t *rtt, uint64_t sample_us,
                     uint64_t ack_delay_us) {
    if (sample_us < rtt->min_us) {
        rtt->min_us = sample_us;
    }

    rtt->latest_us = sample_us;

    /* Subtract ack_delay if sample is above min_rtt */
    uint64_t adjusted = sample_us;
    if (adjusted > rtt->min_us + ack_delay_us) {
        adjusted -= ack_delay_us;
    }

    if (!rtt->has_sample) {
        rtt->smoothed_us = adjusted;
        rtt->variance_us = adjusted / 2;
        rtt->has_sample = 1;
        return;
    }

    /* EWMA update */
    uint64_t diff = adjusted > rtt->smoothed_us
                        ? adjusted - rtt->smoothed_us
                        : rtt->smoothed_us - adjusted;
    rtt->variance_us = (3 * rtt->variance_us + diff) / 4;
    rtt->smoothed_us = (7 * rtt->smoothed_us + adjusted) / 8;
}

/* --- Retransmission buffer --- */

void mqcp_rtb_init(mqcp_rtb_t *rtb) {
    memset(rtb, 0, sizeof(*rtb));
}

void mqcp_rtb_add(mqcp_rtb_t *rtb, mqcp_sent_pkt_t *pkt) {
    pkt->next = NULL;
    if (!rtb->head) {
        rtb->head = pkt;
    } else {
        /* Append at tail (PNs are monotonically increasing) */
        mqcp_sent_pkt_t *tail = rtb->head;
        while (tail->next) tail = tail->next;
        tail->next = pkt;
    }
    rtb->count++;
}

static int pn_is_acked(uint64_t pn, uint32_t largest_ack,
                       const uint64_t *ranges, int range_count) {
    /* First range: largest_ack - ranges[0] .. largest_ack */
    if (range_count < 1) return 0;

    uint64_t lo = (uint64_t)largest_ack - ranges[0];
    uint64_t hi = (uint64_t)largest_ack;
    if (pn >= lo && pn <= hi) return 1;

    /* Additional ranges */
    uint64_t bottom = lo;
    for (int i = 0; i < range_count - 1; i++) {
        uint64_t gap = ranges[1 + i * 2];
        uint64_t rlen = ranges[1 + i * 2 + 1];
        if (bottom < gap + 2) break;
        bottom = bottom - gap - 2;
        hi = bottom;
        lo = bottom - rlen;
        if (pn >= lo && pn <= hi) return 1;
        bottom = lo;
    }
    return 0;
}

int mqcp_rtb_on_ack(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                    uint32_t largest_ack, uint16_t ack_delay_us8,
                    const uint64_t *ranges, int range_count,
                    uint64_t now_us,
                    uint64_t *bytes_acked_out,
                    mqcp_lost_cb lost_cb, void *lost_ctx) {
    uint64_t ack_delay_us = (uint64_t)ack_delay_us8 * 8;
    int acked = 0;
    uint64_t bytes_acked = 0;
    int got_rtt_sample = 0;

    /* Update largest acked */
    if ((uint64_t)largest_ack > rtb->largest_acked_pn) {
        rtb->largest_acked_pn = largest_ack;
    }

    /* Walk the sent list, remove acked packets */
    mqcp_sent_pkt_t **pp = &rtb->head;
    while (*pp) {
        mqcp_sent_pkt_t *p = *pp;
        if (pn_is_acked(p->pn, largest_ack, ranges, range_count)) {
            /* RTT sample from the largest newly acked */
            if (p->pn == (uint64_t)largest_ack && !got_rtt_sample) {
                uint64_t sample = now_us - p->sent_time_us;
                mqcp_rtt_update(rtt, sample, ack_delay_us);
                rtb->largest_acked_sent_time = p->sent_time_us;
                got_rtt_sample = 1;
            }
            if (p->in_flight) {
                bytes_acked += p->pkt_len;
            }
            *pp = p->next;
            free(p);
            rtb->count--;
            acked++;
        } else {
            pp = &p->next;
        }
    }

    *bytes_acked_out = bytes_acked;

    /* Detect lost packets now that we have updated largest_acked */
    uint64_t bytes_lost = 0;
    mqcp_rtb_detect_lost(rtb, rtt, now_us, &bytes_lost, lost_cb, lost_ctx);

    return acked;
}

int mqcp_rtb_detect_lost(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                         uint64_t now_us,
                         uint64_t *bytes_lost_out,
                         mqcp_lost_cb lost_cb, void *lost_ctx) {
    uint64_t loss_delay = rtt->latest_us;
    if (rtt->smoothed_us > loss_delay) loss_delay = rtt->smoothed_us;
    loss_delay = loss_delay * MQCP_TIME_THRESHOLD_NUM / MQCP_TIME_THRESHOLD_DEN;
    if (loss_delay < MQCP_TIMER_GRANULARITY_US) {
        loss_delay = MQCP_TIMER_GRANULARITY_US;
    }

    uint64_t bytes_lost = 0;
    int lost_count = 0;

    mqcp_sent_pkt_t **pp = &rtb->head;
    while (*pp) {
        mqcp_sent_pkt_t *p = *pp;
        if (p->pn > rtb->largest_acked_pn) {
            pp = &p->next;
            continue;
        }

        int is_lost = 0;

        /* Packet threshold: lost if 3+ later packets acked */
        if (rtb->largest_acked_pn >= p->pn + MQCP_PKT_THRESHOLD) {
            is_lost = 1;
        }

        /* Time threshold */
        if (now_us >= p->sent_time_us + loss_delay) {
            is_lost = 1;
        }

        if (is_lost) {
            if (lost_cb && p->stream_len > 0) {
                lost_cb(p->stream_offset, p->stream_len, lost_ctx);
            }
            if (p->in_flight) {
                bytes_lost += p->pkt_len;
            }
            *pp = p->next;
            free(p);
            rtb->count--;
            lost_count++;
        } else {
            pp = &p->next;
        }
    }

    *bytes_lost_out = bytes_lost;
    return lost_count;
}

uint64_t mqcp_rtb_pto_deadline(mqcp_rtb_t *rtb, mqcp_rtt_t *rtt,
                               int pto_count) {
    /* Find earliest ack-eliciting packet */
    mqcp_sent_pkt_t *earliest = NULL;
    for (mqcp_sent_pkt_t *p = rtb->head; p; p = p->next) {
        if (p->ack_eliciting) {
            earliest = p;
            break;
        }
    }
    if (!earliest) return 0;

    uint64_t pto = rtt->smoothed_us + 4 * rtt->variance_us;
    if (pto < MQCP_TIMER_GRANULARITY_US) pto = MQCP_TIMER_GRANULARITY_US;
    pto += MQCP_MAX_ACK_DELAY_US;

    /* Exponential backoff */
    for (int i = 0; i < pto_count; i++) {
        pto *= 2;
    }

    return earliest->sent_time_us + pto;
}

void mqcp_rtb_free(mqcp_rtb_t *rtb) {
    mqcp_sent_pkt_t *p = rtb->head;
    while (p) {
        mqcp_sent_pkt_t *next = p->next;
        free(p);
        p = next;
    }
    memset(rtb, 0, sizeof(*rtb));
}

/* --- ACK tracker --- */

void mqcp_ack_tracker_init(mqcp_ack_tracker_t *at) {
    memset(at, 0, sizeof(*at));
}

void mqcp_ack_tracker_add(mqcp_ack_tracker_t *at, uint64_t pn,
                          int ack_eliciting, uint64_t now_us) {
    /* Store in ring buffer */
    if (at->count < 256) {
        int idx = (at->head + at->count) % 256;
        at->pns[idx] = pn;
        at->count++;
    }

    if (pn > at->largest_recv_pn || at->largest_recv_pn == 0) {
        at->largest_recv_pn = pn;
        at->largest_recv_time = now_us;
    }

    if (ack_eliciting) {
        at->ack_eliciting_since_ack++;
        if (at->ack_timer_deadline == 0) {
            at->ack_timer_deadline = now_us + MQCP_MAX_ACK_DELAY_US;
        }
    }
}

int mqcp_ack_tracker_should_ack(mqcp_ack_tracker_t *at, uint64_t now_us) {
    if (at->count == 0) return 0;

    /* Immediate ACK after threshold */
    if (at->ack_eliciting_since_ack >= MQCP_ACK_ELICITING_THRESHOLD) return 1;

    /* Delayed ACK timer expired */
    if (at->ack_timer_deadline != 0 && now_us >= at->ack_timer_deadline) return 1;

    return 0;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

int mqcp_ack_tracker_build_ranges(mqcp_ack_tracker_t *at,
                                  uint32_t *largest_ack,
                                  uint16_t *ack_delay_us8,
                                  uint64_t *ranges, int max_ranges,
                                  uint64_t now_us) {
    if (at->count == 0) return 0;

    /* Sort received PNs */
    uint64_t sorted[256];
    for (int i = 0; i < at->count; i++) {
        sorted[i] = at->pns[(at->head + i) % 256];
    }
    qsort(sorted, (size_t)at->count, sizeof(uint64_t), cmp_u64);

    /* Remove duplicates */
    int n = 1;
    for (int i = 1; i < at->count; i++) {
        if (sorted[i] != sorted[i - 1]) {
            sorted[n++] = sorted[i];
        }
    }

    *largest_ack = (uint32_t)sorted[n - 1];
    uint64_t delay = now_us > at->largest_recv_time
                         ? now_us - at->largest_recv_time
                         : 0;
    *ack_delay_us8 = (uint16_t)(delay / 8);
    if (delay / 8 > 65535) *ack_delay_us8 = 65535;

    /* Build ranges: walk from highest to lowest */
    int range_idx = 0;
    uint64_t hi = sorted[n - 1];
    uint64_t lo = hi;

    for (int i = n - 2; i >= 0 && range_idx < max_ranges; i--) {
        if (sorted[i] == lo - 1) {
            lo = sorted[i];
        } else {
            /* End of contiguous range */
            if (range_idx == 0) {
                ranges[0] = hi - lo; /* first ack range */
            } else {
                uint64_t gap = lo - sorted[i] - 2;
                ranges[1 + (range_idx - 1) * 2] = gap;
                uint64_t new_hi = sorted[i];
                /* Find extent of this new range */
                uint64_t new_lo = new_hi;
                while (i > 0 && sorted[i - 1] == new_lo - 1) {
                    new_lo = sorted[--i];
                }
                ranges[1 + (range_idx - 1) * 2 + 1] = new_hi - new_lo;
            }
            range_idx++;
            hi = sorted[i];
            lo = hi;
        }
    }

    /* Final range */
    if (range_idx == 0) {
        ranges[0] = hi - lo;
        range_idx = 1;
    }

    return range_idx;
}

void mqcp_ack_tracker_on_ack_sent(mqcp_ack_tracker_t *at) {
    at->ack_eliciting_since_ack = 0;
    at->ack_timer_deadline = 0;
}
