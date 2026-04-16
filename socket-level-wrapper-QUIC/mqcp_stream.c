/* mqcp_stream.c — Send/receive stream buffers with reordering */

#include "mqcp_stream.h"

#include <stdlib.h>
#include <string.h>

/* --- Send stream --- */

int mqcp_send_stream_init(mqcp_send_stream_t *s, size_t capacity) {
    memset(s, 0, sizeof(*s));
    s->buf = (uint8_t *)malloc(capacity);
    if (!s->buf) return -1;
    s->capacity = capacity;
    return 0;
}

void mqcp_send_stream_free(mqcp_send_stream_t *s) {
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

size_t mqcp_send_stream_write(mqcp_send_stream_t *s,
                              const void *data, size_t len) {
    size_t avail = s->capacity - s->len;
    if (len > avail) len = avail;
    if (len == 0) return 0;

    /* Write into circular buffer at write_offset position */
    size_t buf_pos = (size_t)(s->write_offset % s->capacity);
    size_t first = s->capacity - buf_pos;
    if (first > len) first = len;

    memcpy(s->buf + buf_pos, data, first);
    if (len > first) {
        memcpy(s->buf, (const uint8_t *)data + first, len - first);
    }

    s->write_offset += len;
    s->len += len;
    return len;
}

size_t mqcp_send_stream_peek(mqcp_send_stream_t *s,
                             const uint8_t **data_out, size_t max_len) {
    uint64_t unsent = s->write_offset - s->send_offset;
    if (unsent == 0) { *data_out = NULL; return 0; }

    size_t avail = (size_t)unsent;
    if (avail > max_len) avail = max_len;

    size_t buf_pos = (size_t)(s->send_offset % s->capacity);
    /* Can only return contiguous chunk up to end of circular buffer */
    size_t contiguous = s->capacity - buf_pos;
    if (avail > contiguous) avail = contiguous;

    *data_out = s->buf + buf_pos;
    return avail;
}

void mqcp_send_stream_advance(mqcp_send_stream_t *s, size_t len) {
    s->send_offset += len;
}

void mqcp_send_stream_ack(mqcp_send_stream_t *s,
                          uint64_t offset, size_t len) {
    uint64_t end = offset + len;
    if (end > s->acked_offset) {
        /* For simplicity: advance acked_offset to the end.
         * A more precise implementation would track ACK ranges,
         * but with single-stream in-order this is sufficient. */
        size_t freed = (size_t)(end - s->acked_offset);
        s->acked_offset = end;
        if (s->len >= freed) {
            s->len -= freed;
        } else {
            s->len = 0;
        }
    }
}

void mqcp_send_stream_retransmit(mqcp_send_stream_t *s,
                                 uint64_t offset, size_t len) {
    /* Rewind send_offset to re-send lost data */
    if (offset < s->send_offset) {
        s->send_offset = offset;
    }
    (void)len;
}

size_t mqcp_send_stream_pending(mqcp_send_stream_t *s) {
    if (s->write_offset <= s->send_offset) return 0;
    return (size_t)(s->write_offset - s->send_offset);
}

/* --- Receive stream --- */

int mqcp_recv_stream_init(mqcp_recv_stream_t *s, size_t capacity) {
    memset(s, 0, sizeof(*s));
    s->buf = (uint8_t *)calloc(1, capacity);
    if (!s->buf) return -1;
    s->capacity = capacity;
    return 0;
}

void mqcp_recv_stream_free(mqcp_recv_stream_t *s) {
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

static void merge_ranges(mqcp_recv_stream_t *s) {
    if (s->range_count < 2) return;

    /* Sort by start */
    for (int i = 0; i < s->range_count - 1; i++) {
        for (int j = i + 1; j < s->range_count; j++) {
            if (s->ranges[j].start < s->ranges[i].start) {
                mqcp_recv_range_t tmp = s->ranges[i];
                s->ranges[i] = s->ranges[j];
                s->ranges[j] = tmp;
            }
        }
    }

    /* Merge overlapping */
    int out = 0;
    for (int i = 1; i < s->range_count; i++) {
        if (s->ranges[i].start <= s->ranges[out].end) {
            if (s->ranges[i].end > s->ranges[out].end) {
                s->ranges[out].end = s->ranges[i].end;
            }
        } else {
            out++;
            s->ranges[out] = s->ranges[i];
        }
    }
    s->range_count = out + 1;

    /* Update contiguous_offset */
    if (s->range_count > 0 && s->ranges[0].start <= s->contiguous_offset) {
        if (s->ranges[0].end > s->contiguous_offset) {
            s->contiguous_offset = s->ranges[0].end;
        }
        /* Remove the first range if it's now contiguous */
        if (s->ranges[0].end <= s->contiguous_offset) {
            s->range_count--;
            for (int i = 0; i < s->range_count; i++) {
                s->ranges[i] = s->ranges[i + 1];
            }
        }
    }
}

int mqcp_recv_stream_insert(mqcp_recv_stream_t *s,
                            uint64_t offset, const uint8_t *data, size_t len) {
    if (len == 0) return 0;

    uint64_t end = offset + len;

    /* Bounds check: don't exceed receive window */
    if (end > s->read_offset + s->capacity) return -1;

    /* Copy data into circular buffer */
    size_t buf_pos = (size_t)(offset % s->capacity);
    size_t first = s->capacity - buf_pos;
    if (first > len) first = len;
    memcpy(s->buf + buf_pos, data, first);
    if (len > first) {
        memcpy(s->buf, data + first, len - first);
    }

    /* If this extends the contiguous range */
    if (offset <= s->contiguous_offset && end > s->contiguous_offset) {
        s->contiguous_offset = end;
    } else if (offset > s->contiguous_offset) {
        /* Out-of-order: add to ranges */
        if (s->range_count < 64) {
            s->ranges[s->range_count].start = offset;
            s->ranges[s->range_count].end = end;
            s->range_count++;
        }
    }

    merge_ranges(s);
    return 0;
}

size_t mqcp_recv_stream_read(mqcp_recv_stream_t *s,
                             void *buf, size_t len) {
    size_t avail = mqcp_recv_stream_available(s);
    if (avail == 0) return 0;
    if (len > avail) len = avail;

    size_t buf_pos = (size_t)(s->read_offset % s->capacity);
    size_t first = s->capacity - buf_pos;
    if (first > len) first = len;

    memcpy(buf, s->buf + buf_pos, first);
    if (len > first) {
        memcpy((uint8_t *)buf + first, s->buf, len - first);
    }

    s->read_offset += len;
    return len;
}

size_t mqcp_recv_stream_available(mqcp_recv_stream_t *s) {
    if (s->contiguous_offset <= s->read_offset) return 0;
    return (size_t)(s->contiguous_offset - s->read_offset);
}
