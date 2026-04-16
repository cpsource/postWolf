/* mqcp_stream.h — Send/receive stream buffers with reordering */

#ifndef MQCP_STREAM_H
#define MQCP_STREAM_H

#include "mqcp_types.h"

/* Send buffer: application writes here, packets pull from here. */
typedef struct {
    uint8_t *buf;                 /* circular buffer */
    size_t   capacity;
    size_t   len;                 /* bytes currently buffered */
    uint64_t write_offset;        /* next app write offset */
    uint64_t send_offset;         /* next offset to send on wire */
    uint64_t acked_offset;        /* highest contiguous acked offset */
    int      fin;                 /* 1 if app has closed writing */
} mqcp_send_stream_t;

/* Out-of-order range for receive reassembly. */
typedef struct {
    uint64_t start;
    uint64_t end;                 /* exclusive */
} mqcp_recv_range_t;

/* Receive buffer: packets deposit here, application reads from here. */
typedef struct {
    uint8_t *buf;                 /* circular buffer */
    size_t   capacity;
    uint64_t read_offset;         /* next byte to deliver to app */
    uint64_t contiguous_offset;   /* highest contiguous byte received */
    mqcp_recv_range_t ranges[64]; /* out-of-order ranges */
    int      range_count;
    int      fin;                 /* 1 if FIN received */
    uint64_t fin_offset;          /* stream offset of FIN */
} mqcp_recv_stream_t;

/* --- Send stream --- */

int  mqcp_send_stream_init(mqcp_send_stream_t *s, size_t capacity);
void mqcp_send_stream_free(mqcp_send_stream_t *s);

/* Buffer data from application. Returns bytes accepted. */
size_t mqcp_send_stream_write(mqcp_send_stream_t *s,
                              const void *data, size_t len);

/* Get pointer to unsent data starting at send_offset.
 * Returns length available (may be less than requested). */
size_t mqcp_send_stream_peek(mqcp_send_stream_t *s,
                             const uint8_t **data_out, size_t max_len);

/* Advance send_offset after data has been packetized. */
void mqcp_send_stream_advance(mqcp_send_stream_t *s, size_t len);

/* Mark bytes as acknowledged. Frees buffer space. */
void mqcp_send_stream_ack(mqcp_send_stream_t *s,
                          uint64_t offset, size_t len);

/* Re-queue lost data for retransmission by rewinding send_offset. */
void mqcp_send_stream_retransmit(mqcp_send_stream_t *s,
                                 uint64_t offset, size_t len);

/* Returns bytes available to send (send_offset - acked_offset limit). */
size_t mqcp_send_stream_pending(mqcp_send_stream_t *s);

/* --- Receive stream --- */

int  mqcp_recv_stream_init(mqcp_recv_stream_t *s, size_t capacity);
void mqcp_recv_stream_free(mqcp_recv_stream_t *s);

/* Insert received data at given offset. Handles out-of-order, duplicates.
 * Returns 0 on success, -1 on error (e.g., exceeds window). */
int mqcp_recv_stream_insert(mqcp_recv_stream_t *s,
                            uint64_t offset, const uint8_t *data, size_t len);

/* Read contiguous data from the stream. Returns bytes read. */
size_t mqcp_recv_stream_read(mqcp_recv_stream_t *s,
                             void *buf, size_t len);

/* Returns number of contiguous bytes available to read. */
size_t mqcp_recv_stream_available(mqcp_recv_stream_t *s);

#endif /* MQCP_STREAM_H */
