/* mqcp_packet.h — Packet encoding/decoding and fragment reassembly */

#ifndef MQCP_PACKET_H
#define MQCP_PACKET_H

#include "mqcp_types.h"

/* --- Long header encoding --- */

/* Encode a long header into buf. Returns header length written. */
int mqcp_long_header_encode(uint8_t *buf, size_t buflen,
                            int pkt_type,        /* MQCP_PKT_* */
                            uint32_t conn_id,
                            uint32_t pkt_num,
                            uint8_t msg_type,    /* MQCP_HS_* */
                            uint16_t frag_offset,
                            uint32_t total_len,  /* 24-bit, max 16MB */
                            uint16_t frag_len);

/* Decode a long header from buf. Returns header length consumed, or -1. */
int mqcp_long_header_decode(const uint8_t *buf, size_t buflen,
                            int *pkt_type,
                            uint32_t *conn_id,
                            uint32_t *pkt_num,
                            uint8_t *msg_type,
                            uint16_t *frag_offset,
                            uint32_t *total_len,
                            uint16_t *frag_len);

/* Returns 1 if the first byte indicates a long header (bit 7 set). */
static inline int mqcp_is_long_header(uint8_t first_byte) {
    return (first_byte & 0x80) != 0;
}

/* --- Short header encoding --- */

/* Encode a short header. Returns header length (1 + pn_len bytes). */
int mqcp_short_header_encode(uint8_t *buf, size_t buflen,
                             uint64_t pkt_num, int pn_len);

/* Decode a short header. Returns header length consumed, or -1.
 * pn_len is read from header byte bits 3-2. */
int mqcp_short_header_decode(const uint8_t *buf, size_t buflen,
                             uint64_t *pkt_num, int *pn_len);

/* Determine minimum PN encoding length for given pn and largest_acked. */
int mqcp_pn_encoding_len(uint64_t pkt_num, uint64_t largest_acked);

/* Reconstruct full packet number from truncated value. */
uint64_t mqcp_pn_decode(uint64_t truncated, int pn_len,
                        uint64_t largest_recv);

/* --- Frame encoding --- */

/* Encode STREAM frame header. Returns header length, -1 on error.
 * Caller writes data after header. */
int mqcp_frame_stream_encode(uint8_t *buf, size_t buflen,
                             uint64_t offset, uint16_t data_len);

/* Decode STREAM frame header. Returns header length consumed, -1 on error. */
int mqcp_frame_stream_decode(const uint8_t *buf, size_t buflen,
                             uint64_t *offset, uint16_t *data_len);

/* Encode ACK frame. Returns total frame length, -1 on error.
 * ranges: array of (first, last) pairs, count entries. */
int mqcp_frame_ack_encode(uint8_t *buf, size_t buflen,
                          uint32_t largest_ack, uint16_t ack_delay_us8,
                          const uint64_t *ranges, int range_count);

/* Decode ACK frame. Returns frame length consumed, -1 on error. */
int mqcp_frame_ack_decode(const uint8_t *buf, size_t buflen,
                          uint32_t *largest_ack, uint16_t *ack_delay_us8,
                          uint64_t *ranges, int *range_count,
                          int max_ranges);

/* Encode CLOSE frame. Returns frame length. */
int mqcp_frame_close_encode(uint8_t *buf, size_t buflen,
                            uint32_t error_code,
                            const char *reason, size_t reason_len);

/* Encode MAX_DATA frame. Returns frame length. */
int mqcp_frame_max_data_encode(uint8_t *buf, size_t buflen,
                               uint64_t max_bytes);

/* Encode PING frame. Returns frame length (1). */
int mqcp_frame_ping_encode(uint8_t *buf, size_t buflen);

/* --- Fragment reassembly --- */

#define MQCP_REASSEMBLY_BITMAP_SZ 128  /* supports up to 128 fragments */

typedef struct {
    uint8_t *buf;              /* reassembly buffer (malloc'd, total_len) */
    uint32_t total_len;        /* expected total message length */
    uint32_t received;         /* bytes received so far */
    uint8_t  bitmap[MQCP_REASSEMBLY_BITMAP_SZ]; /* which chunks received */
    int      complete;         /* 1 if all bytes received */
} mqcp_reassembly_t;

/* Initialize reassembly state for a message of given total_len. */
int mqcp_reassembly_init(mqcp_reassembly_t *r, uint32_t total_len);

/* Add a fragment. Returns 1 if message is now complete, 0 if not, -1 error. */
int mqcp_reassembly_add(mqcp_reassembly_t *r,
                        uint16_t offset, const uint8_t *data, uint16_t len);

/* Free reassembly buffer. */
void mqcp_reassembly_free(mqcp_reassembly_t *r);

#endif /* MQCP_PACKET_H */
