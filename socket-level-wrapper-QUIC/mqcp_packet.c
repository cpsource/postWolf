/* mqcp_packet.c — Packet encoding/decoding and fragment reassembly */

#include "mqcp_packet.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* --- Byte helpers --- */

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void put_u24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v);
}

static uint32_t get_u24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_u64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)(v);
}

static uint64_t get_u64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
}

/* --- Long header ---
 *
 * Byte 0:       1TTT00PP  (form=1, type=3bits, reserved=2bits, pnlen=2bits)
 *   But we always use 4-byte PN for long headers, so PP=3.
 * Bytes 1-4:    Connection ID
 * Bytes 5-8:    Packet Number
 * Byte  9:      Handshake Message Type
 * Bytes 10-11:  Fragment Offset
 * Bytes 12-14:  Total Message Length (24-bit)
 * Bytes 15-16:  Fragment Length
 * Total: 17 bytes
 */

int mqcp_long_header_encode(uint8_t *buf, size_t buflen,
                            int pkt_type, uint32_t conn_id,
                            uint32_t pkt_num, uint8_t msg_type,
                            uint16_t frag_offset, uint32_t total_len,
                            uint16_t frag_len) {
    if (buflen < MQCP_LONG_HEADER_LEN) return -1;

    buf[0] = 0x80 | ((pkt_type & 0x07) << 4) | 0x03; /* form=1, pnlen=3 (4 bytes) */
    put_u32(buf + 1, conn_id);
    put_u32(buf + 5, pkt_num);
    buf[9] = msg_type;
    put_u16(buf + 10, frag_offset);
    put_u24(buf + 12, total_len);
    put_u16(buf + 15, frag_len);

    return MQCP_LONG_HEADER_LEN;
}

int mqcp_long_header_decode(const uint8_t *buf, size_t buflen,
                            int *pkt_type, uint32_t *conn_id,
                            uint32_t *pkt_num, uint8_t *msg_type,
                            uint16_t *frag_offset, uint32_t *total_len,
                            uint16_t *frag_len) {
    if (buflen < MQCP_LONG_HEADER_LEN) return -1;
    if (!(buf[0] & 0x80)) return -1; /* not a long header */

    *pkt_type = (buf[0] >> 4) & 0x07;
    *conn_id = get_u32(buf + 1);
    *pkt_num = get_u32(buf + 5);
    *msg_type = buf[9];
    *frag_offset = get_u16(buf + 10);
    *total_len = get_u24(buf + 12);
    *frag_len = get_u16(buf + 15);

    return MQCP_LONG_HEADER_LEN;
}

/* --- Short header ---
 *
 * Byte 0:       0000PPFF  (form=0, PN length in bits 3-2, flags in bits 1-0)
 * Bytes 1..M:   Packet Number (1-4 bytes, length = PP+1)
 */

int mqcp_pn_encoding_len(uint64_t pkt_num, uint64_t largest_acked) {
    uint64_t num_unacked = pkt_num - largest_acked;
    if (num_unacked < 0x80) return 1;
    if (num_unacked < 0x8000) return 2;
    if (num_unacked < 0x800000) return 3;
    return 4;
}

int mqcp_short_header_encode(uint8_t *buf, size_t buflen,
                             uint64_t pkt_num, int pn_len) {
    if (pn_len < 1 || pn_len > 4) return -1;
    size_t hdr_len = 1 + (size_t)pn_len;
    if (buflen < hdr_len) return -1;

    buf[0] = (uint8_t)(((pn_len - 1) & 0x03) << 2);

    /* Write lowest pn_len bytes of pkt_num */
    for (int i = pn_len - 1; i >= 0; i--) {
        buf[1 + i] = (uint8_t)(pkt_num & 0xFF);
        pkt_num >>= 8;
    }

    return (int)hdr_len;
}

int mqcp_short_header_decode(const uint8_t *buf, size_t buflen,
                             uint64_t *pkt_num, int *pn_len) {
    if (buflen < 1) return -1;
    if (buf[0] & 0x80) return -1; /* long header, not short */

    *pn_len = ((buf[0] >> 2) & 0x03) + 1;
    size_t hdr_len = 1 + (size_t)*pn_len;
    if (buflen < hdr_len) return -1;

    uint64_t pn = 0;
    for (int i = 0; i < *pn_len; i++) {
        pn = (pn << 8) | buf[1 + i];
    }
    *pkt_num = pn;

    return (int)hdr_len;
}

uint64_t mqcp_pn_decode(uint64_t truncated, int pn_len,
                        uint64_t largest_recv) {
    uint64_t pn_nbits = (uint64_t)pn_len * 8;
    uint64_t pn_win = (uint64_t)1 << pn_nbits;
    uint64_t pn_hwin = pn_win / 2;
    uint64_t pn_mask = pn_win - 1;

    uint64_t expected = largest_recv + 1;
    uint64_t candidate = (expected & ~pn_mask) | truncated;

    if (expected > pn_hwin &&
        candidate <= expected - pn_hwin &&
        candidate < ((uint64_t)1 << 62) - pn_win) {
        candidate += pn_win;
    } else if (candidate > expected + pn_hwin && candidate >= pn_win) {
        candidate -= pn_win;
    }

    return candidate;
}

/* --- Frame encoding --- */

/* STREAM: type(1) + offset(8) + length(2) + data */
int mqcp_frame_stream_encode(uint8_t *buf, size_t buflen,
                             uint64_t offset, uint16_t data_len) {
    size_t hdr = 1 + 8 + 2; /* type + offset + length */
    if (buflen < hdr) return -1;

    buf[0] = MQCP_FRAME_STREAM;
    put_u64(buf + 1, offset);
    put_u16(buf + 9, data_len);

    return (int)hdr;
}

int mqcp_frame_stream_decode(const uint8_t *buf, size_t buflen,
                             uint64_t *offset, uint16_t *data_len) {
    size_t hdr = 1 + 8 + 2;
    if (buflen < hdr) return -1;
    if (buf[0] != MQCP_FRAME_STREAM) return -1;

    *offset = get_u64(buf + 1);
    *data_len = get_u16(buf + 9);

    return (int)hdr;
}

/* ACK: type(1) + largest(4) + delay(2) + range_count(1) + first_range(2)
 *      + [gap(2) + range(2)] * range_count */
int mqcp_frame_ack_encode(uint8_t *buf, size_t buflen,
                          uint32_t largest_ack, uint16_t ack_delay_us8,
                          const uint64_t *ranges, int range_count) {
    /* ranges[0] = first_ack_range (contiguous below largest)
     * ranges[1] = gap1, ranges[2] = range1, etc. */
    size_t needed = 1 + 4 + 2 + 1 + 2;
    int additional = range_count > 0 ? range_count - 1 : 0;
    needed += (size_t)additional * 4; /* gap(2) + range(2) per additional */
    if (buflen < needed) return -1;

    size_t pos = 0;
    buf[pos++] = MQCP_FRAME_ACK;
    put_u32(buf + pos, largest_ack); pos += 4;
    put_u16(buf + pos, ack_delay_us8); pos += 2;
    buf[pos++] = (uint8_t)(additional > 255 ? 255 : additional);
    put_u16(buf + pos, range_count > 0 ? (uint16_t)ranges[0] : 0); pos += 2;

    for (int i = 0; i < additional; i++) {
        put_u16(buf + pos, (uint16_t)ranges[1 + i * 2]); pos += 2;     /* gap */
        put_u16(buf + pos, (uint16_t)ranges[1 + i * 2 + 1]); pos += 2; /* range */
    }

    return (int)pos;
}

int mqcp_frame_ack_decode(const uint8_t *buf, size_t buflen,
                          uint32_t *largest_ack, uint16_t *ack_delay_us8,
                          uint64_t *ranges, int *range_count,
                          int max_ranges) {
    if (buflen < 10) return -1;
    if (buf[0] != MQCP_FRAME_ACK) return -1;

    size_t pos = 1;
    *largest_ack = get_u32(buf + pos); pos += 4;
    *ack_delay_us8 = get_u16(buf + pos); pos += 2;
    int additional = buf[pos++];
    *range_count = 1 + additional;

    if (buflen < pos + 2 + (size_t)additional * 4) return -1;

    ranges[0] = get_u16(buf + pos); pos += 2;
    int count = additional < max_ranges - 1 ? additional : max_ranges - 1;
    for (int i = 0; i < count; i++) {
        ranges[1 + i * 2] = get_u16(buf + pos); pos += 2;
        ranges[1 + i * 2 + 1] = get_u16(buf + pos); pos += 2;
    }
    /* Skip any we couldn't store */
    pos += (size_t)(additional - count) * 4;

    return (int)pos;
}

int mqcp_frame_close_encode(uint8_t *buf, size_t buflen,
                            uint32_t error_code,
                            const char *reason, size_t reason_len) {
    size_t needed = 1 + 4 + 2 + reason_len;
    if (buflen < needed) return -1;

    size_t pos = 0;
    buf[pos++] = MQCP_FRAME_CLOSE;
    put_u32(buf + pos, error_code); pos += 4;
    put_u16(buf + pos, (uint16_t)reason_len); pos += 2;
    if (reason_len > 0) {
        memcpy(buf + pos, reason, reason_len);
        pos += reason_len;
    }

    return (int)pos;
}

int mqcp_frame_max_data_encode(uint8_t *buf, size_t buflen,
                               uint64_t max_bytes) {
    if (buflen < 9) return -1;
    buf[0] = MQCP_FRAME_MAX_DATA;
    put_u64(buf + 1, max_bytes);
    return 9;
}

int mqcp_frame_ping_encode(uint8_t *buf, size_t buflen) {
    if (buflen < 1) return -1;
    buf[0] = MQCP_FRAME_PING;
    return 1;
}

/* --- Fragment reassembly --- */

int mqcp_reassembly_init(mqcp_reassembly_t *r, uint32_t total_len) {
    memset(r, 0, sizeof(*r));
    r->buf = (uint8_t *)calloc(1, total_len);
    if (!r->buf) return -1;
    r->total_len = total_len;
    return 0;
}

int mqcp_reassembly_add(mqcp_reassembly_t *r,
                        uint16_t offset, const uint8_t *data, uint16_t len) {
    if (r->complete) return 1;
    if (!r->buf) return -1;
    if ((uint32_t)offset + len > r->total_len) return -1;

    /* Track which fragment chunks we've received using a simple bitmap.
     * Each bit represents one byte of the reassembly buffer grouped into
     * MQCP_HS_FRAGMENT_PAYLOAD-sized chunks for efficiency. */
    size_t chunk_size = MQCP_HS_FRAGMENT_PAYLOAD;
    size_t first_chunk = offset / chunk_size;
    size_t last_chunk = (offset + len - 1) / chunk_size;

    for (size_t c = first_chunk; c <= last_chunk && c < MQCP_REASSEMBLY_BITMAP_SZ * 8; c++) {
        size_t byte_idx = c / 8;
        uint8_t bit = (uint8_t)(1 << (c % 8));
        if (r->bitmap[byte_idx] & bit) {
            /* Already have this chunk — skip the overlapping portion */
            continue;
        }
        r->bitmap[byte_idx] |= bit;
    }

    /* Copy data (may partially overlap with already-received data) */
    memcpy(r->buf + offset, data, len);
    r->received += len;

    if (r->received >= r->total_len) {
        r->complete = 1;
        return 1;
    }
    return 0;
}

void mqcp_reassembly_free(mqcp_reassembly_t *r) {
    free(r->buf);
    memset(r, 0, sizeof(*r));
}
