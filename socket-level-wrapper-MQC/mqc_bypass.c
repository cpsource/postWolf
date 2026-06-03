/******************************************************************************
 * File:        mqc_bypass.c
 * Purpose:     MQCBYPASS token encode/decode + HMAC-SHA256 validation.
 *
 * Description:
 *   The bypass token lets an operator skip selected pre-handshake gates
 *   on the server for a single connection by proving knowledge of a
 *   shared master password.  Wire format (full 99-byte line):
 *
 *     "MQCBYPASS:" || hex(8B ts_be || 4B mask_be || 32B hmac) || "\n"
 *
 *   hmac = HMAC-SHA256(master_password,
 *                      "mqc-bypass:" || ts_be || mask_be || src_ip_str)
 *
 *   - ts_be       : uint64 unix seconds, big-endian
 *   - mask_be     : uint32 MQC_BYPASS_* bitmask, big-endian
 *   - src_ip_str  : peer IP rendered as ASCII (dotted-quad for v4)
 *
 *   Replay defenses: freshness window (±MQC_BYPASS_FRESHNESS_SEC), IP
 *   binding (server compares the accept'd peer IP against the IP byte
 *   string hashed in by the client).
 *
 * Build-side:
 *   This TU is only compiled into server-side links (anything that
 *   pulls mqc_accept_*) AND into the standalone `mqc-gen-bypass-token`
 *   tool.  Pure clients (qsh, fips-manifest-*, fetch-publisher-key)
 *   build the token by inlining the same encoder via mqc_bypass_make
 *   — they pull in this file via the static archive.
 *
 * Dependencies:
 *   wolfCrypt (wc_HmacSetKey + WC_SHA256) — already linked.
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>

/* "mqc-bypass:" label hashed in front of every signed input.  Plays
 * the same role the AAD label plays for AEAD frames — domain
 * separation against any other use of the master password (none
 * exist today, but the label costs nothing). */
static const char MQC_BYPASS_HMAC_LABEL[] = "mqc-bypass:";
#define MQC_BYPASS_HMAC_LABEL_LEN (sizeof(MQC_BYPASS_HMAC_LABEL) - 1)

static void put_u64_be(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64_be(const uint8_t in[8])
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | (uint64_t)in[i];
    return v;
}

static uint32_t get_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] <<  8) |  (uint32_t)in[3];
}

/* HMAC-SHA256 with all three concatenated inputs.  master_password is
 * treated as a UTF-8 byte string (its length determines the key). */
static int mqc_bypass_hmac(const char *master_password,
                           uint64_t ts_sec, uint32_t mask,
                           const char *src_ip,
                           uint8_t out_mac[32])
{
    Hmac hmac;
    uint8_t ts_be[8], mask_be[4];
    int ret;

    if (!master_password || !*master_password) return -1;
    if (!src_ip || !*src_ip) return -1;

    put_u64_be(ts_be, ts_sec);
    mqc_put_u32be(mask_be, mask);

    if ((ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID)) != 0) return ret;
    if ((ret = wc_HmacSetKey(&hmac, WC_SHA256,
                             (const byte *)master_password,
                             (word32)strlen(master_password))) != 0)
        goto out;
    if ((ret = wc_HmacUpdate(&hmac,
                             (const byte *)MQC_BYPASS_HMAC_LABEL,
                             MQC_BYPASS_HMAC_LABEL_LEN)) != 0) goto out;
    if ((ret = wc_HmacUpdate(&hmac, ts_be, sizeof(ts_be))) != 0) goto out;
    if ((ret = wc_HmacUpdate(&hmac, mask_be, sizeof(mask_be))) != 0) goto out;
    if ((ret = wc_HmacUpdate(&hmac,
                             (const byte *)src_ip,
                             (word32)strlen(src_ip))) != 0) goto out;
    ret = wc_HmacFinal(&hmac, out_mac);
out:
    wc_HmacFree(&hmac);
    return ret;
}

int mqc_bypass_make(const char *master_password,
                    uint64_t timestamp_sec, uint32_t bypass_mask,
                    const char *src_ip,
                    char out_line[MQC_BYPASS_LINE_LEN])
{
    uint8_t payload[MQC_BYPASS_PAYLOAD_BYTES];
    uint8_t mac[32];
    char hex[MQC_BYPASS_HEX_LEN + 1];
    int ret;

    if ((bypass_mask & ~MQC_BYPASS_VALID_MASK) != 0) return -1;
    if (bypass_mask == 0) return -1;   /* refuse to generate an empty token */

    ret = mqc_bypass_hmac(master_password, timestamp_sec, bypass_mask,
                          src_ip, mac);
    if (ret != 0) return -1;

    put_u64_be(payload, timestamp_sec);
    mqc_put_u32be(payload + 8, bypass_mask);
    memcpy(payload + 12, mac, 32);

    mqc_to_hex(payload, MQC_BYPASS_PAYLOAD_BYTES, hex);

    memcpy(out_line, MQC_BYPASS_PREFIX, MQC_BYPASS_PREFIX_LEN);
    memcpy(out_line + MQC_BYPASS_PREFIX_LEN, hex, MQC_BYPASS_HEX_LEN);
    out_line[MQC_BYPASS_LINE_LEN - 1] = '\n';
    return 0;
}

static int hex_nybble(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0');      return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(10 + c - 'a'); return 0; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(10 + c - 'A'); return 0; }
    return -1;
}

int mqc_bypass_verify(const char *master_password,
                      const char *line, int line_len,
                      const char *src_ip,
                      uint64_t now_sec,
                      uint32_t *out_mask,
                      const char **out_reason)
{
    uint8_t payload[MQC_BYPASS_PAYLOAD_BYTES];
    uint8_t mac_expected[32];
    uint64_t ts;
    uint32_t mask;
    int i;
    int64_t skew;

    if (out_reason) *out_reason = "internal";

    if (!master_password || !*master_password) {
        if (out_reason) *out_reason = "no-master-password";
        return -1;
    }
    if (!line || line_len != MQC_BYPASS_LINE_LEN) {
        if (out_reason) *out_reason = "wrong-length";
        return -1;
    }
    if (memcmp(line, MQC_BYPASS_PREFIX, MQC_BYPASS_PREFIX_LEN) != 0) {
        if (out_reason) *out_reason = "bad-prefix";
        return -1;
    }
    if (line[MQC_BYPASS_LINE_LEN - 1] != '\n') {
        if (out_reason) *out_reason = "missing-newline";
        return -1;
    }

    for (i = 0; i < MQC_BYPASS_PAYLOAD_BYTES; i++) {
        uint8_t hi, lo;
        const char *p = line + MQC_BYPASS_PREFIX_LEN + i * 2;
        if (hex_nybble(p[0], &hi) != 0 || hex_nybble(p[1], &lo) != 0) {
            if (out_reason) *out_reason = "bad-hex";
            return -1;
        }
        payload[i] = (uint8_t)((hi << 4) | lo);
    }

    ts   = get_u64_be(payload);
    mask = get_u32_be(payload + 8);

    if ((mask & ~MQC_BYPASS_VALID_MASK) != 0) {
        if (out_reason) *out_reason = "reserved-bits-set";
        return -1;
    }
    if (mask == 0) {
        if (out_reason) *out_reason = "empty-mask";
        return -1;
    }

    /* Freshness: ±MQC_BYPASS_FRESHNESS_SEC vs server wall clock. */
    skew = (int64_t)now_sec - (int64_t)ts;
    if (skew < 0) skew = -skew;
    if (skew > MQC_BYPASS_FRESHNESS_SEC) {
        if (out_reason) *out_reason = "stale-or-future";
        return -1;
    }

    if (mqc_bypass_hmac(master_password, ts, mask, src_ip, mac_expected) != 0) {
        if (out_reason) *out_reason = "hmac-compute-failed";
        return -1;
    }
    if (!mqc_const_eq(mac_expected, payload + 12, 32)) {
        if (out_reason) *out_reason = "bad-hmac";
        return -1;
    }

    if (out_mask) *out_mask = mask;
    if (out_reason) *out_reason = "ok";
    return 0;
}
