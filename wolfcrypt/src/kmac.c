/* kmac.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* KMAC128 and KMAC256 per NIST SP 800-185.
 *
 * KMAC(K, X, L, S) = cSHAKE(newX, L, "KMAC", S)
 *   newX = bytepad(encode_string(K), rate) || X || right_encode(L_in_bits)
 *   (right_encode(0) is used in XOF mode)
 *
 * KMAC128 -> SHAKE128 underneath (rate 168 bytes)
 * KMAC256 -> SHAKE256 underneath (rate 136 bytes)
 *
 * cSHAKE differs from SHAKE only by domain-separation byte 0x04 (vs SHAKE's
 * 0x1F), supplied via the internal wc_Sha3_cSHAKE{128,256}_Final helpers.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_KMAC

#include <wolfssl/wolfcrypt/kmac.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define KMAC128_RATE 168
#define KMAC256_RATE 136

/* SP 800-185 §2.3.1: left_encode(x).
 * Writes (1 + n) bytes to out, where n is the smallest positive integer with
 * 2^(8n) > x (so x=0 yields n=1). Layout: [n][x as n big-endian bytes].
 * Caller guarantees out has at least 9 bytes. Returns bytes written. */
static word32 sp800_185_left_encode(byte out[9], word64 x)
{
    word32 n = 0;
    word32 i;
    word64 v = x;

    do {
        n++;
        v >>= 8;
    } while (v != 0);

    out[0] = (byte)n;
    for (i = 0; i < n; i++) {
        out[1 + i] = (byte)(x >> (8 * (n - 1 - i)));
    }
    return n + 1;
}

/* SP 800-185 §2.3.1: right_encode(x).
 * Layout: [x as n big-endian bytes][n]. Same n rule as left_encode. */
static word32 sp800_185_right_encode(byte out[9], word64 x)
{
    word32 n = 0;
    word32 i;
    word64 v = x;

    do {
        n++;
        v >>= 8;
    } while (v != 0);

    for (i = 0; i < n; i++) {
        out[i] = (byte)(x >> (8 * (n - 1 - i)));
    }
    out[n] = (byte)n;
    return n + 1;
}

/* Absorb data into the underlying SHAKE state for this KMAC instance. */
static int kmac_absorb(Kmac* kmac, const byte* data, word32 len)
{
    if (len == 0) {
        return 0;
    }
#ifdef WOLFSSL_SHAKE128
    if (kmac->type == WC_KMAC_128) {
        return wc_Shake128_Update(&kmac->sha3, data, len);
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (kmac->type == WC_KMAC_256) {
        return wc_Shake256_Update(&kmac->sha3, data, len);
    }
#endif
    return BAD_FUNC_ARG;
}

/* Absorb zero-padding bytes (in chunks) so the running byte count is a
 * multiple of w. */
static int kmac_absorb_zero_pad(Kmac* kmac, word32 absorbed, word32 w)
{
    static const byte zeros[KMAC128_RATE] = { 0 };
    word32 padLen = w - (absorbed % w);

    if (padLen == w) {
        return 0;
    }
    while (padLen > 0) {
        word32 chunk = (padLen > sizeof(zeros)) ? (word32)sizeof(zeros) :
                                                  padLen;
        int ret = kmac_absorb(kmac, zeros, chunk);
        if (ret != 0) {
            return ret;
        }
        padLen -= chunk;
    }
    return 0;
}

/* Absorb encode_string(S) = left_encode(|S|*8) || S, returning bytes
 * absorbed via *absorbed (added to running total). */
static int kmac_absorb_encoded_string(Kmac* kmac, const byte* s, word32 sLen,
                                      word32* absorbed)
{
    byte enc[9];
    word32 encLen;
    int ret;

    encLen = sp800_185_left_encode(enc, (word64)sLen * 8);
    ret = kmac_absorb(kmac, enc, encLen);
    if (ret != 0) {
        return ret;
    }
    *absorbed += encLen;

    ret = kmac_absorb(kmac, s, sLen);
    if (ret != 0) {
        return ret;
    }
    *absorbed += sLen;

    return 0;
}

/* Absorb the cSHAKE prefix bytepad(encode_string("KMAC") || encode_string(S),
 * rate) into the SHAKE state. */
static int kmac_absorb_cshake_prefix(Kmac* kmac, const byte* custom,
                                     word32 customLen, word32 rate)
{
    /* encode_string("KMAC") = left_encode(32) || "KMAC" = 01 20 4B 4D 41 43 */
    static const byte encKmac[] = { 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43 };
    byte enc[9];
    word32 encLen;
    word32 absorbed = 0;
    int ret;

    /* left_encode(rate) */
    encLen = sp800_185_left_encode(enc, rate);
    ret = kmac_absorb(kmac, enc, encLen);
    if (ret != 0) {
        return ret;
    }
    absorbed += encLen;

    /* encode_string("KMAC") */
    ret = kmac_absorb(kmac, encKmac, (word32)sizeof(encKmac));
    if (ret != 0) {
        return ret;
    }
    absorbed += (word32)sizeof(encKmac);

    /* encode_string(S) */
    ret = kmac_absorb_encoded_string(kmac, custom, customLen, &absorbed);
    if (ret != 0) {
        return ret;
    }

    /* Pad to next multiple of rate. */
    return kmac_absorb_zero_pad(kmac, absorbed, rate);
}

/* Absorb bytepad(encode_string(K), rate). */
static int kmac_absorb_key_block(Kmac* kmac, const byte* key, word32 keyLen,
                                 word32 rate)
{
    byte enc[9];
    word32 encLen;
    word32 absorbed = 0;
    int ret;

    encLen = sp800_185_left_encode(enc, rate);
    ret = kmac_absorb(kmac, enc, encLen);
    if (ret != 0) {
        return ret;
    }
    absorbed += encLen;

    ret = kmac_absorb_encoded_string(kmac, key, keyLen, &absorbed);
    if (ret != 0) {
        return ret;
    }

    return kmac_absorb_zero_pad(kmac, absorbed, rate);
}

int wc_InitKmac(Kmac* kmac, int type,
                const byte* key, word32 keyLen,
                const byte* custom, word32 customLen,
                void* heap, int devId)
{
    int ret;
    word32 rate;

    if (kmac == NULL) {
        return BAD_FUNC_ARG;
    }
    if (key == NULL && keyLen != 0) {
        return BAD_FUNC_ARG;
    }
    if (custom == NULL && customLen != 0) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(kmac, 0, sizeof(*kmac));
    kmac->type = (byte)type;
    kmac->heap = heap;
    kmac->devId = devId;

    switch (type) {
#ifdef WOLFSSL_SHAKE128
        case WC_KMAC_128:
            ret = wc_InitShake128(&kmac->sha3, heap, devId);
            rate = KMAC128_RATE;
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case WC_KMAC_256:
            ret = wc_InitShake256(&kmac->sha3, heap, devId);
            rate = KMAC256_RATE;
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }
    if (ret != 0) {
        return ret;
    }

    ret = kmac_absorb_cshake_prefix(kmac, custom, customLen, rate);
    if (ret != 0) {
        return ret;
    }

    return kmac_absorb_key_block(kmac, key, keyLen, rate);
}

int wc_KmacSetXof(Kmac* kmac, int xof)
{
    if (kmac == NULL) {
        return BAD_FUNC_ARG;
    }
    if (kmac->updated || kmac->finalized) {
        return BAD_STATE_E;
    }
    kmac->isXof = (byte)(xof ? 1 : 0);
    return 0;
}

int wc_KmacUpdate(Kmac* kmac, const byte* in, word32 inSz)
{
    if (kmac == NULL || (in == NULL && inSz != 0)) {
        return BAD_FUNC_ARG;
    }
    if (kmac->finalized) {
        return BAD_STATE_E;
    }
    if (inSz == 0) {
        return 0;
    }
    kmac->updated = 1;
    return kmac_absorb(kmac, in, inSz);
}

int wc_KmacFinal(Kmac* kmac, byte* out, word32 outSz)
{
    byte enc[9];
    word32 encLen;
    word64 lBits;
    int ret;

    if (kmac == NULL || out == NULL || outSz == 0) {
        return BAD_FUNC_ARG;
    }
    if (kmac->finalized) {
        return BAD_STATE_E;
    }

    lBits = kmac->isXof ? (word64)0 : ((word64)outSz * 8);
    encLen = sp800_185_right_encode(enc, lBits);
    ret = kmac_absorb(kmac, enc, encLen);
    if (ret != 0) {
        return ret;
    }

    switch (kmac->type) {
#ifdef WOLFSSL_SHAKE128
        case WC_KMAC_128:
            ret = wc_Sha3_cSHAKE128_Final(&kmac->sha3, out, outSz);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case WC_KMAC_256:
            ret = wc_Sha3_cSHAKE256_Final(&kmac->sha3, out, outSz);
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    if (ret == 0) {
        kmac->finalized = 1;
    }
    return ret;
}

int wc_KmacFree(Kmac* kmac)
{
    if (kmac == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (kmac->type) {
#ifdef WOLFSSL_SHAKE128
        case WC_KMAC_128:
            wc_Shake128_Free(&kmac->sha3);
            break;
#endif
#ifdef WOLFSSL_SHAKE256
        case WC_KMAC_256:
            wc_Shake256_Free(&kmac->sha3);
            break;
#endif
        default:
            break;
    }
    ForceZero(kmac, sizeof(*kmac));
    return 0;
}

#endif /* WOLFSSL_KMAC */
