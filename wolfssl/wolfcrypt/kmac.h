/* kmac.h
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


#ifndef WOLF_CRYPT_KMAC_H
#define WOLF_CRYPT_KMAC_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_KMAC

#include <wolfssl/wolfcrypt/sha3.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef enum KmacType {
    WC_KMAC_128 = 1,
    WC_KMAC_256 = 2
} KmacType;

#ifndef WC_KMAC_TYPE_DEFINED
    typedef struct Kmac Kmac;
    #define WC_KMAC_TYPE_DEFINED
#endif

struct Kmac {
    wc_Sha3 sha3;
    void*   heap;
    int     devId;
    byte    type;
    byte    isXof;
    byte    updated;
    byte    finalized;
};

WOLFSSL_API int wc_InitKmac(Kmac* kmac, int type,
                            const byte* key, word32 keyLen,
                            const byte* custom, word32 customLen,
                            void* heap, int devId);
WOLFSSL_API int wc_KmacSetXof(Kmac* kmac, int xof);
WOLFSSL_API int wc_KmacUpdate(Kmac* kmac, const byte* in, word32 inSz);
WOLFSSL_API int wc_KmacFinal(Kmac* kmac, byte* out, word32 outSz);
WOLFSSL_API int wc_KmacFree(Kmac* kmac);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_KMAC */

#endif /* WOLF_CRYPT_KMAC_H */
