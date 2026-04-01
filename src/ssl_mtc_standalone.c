/* src/ssl_mtc_standalone.c
 *
 * Standalone build of the MTC C API for use outside libwolfssl.
 * This wraps ssl_mtc.c with the necessary defines and includes
 * so it can be compiled as a separate translation unit.
 *
 * Used by examples/quic-mtc/ and other standalone programs.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>

/* Bypass the ssl.c inclusion guard */
#undef WOLFSSL_SSL_MTC_INCLUDED
#define WOLFSSL_SSL_MTC_INCLUDED

/* Provide XSNPRINTF if not defined */
#ifndef XSNPRINTF
#define XSNPRINTF snprintf
#endif
#ifndef XSTRLEN
#define XSTRLEN strlen
#endif
#ifndef XMEMCPY
#define XMEMCPY memcpy
#endif

#include "ssl_mtc.c"
