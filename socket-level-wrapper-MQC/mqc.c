/******************************************************************************
 * File:        mqc.c
 * Purpose:     MQC public-API client-side dispatcher.
 *
 * Description:
 *   The MQC implementation is split across these sibling files:
 *
 *     mqc_common.c          — shared machinery (transcript hash, key
 *                             schedule, AEAD frames, JSON parsers,
 *                             runtime cfg, etc.)
 *     mqc_clear.c           — clear-identity-mode client handshake
 *                             (mqc_connect_clear)
 *     mqc_clear_accept.c    — clear-identity-mode server handshake
 *                             (mqc_accept_clear, mqc_accept_clear_continue)
 *     mqc_encrypted.c       — encrypted-identity-mode client handshake
 *                             (mqc_connect_encrypted)
 *     mqc_encrypted_accept.c — encrypted-identity-mode server handshake
 *                             (mqc_accept_encrypted,
 *                              mqc_accept_encrypted_continue)
 *     mqc_accept_dispatch.c — mqc_accept + mqc_accept_auto (server)
 *     mqc_ratelimit.c       — Redis rate-limit gates + accept prologue
 *     mqc_abuseipdb.c       — AbuseIPDB lookup
 *
 *   Splitting client- and server-side handshake bodies into separate
 *   translation units keeps libcurl / libhiredis off the link line of
 *   pure MQC clients (qsh, fips-manifest-*, fetch-publisher-key, ...).
 *
 *   This file contains only the client-side dispatcher mqc_connect,
 *   which reads ctx->encrypt_identity and routes to mqc_connect_clear
 *   or mqc_connect_encrypted.
 *
 * Created:     2026-04-15
 *              2026-05-03  split into dispatcher + per-mode files
 *              2026-05-13  client/server split (TODO #81)
 ******************************************************************************/

#include "mqc_internal.h"

mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)
{
    if (!ctx) return NULL;
    return ctx->encrypt_identity
         ? mqc_connect_encrypted(ctx, host, port)
         : mqc_connect_clear    (ctx, host, port);
}
