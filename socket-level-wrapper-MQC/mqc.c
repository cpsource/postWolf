/******************************************************************************
 * File:        mqc.c
 * Purpose:     MQC public-API dispatcher (Phase 7 commit 1).
 *
 * Description:
 *   Phase 7's file split moved the bulk of the MQC implementation
 *   into three sibling files:
 *
 *     mqc_common.c     — shared machinery (transcript hash, key
 *                        schedule, AEAD frames, JSON parsers, Redis
 *                        rate limits, runtime cfg, etc.)
 *     mqc_clear.c      — clear-identity-mode handshake bodies
 *                        (mqc_connect_clear, mqc_accept_clear)
 *     mqc_encrypted.c  — encrypted-identity-mode handshake bodies
 *                        (currently stubs; bodies arrive in Phase 7
 *                        commit 2)
 *
 *   This file is the thin shell that the public mqc.h API surface
 *   binds to.  mqc_connect / mqc_accept read ctx->encrypt_identity
 *   and route to the correct mode.  mqc_accept_auto stays a thin
 *   alias for mqc_accept (true mode auto-detection by peeking at the
 *   first frame's `mode` field is restored in Phase 7 commit 2).
 *
 *   No semantic change vs the pre-split mqc.c: callers that did
 *   nothing with `cfg.encrypt_identity` still get the clear-mode
 *   bodies; callers that opt in via cfg.encrypt_identity = 1 still
 *   get the (NULL-returning) encrypted stub until commit 2 lands.
 *
 * Created:     2026-04-15
 *              2026-05-03  split into dispatcher + per-mode files
 ******************************************************************************/

#include "mqc_internal.h"

mqc_conn_t *mqc_connect(mqc_ctx_t *ctx, const char *host, int port)
{
    if (!ctx) return NULL;
    return ctx->encrypt_identity
         ? mqc_connect_encrypted(ctx, host, port)
         : mqc_connect_clear    (ctx, host, port);
}

mqc_conn_t *mqc_accept(mqc_ctx_t *ctx, int listen_fd)
{
    if (!ctx) return NULL;
    return ctx->encrypt_identity
         ? mqc_accept_encrypted(ctx, listen_fd)
         : mqc_accept_clear    (ctx, listen_fd);
}

/* --- Auto-detecting accept (Phase 7 commit 1: clear-mode only) ---
 *
 * Pre-Phase-1 mqc_accept_auto inlined both handshake bodies because
 * it had to detect mode after accept().  Issue #1's wire-format
 * change broke the inlined logic, and every production MQC caller
 * uses clear-mode mqc_connect, so this is a thin alias for
 * mqc_accept.  An operator who needs encrypted mode on the server
 * should configure ctx->encrypt_identity = 1 (which routes through
 * the dispatcher above) or call mqc_accept_encrypted directly
 * (currently a stub; Phase 7 commit 2 restores both true
 * auto-detection and the encrypted handshake body).  No silent
 * compat loss: a peer sending encrypted-mode bytes hits the
 * clear-mode strict-parse "mode" check and is rejected with a clear
 * diagnostic. */

mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)
{
    return mqc_accept(ctx, listen_fd);
}
