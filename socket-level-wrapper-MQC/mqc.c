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

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* --- Auto-detecting accept (Phase 7 commit 2) ---------------------
 *
 * Determines handshake mode by peeking at the first JSON frame's
 * `mode` field BEFORE the chosen sub-handler consumes any bytes.
 * This lets a single listener accept both clear- and encrypted-mode
 * clients in a deployment without the server's ctx needing to know
 * in advance which one a given peer will use.
 *
 * Implementation: accept() ourselves, getpeername() for the
 * client_ip, then MSG_PEEK enough bytes to see whether the first
 * JSON contains `"mode":"encrypted"`.  Dispatch to the
 * mode-specific post-accept continuation (which expects an
 * already-accepted fd).  The peeked bytes stay in the socket
 * buffer; the sub-handler's own mqc_read_json_block() reads them
 * normally.
 *
 * Peek size: 256 bytes is enough to see `"mode":"..."` in any
 * valid frame.  The full ClientHello is ~12 KiB (mostly the
 * 4627-byte signature in hex); a 256-byte prefix lands well
 * inside the JSON header.  If the peek returns less than 256
 * bytes the wire is broken and the sub-handler will reject. */

#define MQC_MODE_PEEK_BYTES   256

mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)
{
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char client_ip[64] = "unknown";
    int fd;
    char peek_buf[MQC_MODE_PEEK_BYTES + 1];
    ssize_t n;
    int encrypted = 0;

    if (!ctx) return NULL;

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;
    inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));

    /* MSG_PEEK reads from the socket buffer without consuming the
     * bytes.  The sub-handler's own mqc_read_json_block() will read
     * them normally a few microseconds later. */
    n = recv(fd, peek_buf, MQC_MODE_PEEK_BYTES, MSG_PEEK);
    if (n > 0) {
        peek_buf[n] = '\0';
        if (strstr(peek_buf, "\"mode\":\"encrypted\""))
            encrypted = 1;
    }
    /* If the peek returned 0 / -1 / no recognisable mode field, we
     * fall through as clear-mode.  The sub-handler's strict parser
     * will surface a clean rejection on whatever malformed bytes
     * the client actually sent.  This is the same failure mode the
     * dispatcher would produce for a direct mqc_accept_clear call
     * against malformed input. */

    return encrypted
         ? mqc_accept_encrypted_post(ctx, fd, client_ip)
         : mqc_accept_clear_post    (ctx, fd, client_ip);
}
