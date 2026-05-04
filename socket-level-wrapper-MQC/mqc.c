/******************************************************************************
 * File:        mqc.c
 * Purpose:     MQC public-API dispatcher.
 *
 * Description:
 *   The MQC implementation is split across three sibling files:
 *
 *     mqc_common.c     — shared machinery (transcript hash, key
 *                        schedule, AEAD frames, JSON parsers, Redis
 *                        rate limits, runtime cfg, etc.)
 *     mqc_clear.c      — clear-identity-mode handshake bodies
 *                        (mqc_connect_clear, mqc_accept_clear)
 *     mqc_encrypted.c  — encrypted-identity-mode handshake bodies
 *                        (mqc_connect_encrypted, mqc_accept_encrypted)
 *
 *   This file is the thin shell that the public mqc.h API surface
 *   binds to.  mqc_connect / mqc_accept read ctx->encrypt_identity
 *   and route to the correct mode.  mqc_accept_auto reads the first
 *   length-prefixed handshake frame, strict-parses the JSON, and
 *   dispatches on the parsed `mode` field — see the auto-detect
 *   block below for the full sequence.
 *
 * Created:     2026-04-15
 *              2026-05-03  split into dispatcher + per-mode files
 *              2026-05-03  encrypted-mode bodies shipped (commit
 *                          a287aa8d0; mqc-1 Phase 7 commit 2)
 *              2026-05-03  mqc_accept_auto rewritten for length-
 *                          prefixed dispatch (mqc-2 Phase 1)
 ******************************************************************************/

#include "mqc_internal.h"

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <json-c/json.h>

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

/* --- Auto-detecting accept (mqc-2 P1.4) ---------------------------
 *
 * A single listener that accepts both clear- and encrypted-mode
 * clients in a deployment whose server ctx didn't commit in advance
 * to one mode.
 *
 * Pre-mqc-2 used MSG_PEEK + strstr("mode\":\"encrypted") on a 256-
 * byte prefix.  Reviewer issue #9 flagged that as brittle (no JSON
 * structure awareness).  Now that handshake frames are length-
 * prefixed (spec §5.1, P1.1/P1.2), we can read the FULL first frame
 * here, parse it strict-JSON, look at the parsed `mode` field, and
 * dispatch to the chosen continuation with the already-read frame
 * passed in.
 *
 * Order of operations (matches the per-mode public entry points):
 *   1. accept(), inet_ntop client IP
 *   2. mqc_accept_prologue: AbuseIPDB, per-IP RL, per-IP fail RL,
 *      socket per-syscall timeout
 *   3. arm HANDSHAKE_DEADLINE_ACTIVE in this scope (propagates
 *      through the continuation via the static deadline)
 *   4. mqc_read_handshake_frame — strict 4-byte length + body
 *   5. mqc_json_parse_strict on the body, extract `mode`
 *   6. dispatch to mqc_accept_clear_continue or mqc_accept_encrypted_continue */

mqc_conn_t *mqc_accept_auto(mqc_ctx_t *ctx, int listen_fd)
{
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char client_ip[64] = "unknown";
    char first_frame[64000];
    int  first_frame_len;
    int  fd;
    struct json_object *first_obj = NULL;
    struct json_object *mode_obj  = NULL;
    const char *mode_str;
    int encrypted = 0;

    if (!ctx) return NULL;

    fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) return NULL;
    inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
    MQC_LOG("auto-detect accept from %s:%d",
            client_ip, ntohs(cli_addr.sin_port));

    if (mqc_accept_prologue(fd, client_ip) != 0) {
        close(fd); return NULL;
    }

    HANDSHAKE_DEADLINE_ACTIVE();

    first_frame_len = mqc_read_handshake_frame(fd, first_frame,
                                               sizeof(first_frame));
    if (first_frame_len <= 0) {
        MQC_SECURITY("auto-detect: first-frame read failed (fd=%d)", fd);
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }

    /* Strict JSON parse just to learn `mode`.  The chosen
     * continuation re-parses the same buffer with full field
     * checks; we only need `mode` here for dispatch.  Doing a real
     * parse (not strstr) means a `mode` value buried in a string
     * literal can't fool us. */
    first_obj = mqc_json_parse_strict("auto-first-frame",
                                      first_frame, first_frame_len);
    if (!first_obj) {
        MQC_SECURITY("auto-detect: first frame is not strict JSON");
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }
    if (!json_object_object_get_ex(first_obj, "mode", &mode_obj) ||
        !json_object_is_type(mode_obj, json_type_string)) {
        MQC_SECURITY("auto-detect: first frame has no string `mode` field");
        json_object_put(first_obj);
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }
    mode_str = json_object_get_string(mode_obj);
    if (strcmp(mode_str, "encrypted") == 0) {
        encrypted = 1;
    } else if (strcmp(mode_str, "clear") == 0) {
        encrypted = 0;
    } else {
        MQC_SECURITY("auto-detect: unknown mode '%s'", mode_str);
        json_object_put(first_obj);
        mqc_ratelimit_fail_record(client_ip);
        close(fd); return NULL;
    }
    json_object_put(first_obj);

    return encrypted
         ? mqc_accept_encrypted_continue(ctx, fd, client_ip,
                                         first_frame, first_frame_len)
         : mqc_accept_clear_continue    (ctx, fd, client_ip,
                                         first_frame, first_frame_len);
}
