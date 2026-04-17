/* MQCP echo server example
 *
 * Usage: echo_server <tpm_path> <mtc_server> <port>
 *
 * Listens on UDP, accepts MQCP connections with post-quantum
 * authenticated encryption, and echoes back received data.
 */

#include "mqcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <tpm_path> [port]\n", argv[0]);
        fprintf(stderr, "  tpm_path:    ~/.TPM/<domain>\n");
        fprintf(stderr, "  port:        UDP port to listen on (default: 8446)\n");
        return 1;
    }

    const char *tpm_path = argv[1];
    int port = argc > 2 ? atoi(argv[2]) : 8446;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    mqcp_set_verbose(1);

    mqcp_cfg_t cfg = {0};
    cfg.role = MQCP_SERVER;
    cfg.tpm_path = tpm_path;

    mqcp_ctx_t *ctx = mqcp_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "Failed to create MQCP context\n");
        return 1;
    }

    int listen_fd = mqcp_listen(ctx, NULL, port);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to listen on port %d\n", port);
        mqcp_ctx_free(ctx);
        return 1;
    }

    printf("MQCP echo server listening on port %d\n", port);

    mqcp_conn_t *conn = NULL;

    while (running) {
        struct pollfd pfd = { .fd = conn ? mqcp_get_fd(conn) : listen_fd,
                              .events = POLLIN };

        uint64_t timeout_us = 0;
        if (conn) {
            timeout_us = mqcp_next_timer(conn);
        }

        int timeout_ms = timeout_us > 0 ? (int)((timeout_us + 999) / 1000) : 1000;
        if (timeout_ms > 1000) timeout_ms = 1000;

        int nfds = poll(&pfd, 1, timeout_ms);
        (void)nfds;

        if (!conn) {
            conn = mqcp_accept(ctx, listen_fd);
            if (conn) {
                printf("New connection (handshake in progress)\n");
            }
            continue;
        }

        int ret = mqcp_process(conn);
        if (ret < 0) {
            fprintf(stderr, "Connection error: %d\n", ret);
            mqcp_conn_free(conn);
            conn = NULL;
            continue;
        }

        if (mqcp_is_established(conn)) {
            uint8_t buf[65536];
            int n = mqcp_read(conn, buf, sizeof(buf));
            if (n > 0) {
                printf("Received %d bytes, echoing back\n", n);
                mqcp_write(conn, buf, (size_t)n);
                mqcp_flush(conn);
            } else if (n == MQCP_ERR_CLOSED) {
                printf("Connection closed by peer\n");
                mqcp_conn_free(conn);
                conn = NULL;
            }
        }
    }

    printf("\nShutting down\n");
    if (conn) {
        mqcp_close(conn);
        mqcp_conn_free(conn);
    }
    mqcp_ctx_free(ctx);
    return 0;
}
