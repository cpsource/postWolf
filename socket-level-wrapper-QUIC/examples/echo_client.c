/* MQCP echo client example
 *
 * Usage: echo_client <tpm_path> <mtc_server> <host> <port> [message]
 *
 * Connects to an MQCP server with post-quantum authenticated
 * encryption and sends a message, then prints the echo reply.
 */

#include "mqcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <tpm_path> <host> [port] [message]\n",
                argv[0]);
        return 1;
    }

    const char *tpm_path = argv[1];
    const char *host = argv[2];
    int port = argc > 3 ? atoi(argv[3]) : 8446;
    const char *message = argc > 4 ? argv[4] : "Hello from MQCP!";

    mqcp_set_verbose(1);

    mqcp_cfg_t cfg = {0};
    cfg.role = MQCP_CLIENT;
    cfg.tpm_path = tpm_path;

    mqcp_ctx_t *ctx = mqcp_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "Failed to create MQCP context\n");
        return 1;
    }

    printf("Connecting to %s:%d...\n", host, port);
    mqcp_conn_t *conn = mqcp_connect(ctx, host, port);
    if (!conn) {
        fprintf(stderr, "Failed to initiate connection\n");
        mqcp_ctx_free(ctx);
        return 1;
    }

    /* Event loop: complete handshake */
    struct pollfd pfd;
    while (!mqcp_is_established(conn)) {
        pfd.fd = mqcp_get_fd(conn);
        pfd.events = POLLIN;

        uint64_t next = mqcp_next_timer(conn);
        int timeout_ms = next > 0 ? (int)((next + 999) / 1000) : 1000;
        if (timeout_ms > 5000) timeout_ms = 5000;

        poll(&pfd, 1, timeout_ms);

        int ret = mqcp_process(conn);
        if (ret < 0) {
            fprintf(stderr, "Handshake failed: %d\n", ret);
            mqcp_conn_free(conn);
            mqcp_ctx_free(ctx);
            return 1;
        }
    }

    printf("Connected! Peer cert_index=%d\n", mqcp_get_peer_index(conn));
    printf("Sending: \"%s\"\n", message);

    int written = mqcp_write(conn, message, strlen(message));
    mqcp_flush(conn);
    printf("Buffered %d bytes\n", written);

    /* Wait for echo reply */
    for (int i = 0; i < 30; i++) {
        pfd.fd = mqcp_get_fd(conn);
        pfd.events = POLLIN;
        poll(&pfd, 1, 100);

        mqcp_process(conn);

        uint8_t buf[65536];
        int n = mqcp_read(conn, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Reply (%d bytes): %s\n", n, buf);
            break;
        }
        if (n == MQCP_ERR_CLOSED) {
            printf("Connection closed\n");
            break;
        }
    }

    mqcp_close(conn);
    mqcp_conn_free(conn);
    mqcp_ctx_free(ctx);
    return 0;
}
