/* echo_server.c — Simple echo server using the SLC API
 *
 * Usage:
 *   ./echo_server [port]                           — traditional X.509
 *   ./echo_server --mtc ~/.TPM/factsorlie.com [port] — MTC certificate
 *
 * Listens on the given port (default 4433), accepts one TLS 1.3
 * connection at a time, echoes back whatever the client sends.
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "slc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default paths — wolfSSL test certificates */
#define DEFAULT_CERT "../certs/server-cert.pem"
#define DEFAULT_KEY  "../certs/server-key.pem"
#define DEFAULT_CA   "../certs/client-cert.pem"
#define DEFAULT_PORT 4433
#define BUF_SZ       4096

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    const char *mtc_store = NULL;
    int listen_fd;
    slc_ctx_t  *ctx;
    slc_conn_t *conn;
    slc_cfg_t cfg;
    char buf[BUF_SZ];
    int n, i;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mtc") == 0 && i + 1 < argc)
            mtc_store = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--mtc TPM_PATH] [port]\n", argv[0]);
            printf("  --mtc PATH   Use MTC certificate from ~/.TPM/<domain>\n");
            printf("  port         Listen port (default: %d)\n", DEFAULT_PORT);
            return 0;
        }
        else
            port = atoi(argv[i]);
    }

    /* Configure server context */
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLC_SERVER;

    if (mtc_store) {
        cfg.mtc_store = mtc_store;
        printf("MTC mode: %s\n", mtc_store); fflush(stdout);
        wolfSSL_Debugging_ON();
    } else {
        cfg.cert_file = DEFAULT_CERT;
        cfg.key_file  = DEFAULT_KEY;
        cfg.ca_file   = DEFAULT_CA;
    }

    ctx = slc_ctx_new(&cfg);
    if (ctx == NULL) {
        fprintf(stderr, "slc_ctx_new failed\n");
        return 1;
    }

    /* Start listening */
    listen_fd = slc_listen(NULL, port);
    if (listen_fd < 0) {
        fprintf(stderr, "slc_listen failed on port %d\n", port);
        slc_ctx_free(ctx);
        return 1;
    }

    printf("Echo server listening on port %d%s\n", port,
           mtc_store ? " (MTC)" : " (X.509)");

    /* Accept loop — one client at a time */
    for (;;) {
        printf("Waiting for connection...\n");

        conn = slc_accept(ctx, listen_fd);
        if (conn == NULL) {
            fprintf(stderr, "slc_accept failed (client rejected)\n");
            continue;
        }

        printf("Client connected (fd %d)\n", slc_get_fd(conn));

        /* Echo loop */
        while ((n = slc_read(conn, buf, BUF_SZ)) > 0) {
            printf("Received %d bytes: %.*s\n", n, n, buf);
            if (slc_write(conn, buf, n) < 0) {
                fprintf(stderr, "slc_write failed\n");
                break;
            }
        }

        printf("Client disconnected\n");
        slc_close(conn);
    }

    /* Not reached in this example */
    slc_ctx_free(ctx);
    return 0;
}
