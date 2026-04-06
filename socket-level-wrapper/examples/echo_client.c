/* echo_client.c — Simple echo client using the SLC API
 *
 * Usage: ./echo_client [host] [port]
 *
 * Connects to the echo server, sends a message, prints the response.
 */

#include "slc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default paths — wolfSSL test certificates */
#define DEFAULT_CERT "../certs/client-cert.pem"
#define DEFAULT_KEY  "../certs/client-key.pem"
#define DEFAULT_CA   "../certs/ca-cert.pem"
#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 4433
#define BUF_SZ       4096

int main(int argc, char *argv[])
{
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    slc_ctx_t  *ctx;
    slc_conn_t *conn;
    slc_cfg_t cfg;
    const char *msg = "Hello SLC!";
    char buf[BUF_SZ];
    int n;

    if (argc > 1)
        host = argv[1];
    if (argc > 2)
        port = atoi(argv[2]);

    /* Configure client context */
    memset(&cfg, 0, sizeof(cfg));
    cfg.role      = SLC_CLIENT;
    cfg.cert_file = DEFAULT_CERT;
    cfg.key_file  = DEFAULT_KEY;
    cfg.ca_file   = DEFAULT_CA;

    ctx = slc_ctx_new(&cfg);
    if (ctx == NULL) {
        fprintf(stderr, "slc_ctx_new failed\n");
        return 1;
    }

    /* Connect to server */
    printf("Connecting to %s:%d...\n", host, port);
    conn = slc_connect(ctx, host, port);
    if (conn == NULL) {
        fprintf(stderr, "slc_connect failed\n");
        slc_ctx_free(ctx);
        return 1;
    }

    printf("Connected (fd %d)\n", slc_get_fd(conn));

    /* Send message */
    printf("Sending: %s\n", msg);
    if (slc_write(conn, msg, (int)strlen(msg)) < 0) {
        fprintf(stderr, "slc_write failed\n");
        slc_close(conn);
        slc_ctx_free(ctx);
        return 1;
    }

    /* Read echo response */
    n = slc_read(conn, buf, BUF_SZ - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Received: %s\n", buf);
    } else {
        fprintf(stderr, "slc_read failed\n");
    }

    /* Cleanup */
    slc_close(conn);
    slc_ctx_free(ctx);

    return 0;
}
