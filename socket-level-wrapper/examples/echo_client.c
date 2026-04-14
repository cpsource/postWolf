/* echo_client.c — Simple echo client using the SLC API
 *
 * Usage:
 *   ./echo_client [host] [port]                              — traditional X.509
 *   ./echo_client --mtc ~/.TPM/factsorlie.com [host] [port]  — MTC certificate
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
    const char *mtc_store = NULL;
    slc_ctx_t  *ctx;
    slc_conn_t *conn;
    slc_cfg_t cfg;
    const char *msg = "Hello SLC!";
    char buf[BUF_SZ];
    int n, i, pos;

    /* Parse arguments */
    pos = 0;  /* positional argument counter */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mtc") == 0 && i + 1 < argc)
            mtc_store = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--mtc TPM_PATH] [host] [port]\n", argv[0]);
            printf("  --mtc PATH   Use MTC certificate from ~/.TPM/<domain>\n");
            printf("  host         Server hostname (default: %s)\n", DEFAULT_HOST);
            printf("  port         Server port (default: %d)\n", DEFAULT_PORT);
            return 0;
        }
        else {
            if (pos == 0) host = argv[i];
            else if (pos == 1) port = atoi(argv[i]);
            pos++;
        }
    }

    /* Configure client context */
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SLC_CLIENT;

    if (mtc_store) {
        cfg.mtc_store = mtc_store;
        printf("MTC mode: %s\n", mtc_store);
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

    /* Connect to server */
    printf("Connecting to %s:%d%s...\n", host, port,
           mtc_store ? " (MTC)" : " (X.509)");
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
