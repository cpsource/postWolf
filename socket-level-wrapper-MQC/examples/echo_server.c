/* echo_server.c — MQC echo server
 *
 * Usage: ./echo_server <tpm_path> [port]
 *
 * Example:
 *   ./echo_server ~/.TPM/factsorlie.com-ca 4433
 */

#include "mqc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT    4433
#define DEFAULT_SERVER  "localhost:8444"
#define BUF_SZ          4096

/* TODO: load CA pubkey from file or server */
static unsigned char ca_pubkey[32];
static int ca_pubkey_sz = 0;

static int load_ca_pubkey(const char *mtc_server)
{
    /* For now, zero-fill — full Merkle verification is TODO.
     * In production, fetch from GET /ca/public-key */
    (void)mtc_server;
    memset(ca_pubkey, 0, sizeof(ca_pubkey));
    ca_pubkey_sz = 32;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *tpm_path;
    int port = DEFAULT_PORT;
    int listen_fd;
    mqc_ctx_t *ctx;
    mqc_conn_t *conn;
    mqc_cfg_t cfg;
    char buf[BUF_SZ];
    int n;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <tpm_path> [port]\n", argv[0]);
        fprintf(stderr, "  tpm_path: ~/.TPM/<domain> directory\n");
        return 1;
    }

    tpm_path = argv[1];
    if (argc > 2)
        port = atoi(argv[2]);

    load_ca_pubkey(DEFAULT_SERVER);

    memset(&cfg, 0, sizeof(cfg));
    cfg.role       = MQC_SERVER;
    cfg.tpm_path   = tpm_path;
    cfg.mtc_server = DEFAULT_SERVER;
    cfg.ca_pubkey  = ca_pubkey;
    cfg.ca_pubkey_sz = ca_pubkey_sz;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "mqc_ctx_new failed\n");
        return 1;
    }

    listen_fd = mqc_listen(NULL, port);
    if (listen_fd < 0) {
        fprintf(stderr, "mqc_listen failed on port %d\n", port);
        mqc_ctx_free(ctx);
        return 1;
    }

    printf("MQC echo server listening on port %d\n", port);

    for (;;) {
        printf("Waiting for connection...\n");

        conn = mqc_accept(ctx, listen_fd);
        if (!conn) {
            fprintf(stderr, "mqc_accept failed\n");
            continue;
        }

        printf("Client connected (peer_index=%d)\n", mqc_get_peer_index(conn));

        while ((n = mqc_read(conn, buf, BUF_SZ)) > 0) {
            printf("Received %d bytes: %.*s\n", n, n, buf);
            if (mqc_write(conn, buf, n) < 0) {
                fprintf(stderr, "mqc_write failed\n");
                break;
            }
        }

        printf("Client disconnected\n");
        mqc_close(conn);
    }

    mqc_ctx_free(ctx);
    return 0;
}
