/* echo_client.c — MQC echo client
 *
 * Usage: ./echo_client <tpm_path> <host> [port]
 *
 * Example:
 *   ./echo_client ~/.TPM/factsorlie.com localhost 4433
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
    (void)mtc_server;
    memset(ca_pubkey, 0, sizeof(ca_pubkey));
    ca_pubkey_sz = 32;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *tpm_path;
    const char *host;
    int port = DEFAULT_PORT;
    int encrypted = 0;
    mqc_ctx_t *ctx;
    mqc_conn_t *conn;
    mqc_cfg_t cfg;
    const char *msg = "Hello MQC!";
    char buf[BUF_SZ];
    int n, i, pos;

    /* Parse args */
    pos = 0;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--encrypted") == 0)
            encrypted = 1;
        else if (pos == 0) { tpm_path = argv[i]; pos++; }
        else if (pos == 1) { host = argv[i]; pos++; }
        else if (pos == 2) { port = atoi(argv[i]); pos++; }
    }
    if (pos < 2) {
        fprintf(stderr, "Usage: %s [--encrypted] <tpm_path> <host> [port]\n", argv[0]);
        return 1;
    }

    load_ca_pubkey(DEFAULT_SERVER);

    memset(&cfg, 0, sizeof(cfg));
    cfg.role       = MQC_CLIENT;
    cfg.tpm_path   = tpm_path;
    cfg.mtc_server = DEFAULT_SERVER;
    cfg.ca_pubkey  = ca_pubkey;
    cfg.ca_pubkey_sz = ca_pubkey_sz;

    ctx = mqc_ctx_new(&cfg);
    if (!ctx) {
        fprintf(stderr, "mqc_ctx_new failed\n");
        return 1;
    }

    printf("Connecting to %s:%d%s...\n", host, port,
           encrypted ? " (encrypted identity)" : "");
    conn = encrypted ? mqc_connect_encrypted(ctx, host, port)
                     : mqc_connect(ctx, host, port);
    if (!conn) {
        fprintf(stderr, "mqc_connect failed\n");
        mqc_ctx_free(ctx);
        return 1;
    }

    printf("Connected (peer_index=%d)\n", mqc_get_peer_index(conn));

    printf("Sending: %s\n", msg);
    if (mqc_write(conn, msg, (int)strlen(msg)) < 0) {
        fprintf(stderr, "mqc_write failed\n");
        mqc_close(conn);
        mqc_ctx_free(ctx);
        return 1;
    }

    n = mqc_read(conn, buf, BUF_SZ - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Received: %s\n", buf);
    } else {
        fprintf(stderr, "mqc_read failed\n");
    }

    mqc_close(conn);
    mqc_ctx_free(ctx);
    return 0;
}
